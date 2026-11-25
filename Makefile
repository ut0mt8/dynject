PREFIX        = /opt/dynject
BUILD_DIR     = build
LAUNCH_DAEMONS = /Library/LaunchDaemons

BINARY_DAEMON = $(BUILD_DIR)/dynjectd
BINARY_LOADER = $(BUILD_DIR)/dynject_loader
SOURCE_DAEMON = dynjectd.c
SOURCE_LOADER = dynject_loader.c amfid_stub.s
ENTITLEMENTS  = dynjectd.entitlements
PLIST         = com.dynject.dynjectd.plist

CC     = clang
SDK    = $(shell xcrun --sdk macosx --show-sdk-path)

CFLAGS = \
	-Wall \
	-Wextra \
	-arch arm64e \
	-fblocks \
	-isysroot "$(SDK)"

CFLAGS_DAEMON = $(CFLAGS) -lEndpointSecurity -lbsm -framework CoreFoundation
CFLAGS_LOADER = $(CFLAGS) -lobjc

.PHONY: all clean install uninstall load unload test

all: $(BINARY_DAEMON) $(BINARY_LOADER)

test: | $(BUILD_DIR)
	$(CC) $(CFLAGS_DAEMON) -o $(BUILD_DIR)/test_daemon_policy tests/test_daemon_policy.c log.c
	$(BUILD_DIR)/test_daemon_policy
	$(CC) $(CFLAGS_LOADER) -o $(BUILD_DIR)/test_amfid_stub tests/test_amfid_stub.c amfid_stub.s log.c
	$(BUILD_DIR)/test_amfid_stub
	$(CC) $(CFLAGS_LOADER) -o $(BUILD_DIR)/test_loader_stop tests/test_loader_stop.c amfid_stub.s log.c
	$(BUILD_DIR)/test_loader_stop

$(BUILD_DIR):
	@mkdir -p $@

$(BINARY_DAEMON): $(SOURCE_DAEMON) log.c log.h $(ENTITLEMENTS) | $(BUILD_DIR)
	@echo "[compile] $(SOURCE_DAEMON)"
	$(CC) $(CFLAGS_DAEMON) -o $@ $(SOURCE_DAEMON) log.c
	codesign -f -s - --entitlements $(ENTITLEMENTS) $@
	@echo "[+] $(BINARY_DAEMON)"

$(BINARY_LOADER): $(SOURCE_LOADER) log.c log.h | $(BUILD_DIR)
	@echo "[compile] $(SOURCE_LOADER)"
	$(CC) $(CFLAGS_LOADER) -o $@ $(SOURCE_LOADER) log.c
	codesign -f -s - $@
	@echo "[+] $(BINARY_LOADER)"

install: all
	@echo "[install] creating $(PREFIX)/{bin,etc,lib/tweaks,log}"
	install -d $(PREFIX)/bin
	install -d $(PREFIX)/etc
	install -d $(PREFIX)/lib/tweaks
	install -d $(PREFIX)/log

	install -m 755 $(BINARY_DAEMON) $(PREFIX)/bin/dynjectd
	codesign -f -s - --entitlements $(ENTITLEMENTS) $(PREFIX)/bin/dynjectd

	install -m 755 $(BINARY_LOADER) $(PREFIX)/bin/dynject_loader
	codesign -f -s - $(PREFIX)/bin/dynject_loader

	[ -f $(PREFIX)/etc/dynjectd.conf ] || \
	    install -m 644 dynjectd.conf.example $(PREFIX)/etc/dynjectd.conf

	install -m 644 $(PLIST) $(LAUNCH_DAEMONS)/$(PLIST)

load:
	launchctl load $(LAUNCH_DAEMONS)/$(PLIST)
	@echo "[+] dynjectd loaded (starts at boot)"

unload:
	-launchctl unload $(LAUNCH_DAEMONS)/$(PLIST) 2>/dev/null
	-pkill -x dynjectd 2>/dev/null
	@echo "[-] dynjectd unloaded"

uninstall: unload
	rm -f $(PREFIX)/bin/dynjectd
	rm -f $(PREFIX)/bin/dynject_loader
	rm -f $(LAUNCH_DAEMONS)/$(PLIST)
	@echo "Uninstalled. Logs remain at $(PREFIX)/log/"

clean:
	rm -rf $(BUILD_DIR)
