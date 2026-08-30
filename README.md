# dynject

Dylib injection daemon for macOS arm64e. Loads tweak dylibs into applications
at launch, before any app code runs.

---

## How it works

Every macOS app passes through `xpcproxy`, which calls `posix_spawn` to create
the final process. dynjectd intercepts this by subscribing to EndpointSecurity `AUTH_EXEC`
events for xpcproxy creation and installing a hardware breakpoint at `posix_spawn`.
When the breakpoint fires, it adds `DYLD_INSERT_LIBRARIES` to the envp argument.

`dynject_loader` hooks amfid temporarily at boot to approve dynjectd's
entitlements (`com.apple.developer.endpoint-security.client`,
`task_for_pid-allow`), then restores amfid and exits.

---

## Install

```bash
make
sudo make install
sudo make load
```

---

## Directory layout

```
/opt/dynject/
├── bin/
│   ├── dynjectd           — injection daemon (runs continuously)
│   └── dynject_loader     — amfid patcher (runs once at boot, then exits)
├── etc/
│   └── dynjectd.conf      — configuration
├── lib/
│   └── tweaks/            — drop .dylib tweak files here
└── var/
    └── log/               — logs
```

---

## Configuration

`/opt/dynject/etc/dynjectd.conf`:

```ini
# dynjectd.conf — dylib injection configuration
#
# Location: /opt/dynject/etc/dynjectd.conf
# Reload:   sudo launchctl kickstart -k system/com.dynject.dynjectd
#
# dylib:path:allow          inject into all matched processes (default)
# dylib:path:deny           inject into no processes unless overridden
# dylib:path                shorthand for dylib:path:allow
#
# dylib-override:path:allow:bundle_pattern   inject for matching bundle IDs
# dylib-override:path:deny:bundle_pattern    skip for matching bundle IDs
#
# bundle_pattern is matched as a substring against the XPC service bundle ID.
# First matching override wins; falls back to the dylib's default policy.
#
# Examples:
#
#   Inject everywhere:
#     dylib:/opt/dynject/lib/tweaks/libBrutalium.dylib:allow
#
#   Inject everywhere except Finder and Dock:
#     dylib:/opt/dynject/lib/tweaks/libUITweak.dylib:allow
#     dylib-override:/opt/dynject/lib/tweaks/libUITweak.dylib:deny:com.apple.Finder
#     dylib-override:/opt/dynject/lib/tweaks/libUITweak.dylib:deny:com.apple.Dock
#
#   Debug tool injected only into one app:
#     dylib:/opt/dynject/lib/tweaks/libDebugHook.dylib:deny
#     dylib-override:/opt/dynject/lib/tweaks/libDebugHook.dylib:allow:application.com.myapp

# dylib:/opt/dynject/lib/tweaks/libMyTweak.dylib:allow

# ── Process allow/deny rules ─────────────────────────────────────────
# These filter by PROCESS NAME (resolved at posix_spawn time).
# Evaluated after dylib policy, before injection.
#
# allow:Terminal
# allow:Safari
# deny:Finder

# ── Default UI app rule ───────────────────────────────────────────────
# Inject into processes inside standard .app bundles.
ui_apps:yes

# ── Helper filtering ──────────────────────────────────────────────────
# Skip GPU/Renderer/Plugin sub-processes.
skip_helpers:yes

```

---

## Boot sequence

The LaunchDaemon (`/Library/LaunchDaemons/com.dynject.dynjectd.plist`) runs
`dynject_loader` which:
1. Hooks amfid's validation method with a trampoline (real validation runs,
   return value is forced to YES)
2. Launches dynjectd (whose entitlements are approved by the hook)
3. Waits for the kernel/amfid round-trip to complete
4. Restores amfid to its original state
5. Exits

dynjectd then runs continuously, intercepting app launches.

---

## Logs

```bash
tail /opt/dynject/log/dynjectd.log

# verbose:
sudo /opt/dynject/bin/dynjectd -v
sudo /opt/dynject/bin/dynject_loader -v

```

---

## Requirements

- macOS Tahoe+ arm64e
- SIP relaxed

---

## Thanks

- [CoreBedtime](https://github.com/CoreBedtime) main inspiration from ammonia/playground
- [Zeyad Azima](https://zeyadazima.com/notes/osmrnotes/) great ressources
- and many others...

