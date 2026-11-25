#define main dynjectd_main
#include "../dynjectd.c"
#undef main

#include <assert.h>
#include <sys/mman.h>

typedef struct {
  const char* service;
  const char* expected;
} Worker;

static void* run_policy(void* context) {
  Worker* worker = (Worker*)context;
  for (int i = 0; i < 10000; i++) {
    char value[4096];
    assert(build_dyld_for_bundle(worker->service, NULL, value, sizeof(value)));
    assert(strcmp(value, worker->expected) == 0);
  }
  return NULL;
}

/* Runs the real envp rewrite against this process's own memory. */
static char g_strings[600][32];
static mach_vm_address_t g_envp[600];

static mach_vm_address_t rewrite_envp(int count, int dyld_at, const char* value) {
  for (int i = 0; i < count; i++) {
    if (i == dyld_at)
      snprintf(g_strings[i], sizeof(g_strings[i]), "DYLD_INSERT_LIBRARIES=old");
    else
      snprintf(g_strings[i], sizeof(g_strings[i]), "VAR%d=x", i);
    g_envp[i] = (mach_vm_address_t)g_strings[i];
  }
  g_envp[count] = 0;
  return make_envp_with_dyld(mach_task_self(), (mach_vm_address_t)g_envp, value);
}

static void check_envp(int count, int dyld_at, int expected_count) {
  const char* value = "DYLD_INSERT_LIBRARIES=/a.dylib";
  mach_vm_address_t result = rewrite_envp(count, dyld_at, value);
  if (expected_count == 0) {
    assert(result == 0);
    return;
  }
  assert(result != 0);
  char** envp = (char**)result;
  int n = 0, dyld_seen = 0;
  while (envp[n] != NULL) {
    if (strncmp(envp[n], "DYLD_INSERT_LIBRARIES=", 22) == 0) {
      assert(strcmp(envp[n], value) == 0);
      dyld_seen++;
    }
    n++;
  }
  assert(n == expected_count);
  assert(dyld_seen == 1);
  if (dyld_at < 0) assert(strcmp(envp[n - 1], value) == 0);
  else assert(strcmp(envp[dyld_at], value) == 0);
}

static mach_msg_type_number_t port_name_count(void) {
  mach_port_name_array_t names;
  mach_port_type_array_t types;
  mach_msg_type_number_t name_count, type_count;
  assert(mach_port_names(mach_task_self(), &names, &name_count, &types,
                         &type_count) == KERN_SUCCESS);
  vm_deallocate(mach_task_self(), (vm_address_t)names,
                name_count * sizeof(*names));
  vm_deallocate(mach_task_self(), (vm_address_t)types,
                type_count * sizeof(*types));
  return name_count;
}

/* Every intercepted launch makes and releases one exception port. */
static void check_exception_port_release(void) {
  mach_msg_type_number_t before = port_name_count();
  for (int i = 0; i < 1000; i++) {
    mach_port_t port;
    assert(make_exception_port(&port) == KERN_SUCCESS);
    release_exception_port(port);
  }
  assert(port_name_count() == before);
}

/* Two pages, the second unreadable: things placed at the end of the first. */
static char* g_pages;
static size_t g_page;

static char* at_page_end(size_t size) {
  return g_pages + g_page - size;
}

static void check_remote_reads(void) {
  g_page = (size_t)getpagesize();
  g_pages = mmap(NULL, g_page * 2, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(g_pages != MAP_FAILED);
  assert(mprotect(g_pages + g_page, g_page, PROT_NONE) == 0);

  char buffer[64];
  /* A short string right before the unreadable page reads in full. */
  strcpy(at_page_end(6), "VAR=x");
  assert(read_remote_string(mach_task_self(), (mach_vm_address_t)at_page_end(6),
                            buffer, sizeof(buffer)) == 5);
  assert(strcmp(buffer, "VAR=x") == 0);
  /* A string that runs into it doesn't. */
  memcpy(at_page_end(3), "abc", 3);
  assert(read_remote_string(mach_task_self(), (mach_vm_address_t)at_page_end(3),
                            buffer, sizeof(buffer)) == -1);
  assert(read_remote_string(mach_task_self(),
                            (mach_vm_address_t)(g_pages + g_page), buffer,
                            sizeof(buffer)) == -1);
  /* Longer than the buffer: cut, still terminated. */
  memset(g_pages, 'a', 200);
  g_pages[200] = '\0';
  assert(read_remote_string(mach_task_self(), (mach_vm_address_t)g_pages,
                            buffer, sizeof(buffer)) == 63);
  assert(strlen(buffer) == 63);

  uint64_t value = 1;
  assert(read_remote_u64(mach_task_self(),
                         (mach_vm_address_t)(g_pages + g_page), &value) == -1);
  assert(value == 0);
}

/* An existing DYLD entry at a page's end is found and replaced, not missed and
 * duplicated (the old fixed-size read failed there). */
static void check_envp_dyld_at_page_end(void) {
  const char* old = "DYLD_INSERT_LIBRARIES=old";
  const char* value = "DYLD_INSERT_LIBRARIES=/a.dylib";
  char* old_copy = at_page_end(strlen(old) + 1);
  strcpy(old_copy, old);
  static char other[] = "HOME=/x";
  mach_vm_address_t envp[] = {(mach_vm_address_t)other,
                              (mach_vm_address_t)old_copy, 0};
  char** result = (char**)make_envp_with_dyld(
      mach_task_self(), (mach_vm_address_t)envp, value);
  assert(result != NULL);
  assert(strcmp(result[0], "HOME=/x") == 0);
  assert(strcmp(result[1], value) == 0);
  assert(result[2] == NULL);
}

/* An envp array that runs into unreadable memory (no NULL we can see) is not
 * taken as ending there: injection is skipped. */
static void check_envp_unreadable(void) {
  static char a[] = "A=1";
  mach_vm_address_t* tail = (mach_vm_address_t*)(void*)at_page_end(16);
  tail[0] = (mach_vm_address_t)a;
  tail[1] = (mach_vm_address_t)a;
  assert(make_envp_with_dyld(mach_task_self(), (mach_vm_address_t)tail,
                             "DYLD_INSERT_LIBRARIES=/a.dylib") == 0);
  /* An entry pointing at unreadable memory: skipped too. */
  mach_vm_address_t bad[] = {(mach_vm_address_t)a,
                             (mach_vm_address_t)(g_pages + g_page), 0};
  assert(make_envp_with_dyld(mach_task_self(), (mach_vm_address_t)bad,
                             "DYLD_INSERT_LIBRARIES=/a.dylib") == 0);
}

static mach_port_urefs_t send_refs(mach_port_t name) {
  mach_port_urefs_t refs = 0;
  mach_port_get_refs(mach_task_self(), name, MACH_PORT_RIGHT_SEND, &refs);
  return refs;
}

static mach_port_t port_with_send(void) {
  mach_port_t port;
  assert(make_exception_port(&port) == KERN_SUCCESS);
  return port;
}

static void send_to(mach_port_t port, ExceptionRequest* message, mach_msg_size_t size) {
  message->header.msgh_remote_port = port;
  message->header.msgh_size = size;
  assert(mach_msg(&message->header, MACH_SEND_MSG, size, 0, MACH_PORT_NULL, 0,
                  MACH_PORT_NULL) == KERN_SUCCESS);
}

/* Only /usr/libexec/xpcproxy as a platform binary is intercepted. */
static void check_exec_identity(void) {
  const char* real = "/usr/libexec/xpcproxy";
  const char* fake = "/tmp/xpcproxy";
  const char* longer = "/usr/libexec/xpcproxy2";
  assert(exec_target_is_xpcproxy(real, strlen(real), 1));
  assert(!exec_target_is_xpcproxy(real, strlen(real), 0));
  assert(!exec_target_is_xpcproxy(fake, strlen(fake), 1));
  assert(!exec_target_is_xpcproxy(longer, strlen(longer), 1));
  assert(!exec_target_is_xpcproxy(real, strlen(real) - 1, 1));
  assert(!exec_target_is_xpcproxy(NULL, 0, 1));
}

static void check_copy_printable(void) {
  char out[16];
  const char* label = "a\nb\rc\x1b\x7f" "d\xc3\xa9";
  copy_printable(out, sizeof(out), label, strlen(label), 1);
  assert(strcmp(out, "a?b?c??d??") == 0);
  copy_printable(out, sizeof(out), label, strlen(label), 0);
  assert(strcmp(out, "a?b?c??d\xc3\xa9") == 0);
  copy_printable(out, 4, "abcdef", 6, 1); /* cut to fit, terminated */
  assert(strcmp(out, "abc") == 0);
  copy_printable(out, sizeof(out), "abcdef", 2, 1); /* a token has a length, no NUL */
  assert(strcmp(out, "ab") == 0);
  copy_printable(out, sizeof(out), NULL, 5, 1);
  assert(out[0] == '\0');
}

/* A process can send to its own exception port. Messages that aren't the
 * kernel's are rejected, whatever their shape, and the names in them are
 * never released. */
static void check_forged_exception(void) {
  mach_port_t victim_a = port_with_send(), victim_b = port_with_send();
  ExceptionRequest forged, received;

  /* 1. plain data: the "port names" are just integers the sender chose */
  mach_port_t port = port_with_send();
  memset(&forged, 0, sizeof(forged));
  forged.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
  forged.header.msgh_id = MACH_EXCEPTION_RAISE_ID;
  forged.thread_port.name = victim_a;
  forged.task_port.name = victim_b;
  forged.exception_type = EXC_BREAKPOINT;
  forged.code_count = 2;
  send_to(port, &forged, (mach_msg_size_t)offsetof(ExceptionRequest, padding));
  assert(receive_exception(port, 1000, &received) == KERN_SUCCESS);
  assert(received.thread_port.name == victim_a);
  assert(!exception_request_valid(&received));
  mach_msg_destroy(&received.header);
  release_exception_port(port);

  /* 2. the same shape as the kernel's message, with real rights, sent by us */
  port = port_with_send();
  memset(&forged, 0, sizeof(forged));
  forged.header.msgh_bits =
      MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
  forged.header.msgh_id = MACH_EXCEPTION_RAISE_ID;
  forged.body.msgh_descriptor_count = 2;
  forged.thread_port.name = victim_a;
  forged.thread_port.disposition = MACH_MSG_TYPE_COPY_SEND;
  forged.thread_port.type = MACH_MSG_PORT_DESCRIPTOR;
  forged.task_port = forged.thread_port;
  forged.task_port.name = victim_b;
  forged.ndr = NDR_record;
  forged.exception_type = EXC_BREAKPOINT;
  forged.code_count = 2;
  send_to(port, &forged, (mach_msg_size_t)offsetof(ExceptionRequest, padding));
  assert(receive_exception(port, 1000, &received) == KERN_SUCCESS);
  assert(received.header.msgh_bits & MACH_MSGH_BITS_COMPLEX);
  assert(received.thread_port.disposition == MACH_MSG_TYPE_PORT_SEND);
  assert(!exception_request_valid(&received)); /* only the sender is wrong */
  assert(send_refs(victim_a) == 2);
  mach_msg_destroy(&received.header); /* gives back the rights it carried */
  assert(send_refs(victim_a) == 1 && send_refs(victim_b) == 1);
  release_exception_port(port);

  /* 3. through the real handler */
  port = port_with_send();
  memset(&forged, 0, sizeof(forged));
  forged.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
  forged.thread_port.name = victim_a;
  forged.task_port.name = victim_b;
  forged.exception_type = EXC_BAD_ACCESS;
  send_to(port, &forged, 76);
  XpcHandlerArgs* args = calloc(1, sizeof(*args));
  assert(args != NULL);
  assert(mach_port_mod_refs(mach_task_self(), mach_task_self(), MACH_PORT_RIGHT_SEND, 1) == KERN_SUCCESS);
  args->pid = getpid();
  args->task = mach_task_self(); /* the handler releases one reference */
  args->exception_port = port;
  strlcpy(args->service_name, "application.test", sizeof(args->service_name));
  xpc_handler_thread(args);
  assert(send_refs(victim_a) == 1 && send_refs(victim_b) == 1);

  release_exception_port(victim_a);
  release_exception_port(victim_b);
}

/* The kernel's own breakpoint message is accepted. */
static mach_port_t g_trap_port;

static void* trap_thread(void* context) {
  (void)context;
  assert(thread_set_exception_ports(mach_thread_self(), EXC_MASK_BREAKPOINT, g_trap_port,
                                    EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
                                    ARM_THREAD_STATE64) == KERN_SUCCESS);
  __builtin_debugtrap();
  return NULL;
}

static void check_kernel_exception(void) {
  pthread_t thread;
  pthread_attr_t attr;
  ExceptionRequest received;

  g_trap_port = port_with_send();
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  assert(pthread_create(&thread, &attr, trap_thread, NULL) == 0);
  pthread_attr_destroy(&attr);

  assert(receive_exception(g_trap_port, 5000, &received) == KERN_SUCCESS);
  assert(exception_request_valid(&received));
  assert(received.exception_type == EXC_BREAKPOINT);
  /* No reply: the thread can't continue past the trap, so it stays parked in
   * the kernel, with its message's rights held, until the test exits. */
}

static void write_file(const char* path, const char* text) {
  FILE* file = fopen(path, "w");
  assert(file != NULL);
  fputs(text, file);
  fclose(file);
}

static void write_info_plist(const char* path, const char* identifier) {
  char text[512];
  snprintf(text, sizeof(text),
           "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>"
           "<key>CFBundleIdentifier</key><string>%s</string></dict></plist>\n",
           identifier);
  write_file(path, text);
}

/* The identifier comes from the innermost app bundle around the executable. */
static void check_bundle_identifier(void) {
  char id[200];
  const char* root = "build/idtest";
  assert(system("rm -rf build/idtest && mkdir -p"
                " build/idtest/Outer.app/Contents/MacOS"
                " build/idtest/Outer.app/Contents/Helpers/Inner.app/Contents/MacOS"
                " build/idtest/Flat.app build/idtest/NoId.app/Contents/MacOS"
                " build/idtest/Linked.app/Contents/MacOS") == 0);
  (void)root;
  write_info_plist("build/idtest/Outer.app/Contents/Info.plist", "com.example.Outer");
  write_file("build/idtest/Outer.app/Contents/MacOS/Outer", "x");
  write_info_plist("build/idtest/Outer.app/Contents/Helpers/Inner.app/Contents/Info.plist",
                   "com.example.inner");
  write_file("build/idtest/Outer.app/Contents/Helpers/Inner.app/Contents/MacOS/Inner", "x");
  write_info_plist("build/idtest/Flat.app/Info.plist", "com.example.flat");
  write_file("build/idtest/Flat.app/Flat", "x");
  write_file("build/idtest/NoId.app/Contents/MacOS/NoId", "x");
  write_file("build/idtest/Linked.app/Contents/MacOS/Linked", "x");
  write_file("build/idtest/plain", "x");
  assert(symlink("Outer.app/Contents/MacOS/Outer", "build/idtest/Calculator") == 0);
  assert(symlink("../../Outer.app/Contents/Info.plist",
                 "build/idtest/Linked.app/Contents/Info.plist") == 0);

  assert(bundle_identifier_for_executable("build/idtest/Outer.app/Contents/MacOS/Outer", id, sizeof(id)) == 1);
  assert(strcmp(id, "com.example.Outer") == 0);
  assert(bundle_identifier_for_executable(
             "build/idtest/Outer.app/Contents/Helpers/Inner.app/Contents/MacOS/Inner", id, sizeof(id)) == 1);
  assert(strcmp(id, "com.example.inner") == 0);
  assert(bundle_identifier_for_executable("build/idtest/Flat.app/Flat", id, sizeof(id)) == 1);
  assert(strcmp(id, "com.example.flat") == 0);
  /* a symlink elsewhere to an app's executable is still that app */
  assert(bundle_identifier_for_executable("build/idtest/Calculator", id, sizeof(id)) == 1);
  assert(strcmp(id, "com.example.Outer") == 0);
  /* in a bundle, no identifier to read: -1, never another bundle's */
  assert(bundle_identifier_for_executable("build/idtest/NoId.app/Contents/MacOS/NoId", id, sizeof(id)) == -1);
  assert(id[0] == '\0');
  assert(bundle_identifier_for_executable("build/idtest/Linked.app/Contents/MacOS/Linked", id, sizeof(id)) == -1);
  assert(bundle_identifier_for_executable("build/idtest/plain", id, sizeof(id)) == 0);
  assert(bundle_identifier_for_executable("build/idtest/missing", id, sizeof(id)) == 0);
  assert(system("rm -rf build/idtest") == 0);
}

/* dylib 0 is allowed by default; dylib 1 only where "second" matches. A label
 * alone doesn't decide: the app's own identifier has to agree. */
static void check_verified_policy(void) {
  char value[4096];
  const char* only_first = "DYLD_INSERT_LIBRARIES=dynjectd.c";
  const char* both = "DYLD_INSERT_LIBRARIES=dynjectd.c:dynject_loader.c";

  /* a label made up to contain the pattern, around another app */
  assert(build_dyld_for_bundle("x.second.com.victim.app", "application.com.victim.app.", value, sizeof(value)));
  assert(strcmp(value, only_first) == 0);
  /* label and identifier agree; the identifier's case doesn't matter */
  assert(build_dyld_for_bundle("application.second.1.2", "application.SECOND.", value, sizeof(value)));
  assert(strcmp(value, both) == 0);
  /* not in a bundle: the label decides, as before */
  assert(build_dyld_for_bundle("homebrew.second", NULL, value, sizeof(value)));
  assert(strcmp(value, both) == 0);
  /* in a bundle with no identifier: defaults only */
  assert(build_dyld_for_bundle("application.second.1.2", "application..", value, sizeof(value)));
  assert(strcmp(value, only_first) == 0);

  /* a deny can't be dodged by leaving its pattern out of the label */
  strlcpy(g_config.dylibs[0].overrides[0].pattern, "com.victim", 256);
  g_config.dylibs[0].overrides[0].allow = 0;
  g_config.dylibs[0].override_count = 1;
  assert(build_dyld_for_bundle("anything", "application.com.victim.app.", value, sizeof(value)) == NULL);
  assert(build_dyld_for_bundle("application.com.victim.app.1.2", "application.com.victim.app.", value, sizeof(value)) == NULL);
  assert(build_dyld_for_bundle("application.other.1.2", "application.other.", value, sizeof(value)));
  assert(strcmp(value, only_first) == 0);
  g_config.dylibs[0].override_count = 0;
}

static int is_daemon(const char* label) {
  return service_name_is_system_daemon(label, strlen(label));
}

/* Names on the daemon list count as whole words of a label. */
static void check_daemon_names(void) {
  assert(is_daemon("com.apple.bird"));
  assert(is_daemon("bird"));
  assert(is_daemon("com.apple.logd_helper"));
  assert(is_daemon("com.apple.trustdFileHelper"));
  assert(is_daemon("com.apple.security.cloudkeychainproxy3"));
  assert(is_daemon("com.apple.mdworker.shared.01000000-0500-0000-0000-000000000000"));
  assert(is_daemon("com.apple.AddressBook.abd"));
  assert(is_daemon("com.apple.symptomsd-diag"));
  assert(is_daemon("com.apple.WebKit.WebContent.6F0C0A7E"));
  assert(!is_daemon("application.org.mozilla.thunderbird.123.456"));
  assert(!is_daemon("application.com.example.blogdesk.1.2"));
  assert(!is_daemon("application.com.example.birdfeed.1.2"));
  assert(!is_daemon("application.com.apple.Safari.1.2"));
  assert(!is_daemon("bir"));
}

static void load_config(const char* text) {
  write_file("build/test.conf", text);
  config_set_defaults();
  config_load("build/test.conf");
}

static int warned(const char* text) {
  for (int i = 0; i < g_config_warning_count && i < MAX_CONFIG_WARNINGS; i++) {
    if (strstr(g_config_warnings[i], text) != NULL) return 1;
  }
  return 0;
}

static void check_config(void) {
  static Config saved;
  saved = g_config; /* the other checks use the config main() set up */

  /* yes/no: the usual words, any case; anything else keeps the value and says so */
  load_config("ui_apps:false\nskip_helpers:OFF\ndylib:/x.dylib\n");
  assert(g_config.inject_ui_apps == 0 && g_config.skip_helpers == 0);
  assert(g_config_warning_count == 0);
  load_config("ui_apps:no\nui_apps:True\nskip_helpers:0\nskip_helpers:on\n");
  assert(g_config.inject_ui_apps == 1 && g_config.skip_helpers == 1);
  load_config("ui_apps:no\nui_apps:nope\nskip_helpers:maybe\n");
  assert(g_config.inject_ui_apps == 0 && g_config.skip_helpers == 1);
  assert(g_config_warning_count == 2 && warned("line 2: ui_apps:nope") && warned("skip_helpers:maybe"));

  /* an override counts wherever it stands; file order decides between overrides */
  load_config("dylib-override:/x.dylib:deny:com.apple.Finder\n"
              "dylib:/x.dylib:allow\n"
              "dylib-override:/x.dylib:allow:com.apple\n");
  assert(g_config.dylib_count == 1 && g_config.dylibs[0].override_count == 2);
  assert(strcmp(g_config.dylibs[0].overrides[0].pattern, "com.apple.Finder") == 0);
  assert(g_config.dylibs[0].overrides[0].allow == 0);
  assert(g_config.dylibs[0].overrides[1].allow == 1);
  assert(g_config_warning_count == 0);

  /* an override that names no dylib is reported, not dropped in silence */
  load_config("dylib:/x.dylib:allow\ndylib-override:/y.dylib:deny:com.apple.Finder\n");
  assert(g_config.dylibs[0].override_count == 0);
  assert(g_config_warning_count == 1 && warned("line 2: dylib-override for /y.dylib"));

  /* so is everything past a limit */
  {
    static char text[MAX_DYLIBS * 24 + (MAX_OVERRIDES + 2) * 40 + 64];
    char* at = text;
    for (int i = 0; i < MAX_DYLIBS + 1; i++) at += sprintf(at, "dylib:/d%d.dylib\n", i);
    for (int i = 0; i < MAX_OVERRIDES + 1; i++) at += sprintf(at, "dylib-override:/d0.dylib:deny:p%d\n", i);
    load_config(text);
    assert(g_config.dylib_count == MAX_DYLIBS);
    assert(g_config.dylibs[0].override_count == MAX_OVERRIDES);
    assert(g_config_warning_count == 2 && warned("dylib lines") && warned("overrides for /d0.dylib"));
  }
  unlink("build/test.conf");
  g_config = saved;
  g_config_warning_count = 0;
}

static void* send_later(void* context) {
  ExceptionRequest message;
  usleep(450 * 1000); /* later than the old 300 ms limit */
  memset(&message, 0, sizeof(message));
  message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
  send_to(*(mach_port_t*)context, &message, 76);
  return NULL;
}

static double seconds_since(const struct timespec* start) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (double)(now.tv_sec - start->tv_sec) + (double)(now.tv_nsec - start->tv_nsec) / 1e9;
}

/* The wait lasts as long as the launch may need, but not past the task's end. */
static void check_wait(void) {
  ExceptionRequest received;
  struct timespec start;
  pthread_t thread;
  int gone = -1;
  mach_port_t port = port_with_send();

  clock_gettime(CLOCK_MONOTONIC, &start);
  assert(pthread_create(&thread, NULL, send_later, &port) == 0);
  assert(wait_for_exception(port, mach_task_self(), 5000, &received, &gone) == KERN_SUCCESS);
  assert(gone == 0 && seconds_since(&start) > 0.4 && seconds_since(&start) < 2.0);
  mach_msg_destroy(&received.header);
  pthread_join(thread, NULL);

  /* nothing arrives: the whole time, and the task is still there */
  clock_gettime(CLOCK_MONOTONIC, &start);
  assert(wait_for_exception(port, mach_task_self(), 600, &received, &gone) == MACH_RCV_TIMED_OUT);
  assert(gone == 0 && seconds_since(&start) > 0.55 && seconds_since(&start) < 1.5);

  /* a task that has ended (its port is a dead name): one slice, not five seconds */
  mach_port_t ended = port_with_send();
  assert(mach_port_mod_refs(mach_task_self(), ended, MACH_PORT_RIGHT_RECEIVE, -1) == KERN_SUCCESS);
  assert(task_is_gone(ended) && !task_is_gone(mach_task_self()));
  clock_gettime(CLOCK_MONOTONIC, &start);
  assert(wait_for_exception(port, ended, 5000, &received, &gone) == MACH_RCV_TIMED_OUT);
  assert(gone == 1 && seconds_since(&start) < 1.0);
  mach_port_deallocate(mach_task_self(), ended);
  release_exception_port(port);
}

/* A path that doesn't fit is left out whole, never cut. */
static void check_value_capacity(void) {
  char small[sizeof("DYLD_INSERT_LIBRARIES=dynjectd.c") + 5];
  assert(build_dyld_for_bundle("second", NULL, small, sizeof(small)));
  assert(strcmp(small, "DYLD_INSERT_LIBRARIES=dynjectd.c") == 0);
}

int main(void) {
  log_init("test_daemon_policy", "/dev/null", 0);
  config_set_defaults();
  g_config.dylib_count = 2;
  strlcpy(g_config.dylibs[0].path, "dynjectd.c", PATH_MAX);
  strlcpy(g_config.dylibs[1].path, "dynject_loader.c", PATH_MAX);
  g_config.dylibs[0].default_allow = 1;
  g_config.dylibs[1].default_allow = 0;
  strlcpy(g_config.dylibs[1].overrides[0].pattern, "second", 256);
  g_config.dylibs[1].overrides[0].allow = 1;
  g_config.dylibs[1].override_count = 1;

  assert(envp_pointer_count(511, 0, 513) == 513);
  assert(envp_pointer_count(511, 1, 513) == 512);
  assert(envp_pointer_count(512, 0, 513) == 0);

  check_envp(3, -1, 4);     /* appended */
  check_envp(3, 1, 3);      /* replaced in place */
  check_envp(511, -1, 512); /* the largest list: 511 + DYLD + NULL fills the array */
  check_envp(511, 7, 511);
  check_envp(512, -1, 0);   /* too many: skip injection rather than drop variables */

  check_exception_port_release();
  check_remote_reads();
  check_envp_dyld_at_page_end();
  check_envp_unreadable();
  check_value_capacity();
  check_bundle_identifier();
  check_verified_policy();
  check_daemon_names();
  check_config();
  check_wait();
  check_exec_identity();
  check_copy_printable();
  check_forged_exception();
  check_kernel_exception();

  Worker workers[] = {
      {"first", "DYLD_INSERT_LIBRARIES=dynjectd.c"},
      {"second", "DYLD_INSERT_LIBRARIES=dynjectd.c:dynject_loader.c"},
  };
  pthread_t threads[2];
  for (int i = 0; i < 2; i++)
    assert(pthread_create(&threads[i], NULL, run_policy, &workers[i]) == 0);
  for (int i = 0; i < 2; i++) assert(pthread_join(threads[i], NULL) == 0);

  puts("daemon policy, envp rewrite, remote reads and port release passed");
  return 0;
}
