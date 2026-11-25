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
    assert(build_dyld_for_bundle(worker->service, value, sizeof(value)));
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

/* A path that doesn't fit is left out whole, never cut. */
static void check_value_capacity(void) {
  char small[sizeof("DYLD_INSERT_LIBRARIES=dynjectd.c") + 5];
  assert(build_dyld_for_bundle("second", small, sizeof(small)));
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
