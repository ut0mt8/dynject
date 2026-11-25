#define main dynjectd_main
#include "../dynjectd.c"
#undef main

#include <assert.h>

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

  Worker workers[] = {
      {"first", "DYLD_INSERT_LIBRARIES=dynjectd.c"},
      {"second", "DYLD_INSERT_LIBRARIES=dynjectd.c:dynject_loader.c"},
  };
  pthread_t threads[2];
  for (int i = 0; i < 2; i++)
    assert(pthread_create(&threads[i], NULL, run_policy, &workers[i]) == 0);
  for (int i = 0; i < 2; i++) assert(pthread_join(threads[i], NULL) == 0);

  puts("daemon policy concurrency and envp rewrite passed");
  return 0;
}
