#define main dynject_loader_main
#include "../dynject_loader.c"
#undef main

#include <assert.h>
#include <sys/wait.h>

/* A child of this test has the test's own process name and owner. */
static pid_t child(int ignore_term) {
  pid_t pid = fork();
  assert(pid >= 0);
  if (pid == 0) {
    if (ignore_term) signal(SIGTERM, SIG_IGN);
    for (;;) pause();
  }
  return pid;
}

static int ended_by(pid_t pid) {
  int status = 0;
  assert(waitpid(pid, &status, 0) == pid);
  return WIFSIGNALED(status) ? WTERMSIG(status) : -1;
}

int main(int argc, char** argv) {
  const char* name = strrchr(argv[0], '/');
  pid_t pids[8];
  pid_t a, b;

  (void)argc;
  name = name != NULL ? name + 1 : argv[0];
  log_init("test_loader_stop", "/dev/null", 0);

  /* nothing running: nothing found, and the caller is never counted */
  assert(find_processes(name, getuid(), pids, 8) == 0);
  assert(stop_processes(name, getuid(), 200) == 0);
  /* another owner's processes are left alone */
  a = child(0);
  usleep(50 * 1000);
  assert(find_processes(name, getuid() + 1, pids, 8) == 0);
  assert(find_processes("some-other-name", getuid(), pids, 8) == 0);
  assert(find_processes(name, getuid(), pids, 8) == 1 && pids[0] == a);

  /* two running: both are ended with SIGTERM */
  b = child(0);
  usleep(50 * 1000);
  assert(stop_processes(name, getuid(), 2000) == 2);
  assert(ended_by(a) == SIGTERM);
  assert(ended_by(b) == SIGTERM);

  /* one that ignores SIGTERM is killed after the grace period */
  a = child(1);
  usleep(50 * 1000);
  assert(stop_processes(name, getuid(), 200) == 1);
  assert(ended_by(a) == SIGKILL);
  assert(find_processes(name, getuid(), pids, 8) == 0);

  puts("loader: running daemons are found and stopped");
  return 0;
}
