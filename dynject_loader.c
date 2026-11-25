/*
 * dynject_loader.c — one-shot amfid patcher for dynjectd
 *
 */

#include <dlfcn.h>
#include <errno.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <objc/runtime.h>
#include <ptrauth.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "log.h"

#define AMFI_FRAMEWORK_PATH            \
  "/System/Library/PrivateFrameworks/" \
  "AppleMobileFileIntegrity.framework/AppleMobileFileIntegrity"

#define AMFI_CLASS_NAME "AMFIPathValidator_macos"
#define AMFI_SELECTOR "validateWithError:"

#define HOOK_SIZE 16
/* The stub stops overriding by itself this long after it is installed. */
#define GUARD_MS 300

#define DEFAULT_DYNJECTD "/opt/dynject/bin/dynjectd"
#define DEFAULT_CONFIG "/opt/dynject/etc/dynjectd.conf"
#define DEFAULT_LOGFILE "/opt/dynject/log/dynjectd.log"

#define INSN_LDR_X17_8 0x58000051U
#define INSN_BR_X17 0xD61F0220U
#define PAGE_SZ 0x4000U

/* Layout of the two pages allocated in amfid: code (read/execute), then one
 * page of data that holds the stub's "used" flag. */
#define TRAMPOLINE_OFFSET 0x00
#define STUB_OFFSET 0x20
#define STUB_SIZE 0x58
#define STUB_TRAMPOLINE_LITERAL 0x40
#define STUB_DEADLINE_LITERAL 0x48
#define STUB_FLAG_LITERAL 0x50

extern const uint8_t amfid_stub_template[];
extern const uint8_t amfid_stub_template_end[];

static uint64_t counter_ticks(void) {
  uint64_t value;
  __asm__ volatile("mrs %0, cntvct_el0" : "=r"(value));
  return value;
}

static uint64_t counter_frequency(void) {
  uint64_t value;
  __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(value));
  return value;
}

static int g_verbose = 0;

static struct {
  task_t amfid_task;
  mach_vm_address_t fn_addr;
  mach_vm_address_t page_addr;
  mach_vm_address_t flag_addr;
  uint8_t original[HOOK_SIZE];
  int active;
} g_patch;

typedef enum {
  ENTRY_ORIGINAL, /* the validator's own first instructions */
  ENTRY_HOOKED,   /* an entry hook, left by a loader that didn't finish */
  ENTRY_UNKNOWN,
} EntryState;

/* `expected` is the same function in this process: amfid and the loader map
 * the framework from the same shared cache, and only amfid's copy is ever
 * patched. */
static EntryState entry_state(const uint8_t* entry, const uint8_t* expected) {
  uint32_t ldr = INSN_LDR_X17_8;
  uint32_t br = INSN_BR_X17;

  if (memcmp(entry, expected, HOOK_SIZE) == 0) return ENTRY_ORIGINAL;
  if (memcmp(entry, &ldr, 4) == 0 && memcmp(entry + 4, &br, 4) == 0) {
    return ENTRY_HOOKED;
  }
  return ENTRY_UNKNOWN;
}

/* Fills the code page: the trampoline (the validator's first instructions and
 * a jump back into it) and the stub. Returns -1 if the stub isn't the size
 * this layout expects. */
static int build_code_page(uint8_t* page_buf, const uint8_t* original,
                           uint64_t continue_addr, uint64_t trampoline_addr,
                           uint64_t deadline, uint64_t flag_addr) {
  uint32_t ldr_x17_8 = INSN_LDR_X17_8;
  uint32_t br_x17 = INSN_BR_X17;
  uint8_t* stub = page_buf + STUB_OFFSET;

  if ((size_t)(amfid_stub_template_end - amfid_stub_template) != STUB_SIZE) {
    return -1;
  }

  memcpy(page_buf + TRAMPOLINE_OFFSET, original, HOOK_SIZE);
  memcpy(page_buf + TRAMPOLINE_OFFSET + 0x10, &ldr_x17_8, 4);
  memcpy(page_buf + TRAMPOLINE_OFFSET + 0x14, &br_x17, 4);
  memcpy(page_buf + TRAMPOLINE_OFFSET + 0x18, &continue_addr, 8);

  memcpy(stub, amfid_stub_template, STUB_SIZE);
  memcpy(stub + STUB_TRAMPOLINE_LITERAL, &trampoline_addr, 8);
  memcpy(stub + STUB_DEADLINE_LITERAL, &deadline, 8);
  memcpy(stub + STUB_FLAG_LITERAL, &flag_addr, 8);
  return 0;
}

/* Writes HOOK_SIZE bytes over the validator's entry in amfid. */
static kern_return_t write_entry(task_t task, mach_vm_address_t fn_addr,
                                 const uint8_t* bytes, const char** step) {
  mach_vm_address_t fn_page = fn_addr & ~(mach_vm_address_t)(PAGE_SZ - 1);
  kern_return_t kr;

  *step = "protect";
  kr = mach_vm_protect(task, fn_page, PAGE_SZ, FALSE,
                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
  if (kr != KERN_SUCCESS) return kr;

  *step = "write";
  kr = mach_vm_write(task, fn_addr, (vm_offset_t)bytes,
                     (mach_msg_type_number_t)HOOK_SIZE);
  if (kr != KERN_SUCCESS) {
    mach_vm_protect(task, fn_page, PAGE_SZ, FALSE,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    return kr;
  }

  *step = "protect back";
  return mach_vm_protect(task, fn_page, PAGE_SZ, FALSE,
                         VM_PROT_READ | VM_PROT_EXECUTE);
}

static pid_t find_amfid_pid(void) {
  int pid_count;
  pid_t* pid_list;
  int found_count;
  pid_t result;
  char path[PROC_PIDPATHINFO_MAXSIZE];
  int i;

  pid_count = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0) / (int)sizeof(pid_t);
  if (pid_count <= 0) {
    return -1;
  }

  pid_list = calloc((size_t)pid_count, sizeof(pid_t));
  if (pid_list == NULL) {
    return -1;
  }

  found_count = proc_listpids(PROC_ALL_PIDS, 0, pid_list,
                              pid_count * (int)sizeof(pid_t)) /
                (int)sizeof(pid_t);
  result = -1;

  for (i = 0; i < found_count; i++) {
    memset(path, 0, sizeof(path));
    if (proc_pidpath(pid_list[i], path, sizeof(path)) > 0) {
      if (strcmp(path, "/usr/libexec/amfid") == 0) {
        result = pid_list[i];
        break;
      }
    }
  }

  free(pid_list);
  return result;
}

static mach_vm_address_t find_validate_imp(void) {
  void* handle;
  Class cls;
  Method method;
  IMP imp;
  mach_vm_address_t address;

  handle = dlopen(AMFI_FRAMEWORK_PATH, RTLD_LAZY | RTLD_GLOBAL);
  if (handle == NULL) {
    LOG("ERROR dlopen %s: %s", AMFI_FRAMEWORK_PATH, dlerror());
    return 0;
  }

  cls = objc_getClass(AMFI_CLASS_NAME);
  if (cls == NULL) {
    LOG("ERROR objc_getClass(%s) returned NULL", AMFI_CLASS_NAME);
    return 0;
  }

  method = class_getInstanceMethod(cls, sel_registerName(AMFI_SELECTOR));
  if (method == NULL) {
    LOG("ERROR class_getInstanceMethod(%s) returned NULL", AMFI_SELECTOR);
    return 0;
  }

  imp = method_getImplementation(method);
  address = (mach_vm_address_t)ptrauth_strip((void*)imp,
                                             ptrauth_key_function_pointer);

  VLOG("IMP [%s %s] = 0x%llx", AMFI_CLASS_NAME, AMFI_SELECTOR,
       (unsigned long long)address);

  return address;
}

static int install_hook(task_t task, mach_vm_address_t fn_addr,
                        const uint8_t* expected_entry) {
  kern_return_t kr;
  mach_vm_size_t bytes_read;
  mach_vm_address_t page_addr;
  mach_vm_address_t trampoline_addr;
  mach_vm_address_t stub_addr;
  uint64_t continue_addr;
  mach_vm_address_t flag_addr;
  uint8_t page_buf[PAGE_SZ];
  uint8_t entry_hook[HOOK_SIZE];
  uint64_t now, ticks_per_ms, deadline;
  const char* step = "";

  bytes_read = 0;
  kr = mach_vm_read_overwrite(task, fn_addr, HOOK_SIZE,
                              (mach_vm_address_t)g_patch.original, &bytes_read);
  if (kr != KERN_SUCCESS || bytes_read != HOOK_SIZE) {
    LOG("ERROR read original bytes: %s", mach_error_string(kr));
    return -1;
  }

  switch (entry_state(g_patch.original, expected_entry)) {
    case ENTRY_ORIGINAL:
      break;
    case ENTRY_HOOKED:
      /* A loader that was killed before it removed its hook. Put the
       * validator's own instructions back before hooking again, or the
       * trampoline would copy the old hook instead of them. */
      kr = write_entry(task, fn_addr, expected_entry, &step);
      if (kr != KERN_SUCCESS) {
        LOG("ERROR amfid still has an earlier hook and restoring it failed "
            "(%s: %s)",
            step, mach_error_string(kr));
        return -1;
      }
      LOG("restored amfid's validator from a hook an earlier loader left");
      memcpy(g_patch.original, expected_entry, HOOK_SIZE);
      break;
    default:
      LOG("ERROR amfid's validator doesn't start with the expected "
          "instructions; not hooking");
      return -1;
  }

  now = counter_ticks();
  ticks_per_ms = counter_frequency() / 1000;
  if (ticks_per_ms == 0 || ticks_per_ms > (UINT64_MAX - now) / GUARD_MS) {
    LOG("ERROR unusable counter for the override deadline");
    return -1;
  }
  deadline = now + ticks_per_ms * GUARD_MS;

  page_addr = 0;
  kr = mach_vm_allocate(task, &page_addr, 2 * PAGE_SZ, VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS) {
    LOG("ERROR mach_vm_allocate: %s", mach_error_string(kr));
    return -1;
  }

  trampoline_addr = page_addr + TRAMPOLINE_OFFSET;
  stub_addr = page_addr + STUB_OFFSET;
  flag_addr = page_addr + PAGE_SZ; /* zero-filled: not used yet */
  continue_addr = (uint64_t)(fn_addr + HOOK_SIZE);

  memset(page_buf, 0, sizeof(page_buf));
  if (build_code_page(page_buf, g_patch.original, continue_addr,
                      trampoline_addr, deadline, flag_addr) != 0) {
    LOG("ERROR stub has an unexpected size");
    mach_vm_deallocate(task, page_addr, 2 * PAGE_SZ);
    return -1;
  }

  kr = mach_vm_write(task, page_addr, (vm_offset_t)page_buf,
                     (mach_msg_type_number_t)PAGE_SZ);
  if (kr != KERN_SUCCESS) {
    LOG("ERROR mach_vm_write (page): %s", mach_error_string(kr));
    mach_vm_deallocate(task, page_addr, 2 * PAGE_SZ);
    return -1;
  }

  kr = mach_vm_protect(task, page_addr, PAGE_SZ, FALSE,
                       VM_PROT_READ | VM_PROT_EXECUTE);
  if (kr != KERN_SUCCESS) {
    LOG("ERROR mach_vm_protect (page RX): %s", mach_error_string(kr));
    mach_vm_deallocate(task, page_addr, 2 * PAGE_SZ);
    return -1;
  }

  /* entry hook */
  {
    uint32_t ldr_hook = INSN_LDR_X17_8;
    uint32_t br_hook = INSN_BR_X17;
    memcpy(entry_hook + 0, &ldr_hook, 4);
    memcpy(entry_hook + 4, &br_hook, 4);
    memcpy(entry_hook + 8, &stub_addr, 8);
  }

  /* cow-patch fn_addr with the entry hook */
  kr = write_entry(task, fn_addr, entry_hook, &step);
  if (kr != KERN_SUCCESS && strcmp(step, "protect back") != 0) {
    LOG("ERROR entry hook (%s): %s", step, mach_error_string(kr));
    mach_vm_deallocate(task, page_addr, 2 * PAGE_SZ);
    return -1;
  }
  if (kr != KERN_SUCCESS) {
    LOG("ERROR mach_vm_protect (fn RX): %s", mach_error_string(kr));
  }

  VLOG("stub        @ 0x%llx", (unsigned long long)stub_addr);
  VLOG("trampoline  @ 0x%llx", (unsigned long long)trampoline_addr);
  VLOG("entry hook  @ 0x%llx (16 bytes)", (unsigned long long)fn_addr);
  VLOG("one override, ending by itself within %dms", GUARD_MS);

  g_patch.amfid_task = task;
  g_patch.fn_addr = fn_addr;
  g_patch.page_addr = page_addr;
  g_patch.flag_addr = flag_addr;
  g_patch.active = 1;
  return 0;
}

/* Whether the stub has used its one override: 1 or 0, -1 if amfid's memory
 * couldn't be read. */
static int override_used(void) {
  uint32_t used = 0;
  mach_vm_size_t bytes_read = 0;
  kern_return_t kr;

  kr = mach_vm_read_overwrite(g_patch.amfid_task, g_patch.flag_addr,
                              sizeof(used), (mach_vm_address_t)&used,
                              &bytes_read);
  if (kr != KERN_SUCCESS || bytes_read != sizeof(used)) return -1;
  return used != 0;
}

static void remove_hook(void) {
  const char* step = "";
  kern_return_t kr;

  if (!g_patch.active) {
    return;
  }

  kr = write_entry(g_patch.amfid_task, g_patch.fn_addr, g_patch.original,
                   &step);
  if (kr == KERN_SUCCESS || strcmp(step, "protect back") == 0) {
    VLOG("restored validateWithError: normal validation active");
  } else {
    LOG("ERROR restore %s failed: %s; the entry hook remains, its stub stops "
        "overriding after one use or %dms",
        step, mach_error_string(kr), GUARD_MS);
  }

  /* The two pages stay mapped: a validation that was already running when
   * the entry was restored still returns through the stub. */
  mach_port_deallocate(mach_task_self(), g_patch.amfid_task);

  memset(&g_patch, 0, sizeof(g_patch));
}

static pid_t launch_dynjectd(const char* path, const char* config,
                             const char* logfile, int verbose) {
  pid_t new_pid;
  const char* argv[10];
  int argc;
  posix_spawnattr_t attr;
  int result;

  argc = 0;
  argv[argc++] = path;
  argv[argc++] = "-c";
  argv[argc++] = config;
  argv[argc++] = "-l";
  argv[argc++] = logfile;
  if (verbose) {
    argv[argc++] = "-v";
  }
  argv[argc] = NULL;

  /* places dynjectd in its own process group */
  posix_spawnattr_init(&attr);
  posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
  posix_spawnattr_setpgroup(&attr, 0);

  new_pid = -1;
  result = posix_spawn(&new_pid, path, NULL, &attr, (char* const*)argv, NULL);
  posix_spawnattr_destroy(&attr);

  if (result != 0) {
    LOG("ERROR posix_spawn(%s): %s", path, strerror(result));
    return -1;
  }

  return new_pid;
}

int main(int argc, char* argv[]) {
  const char* dynjectd_path;
  const char* config_path;
  const char* logfile_path;
  pid_t amfid_pid;
  task_t amfid_task;
  mach_vm_address_t imp_address;
  pid_t dynjectd_pid;
  kern_return_t kr;
  int i;
  int used;
  int child_status;

  const char* log_path = DEFAULT_LOGFILE;

  dynjectd_path = DEFAULT_DYNJECTD;
  config_path = DEFAULT_CONFIG;
  logfile_path = DEFAULT_LOGFILE;

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
      dynjectd_path = argv[++i];
    } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
      config_path = argv[++i];
    } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
      logfile_path = argv[++i];
      log_path = argv[i];
    } else if (strcmp(argv[i], "-v") == 0) {
      g_verbose = 1;
    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      fprintf(stderr,
              "usage: dynject_loader [-v] [-d dynjectd] [-c config] [-l "
              "logfile]\n");
      return 0;
    }
  }

  if (geteuid() != 0) {
    fprintf(stderr, "error: must run as root\n");
    return 1;
  }

  if (access(dynjectd_path, X_OK) != 0) {
    fprintf(stderr, "error: dynjectd not found at %s\n", dynjectd_path);
    return 1;
  }

  log_init("dynject_loader", log_path, g_verbose);

  LOG("dynject_loader");

  /* find amfid */
  amfid_pid = find_amfid_pid();
  if (amfid_pid < 0) {
    LOG("ERROR amfid not found");
    return 1;
  }
  VLOG("amfid pid=%d", (int)amfid_pid);

  /* get amfid task port */
  amfid_task = MACH_PORT_NULL;
  kr = task_for_pid(mach_task_self(), amfid_pid, &amfid_task);
  if (kr != KERN_SUCCESS) {
    LOG("ERROR task_for_pid(%d): %s", (int)amfid_pid, mach_error_string(kr));
    return 1;
  }
  VLOG("amfid task=0x%x", amfid_task);

  /* resolve validateWithError IMP */
  imp_address = find_validate_imp();
  if (imp_address == 0) {
    mach_port_deallocate(mach_task_self(), amfid_task);
    return 1;
  }
  VLOG("hooking  [%s %s] @ 0x%llx", AMFI_CLASS_NAME, AMFI_SELECTOR,
       (unsigned long long)imp_address);

  /* install trampoline hook */
  if (install_hook(amfid_task, imp_address,
                   (const uint8_t*)(uintptr_t)imp_address) != 0) {
    mach_port_deallocate(mach_task_self(), amfid_task);
    return 1;
  }
  VLOG("hooked validateWithError");

  /* launch dynjectd  */
  dynjectd_pid =
      launch_dynjectd(dynjectd_path, config_path, logfile_path, g_verbose);
  if (dynjectd_pid < 0) {
    remove_hook();
    return 1;
  }
  VLOG("launched dynjectd pid=%d", (int)dynjectd_pid);

  /* The kernel has amfid check dynjectd's signature during the spawn, so by
   * now the one approval has been used, or wasn't needed because the kernel
   * already knows this file's signature. Either way the hook can go. */
  used = override_used();

  /* restore amfid */
  remove_hook();

  usleep(20 * 1000);
  if (waitpid(dynjectd_pid, &child_status, WNOHANG) == dynjectd_pid) {
    if (used == 1) {
      LOG("ERROR dynjectd (pid=%d) exited although one signature was "
          "approved in the window: the approval may have gone to another "
          "program",
          (int)dynjectd_pid);
    } else {
      LOG("ERROR dynjectd (pid=%d) exited right after launch",
          (int)dynjectd_pid);
    }
    return 1;
  }

  LOG("done dynjectd running (pid=%d); amfid hook removed (%s)",
      (int)dynjectd_pid,
      used == 1 ? "one signature approved"
                : used == 0 ? "no approval was needed" : "state unreadable");
  return 0;
}
