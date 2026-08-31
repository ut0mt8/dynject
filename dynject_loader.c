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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

#define AMFI_FRAMEWORK_PATH            \
  "/System/Library/PrivateFrameworks/" \
  "AppleMobileFileIntegrity.framework/AppleMobileFileIntegrity"

#define AMFI_CLASS_NAME "AMFIPathValidator_macos"
#define AMFI_SELECTOR "validateWithError:"

#define HOOK_SIZE 16
#define WAIT_MS 200

#define DEFAULT_DYNJECTD "/opt/dynject/bin/dynjectd"
#define DEFAULT_CONFIG "/opt/dynject/etc/dynjectd.conf"
#define DEFAULT_LOGFILE "/opt/dynject/log/dynjectd.log"

#define INSN_LDR_X17_8 0x58000051U
#define INSN_LDR_X17_20 0x580000B1U
#define INSN_BR_X17 0xD61F0220U
#define INSN_BLR_X17 0xD63F0220U
#define INSN_MOVZ_X0_1 0xD2800020U
#define INSN_STP_X29_X30 0xA9BF7BFDU
#define INSN_LDP_X29_X30 0xA8C17BFDU
#define INSN_RET 0xD65F03C0U
#define PAGE_SZ 0x4000U

static int g_verbose = 0;

static struct {
  task_t amfid_task;
  mach_vm_address_t fn_addr;
  mach_vm_address_t page_addr;
  uint8_t original[HOOK_SIZE];
  int active;
} g_patch;

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

static int install_hook(task_t task, mach_vm_address_t fn_addr) {
  kern_return_t kr;
  mach_vm_size_t bytes_read;
  mach_vm_address_t page_addr;
  mach_vm_address_t trampoline_addr;
  mach_vm_address_t stub_addr;
  uint64_t continue_addr;
  uint8_t page_buf[PAGE_SZ];
  uint8_t entry_hook[HOOK_SIZE];
  mach_vm_address_t fn_page;

  bytes_read = 0;
  kr = mach_vm_read_overwrite(task, fn_addr, HOOK_SIZE,
                              (mach_vm_address_t)g_patch.original, &bytes_read);
  if (kr != KERN_SUCCESS || bytes_read != HOOK_SIZE) {
    LOG("ERROR read original bytes: %s", mach_error_string(kr));
    return -1;
  }

  page_addr = 0;
  kr = mach_vm_allocate(task, &page_addr, PAGE_SZ, VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS) {
    LOG("ERROR mach_vm_allocate: %s", mach_error_string(kr));
    return -1;
  }

  trampoline_addr = page_addr + 0x00;
  stub_addr = page_addr + 0x20;
  continue_addr = (uint64_t)(fn_addr + HOOK_SIZE);

  memset(page_buf, 0, sizeof(page_buf));

  /* trampoline */
  memcpy(page_buf + 0x00, g_patch.original, HOOK_SIZE);

  {
    uint32_t ldr_x17_8 = INSN_LDR_X17_8;
    uint32_t br_x17 = INSN_BR_X17;
    memcpy(page_buf + 0x10, &ldr_x17_8, 4);
    memcpy(page_buf + 0x14, &br_x17, 4);
    memcpy(page_buf + 0x18, &continue_addr, 8);
  }

  /* stub */
  {
    uint32_t stp = INSN_STP_X29_X30;
    uint32_t ldr_x17_20 = INSN_LDR_X17_20;
    uint32_t blr_x17 = INSN_BLR_X17;
    uint32_t movz_x0_1 = INSN_MOVZ_X0_1;
    uint32_t ldp = INSN_LDP_X29_X30;
    uint32_t ret_insn = INSN_RET;
    memcpy(page_buf + 0x20, &stp, 4);
    memcpy(page_buf + 0x24, &ldr_x17_20, 4);
    memcpy(page_buf + 0x28, &blr_x17, 4);
    memcpy(page_buf + 0x2C, &movz_x0_1, 4);
    memcpy(page_buf + 0x30, &ldp, 4);
    memcpy(page_buf + 0x34, &ret_insn, 4);
    memcpy(page_buf + 0x38, &trampoline_addr, 8);
  }

  kr = mach_vm_write(task, page_addr, (vm_offset_t)page_buf,
                     (mach_msg_type_number_t)PAGE_SZ);
  if (kr != KERN_SUCCESS) {
    LOG("ERROR mach_vm_write (page): %s", mach_error_string(kr));
    mach_vm_deallocate(task, page_addr, PAGE_SZ);
    return -1;
  }

  kr = mach_vm_protect(task, page_addr, PAGE_SZ, FALSE,
                       VM_PROT_READ | VM_PROT_EXECUTE);
  if (kr != KERN_SUCCESS) {
    LOG("ERROR mach_vm_protect (page RX): %s", mach_error_string(kr));
    mach_vm_deallocate(task, page_addr, PAGE_SZ);
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
  fn_page = fn_addr & ~(mach_vm_address_t)(PAGE_SZ - 1);

  kr = mach_vm_protect(task, fn_page, PAGE_SZ, FALSE,
                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
  if (kr != KERN_SUCCESS) {
    LOG("ERROR mach_vm_protect (fn RW|COPY): %s", mach_error_string(kr));
    mach_vm_deallocate(task, page_addr, PAGE_SZ);
    return -1;
  }

  kr = mach_vm_write(task, fn_addr, (vm_offset_t)entry_hook,
                     (mach_msg_type_number_t)HOOK_SIZE);
  if (kr != KERN_SUCCESS) {
    LOG("ERROR mach_vm_write (entry hook): %s", mach_error_string(kr));
    mach_vm_protect(task, fn_page, PAGE_SZ, FALSE,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    mach_vm_deallocate(task, page_addr, PAGE_SZ);
    return -1;
  }

  kr = mach_vm_protect(task, fn_page, PAGE_SZ, FALSE,
                       VM_PROT_READ | VM_PROT_EXECUTE);
  if (kr != KERN_SUCCESS) {
    LOG("EROOR mach_vm_protect (fn RX): %s", mach_error_string(kr));
  }

  VLOG("stub        @ 0x%llx", (unsigned long long)stub_addr);
  VLOG("trampoline  @ 0x%llx", (unsigned long long)trampoline_addr);
  VLOG("entry hook  @ 0x%llx (16 bytes)", (unsigned long long)fn_addr);

  g_patch.amfid_task = task;
  g_patch.fn_addr = fn_addr;
  g_patch.page_addr = page_addr;
  g_patch.active = 1;
  return 0;
}

static void remove_hook(void) {
  mach_vm_address_t fn_page;
  kern_return_t kr;

  if (!g_patch.active) {
    return;
  }

  fn_page = g_patch.fn_addr & ~(mach_vm_address_t)(PAGE_SZ - 1);

  kr = mach_vm_protect(g_patch.amfid_task, fn_page, PAGE_SZ, FALSE,
                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
  if (kr == KERN_SUCCESS) {
    kr = mach_vm_write(g_patch.amfid_task, g_patch.fn_addr,
                       (vm_offset_t)g_patch.original,
                       (mach_msg_type_number_t)HOOK_SIZE);
    if (kr == KERN_SUCCESS) {
      mach_vm_protect(g_patch.amfid_task, fn_page, PAGE_SZ, FALSE,
                      VM_PROT_READ | VM_PROT_EXECUTE);
      VLOG("restored validateWithError: normal validation active");
    } else {
      LOG("ERROR restore write failed: %s amfid hook remains",
          mach_error_string(kr));
    }
  } else {
    LOG("ERROR restore protect failed: %s amfid hook remains",
        mach_error_string(kr));
  }

  mach_vm_deallocate(g_patch.amfid_task, g_patch.page_addr, PAGE_SZ);
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
  if (install_hook(amfid_task, imp_address) != 0) {
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

  VLOG("waiting %dms for entitlement validation", WAIT_MS);
  usleep((useconds_t)WAIT_MS * 1000);

  /* restore amfid */
  remove_hook();
  LOG("done dynjectd running (pid=%d)", (int)dynjectd_pid);
  return 0;
}
