/*
 * dynjectd.c — dylib injection daemon
 *
 */

#include <CoreFoundation/CoreFoundation.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/arm/thread_state.h>
#include <mach/exception_types.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <ptrauth.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "log.h"

#define MAX_DYLIBS 32
#define MAX_OVERRIDES 64
#define MAX_RULES 128

#define HW_BP_BCR_ENABLE 0x1E5U
#define BP_WAIT_TIMEOUT_MS 300

typedef struct {
  struct {
    char path[PATH_MAX];
    int default_allow;
    struct {
      char pattern[256];
      int allow;
    } overrides[MAX_OVERRIDES];
    int override_count;
  } dylibs[MAX_DYLIBS];
  int dylib_count;
  char allow_rules[MAX_RULES][PATH_MAX];
  int allow_count;
  char deny_rules[MAX_RULES][PATH_MAX];
  int deny_count;
  int inject_ui_apps;
  int skip_helpers;
} Config;

static Config g_config;

static void config_set_defaults(void) {
  memset(&g_config, 0, sizeof(g_config));
  g_config.inject_ui_apps = 1;
  g_config.skip_helpers = 1;
}

static void config_load(const char* path) {
  FILE* file;
  char line[PATH_MAX + 64];
  char* s;
  char* colon;
  char* key;
  char* value;
  size_t len;

  file = fopen(path, "r");
  if (file == NULL) {
    return;
  }

  while (fgets(line, sizeof(line), file) != NULL) {
    s = line;
    while (*s == ' ' || *s == '\t') {
      s++;
    }

    len = strlen(s);
    while (len > 0 &&
           (s[len - 1] == '\n' || s[len - 1] == '\r' || s[len - 1] == ' ')) {
      s[--len] = '\0';
    }

    if (len == 0 || s[0] == '#') {
      continue;
    }

    colon = strchr(s, ':');
    if (colon == NULL) {
      continue;
    }
    *colon = '\0';
    key = s;
    value = colon + 1;
    while (*value == ' ') {
      value++;
    }

    if (strcmp(key, "dylib") == 0 && g_config.dylib_count < MAX_DYLIBS) {
      char dylib_path[PATH_MAX];
      int default_allow = 1;
      char* colon = strchr(value, ':');

      if (colon != NULL) {
        size_t plen = (size_t)(colon - value);
        if (plen >= PATH_MAX) plen = PATH_MAX - 1;
        memcpy(dylib_path, value, plen);
        dylib_path[plen] = '\0';
        default_allow = (strcmp(colon + 1, "allow") == 0) ? 1 : 0;
      } else {
        strlcpy(dylib_path, value, PATH_MAX);
      }

      strlcpy(g_config.dylibs[g_config.dylib_count].path, dylib_path, PATH_MAX);
      g_config.dylibs[g_config.dylib_count].default_allow = default_allow;
      g_config.dylib_count++;

    } else if (strcmp(key, "dylib-override") == 0) {
      char dylib_path[PATH_MAX];
      char policy_str[8];
      char pattern[256];
      char* p1;
      char* p2;
      char* p3;
      int i;

      p1 = strchr(value, ':');
      if (p1 == NULL) continue;

      size_t plen = (size_t)(p1 - value);
      if (plen >= PATH_MAX) plen = PATH_MAX - 1;
      memcpy(dylib_path, value, plen);
      dylib_path[plen] = '\0';

      p2 = strchr(p1 + 1, ':');
      if (p2 == NULL) continue;

      plen = (size_t)(p2 - (p1 + 1));
      if (plen >= sizeof(policy_str)) plen = sizeof(policy_str) - 1;
      memcpy(policy_str, p1 + 1, plen);
      policy_str[plen] = '\0';

      p3 = p2 + 1;
      strlcpy(pattern, p3, sizeof(pattern));

      for (i = 0; i < g_config.dylib_count; i++) {
        if (strcmp(g_config.dylibs[i].path, dylib_path) != 0) {
          continue;
        }
        int oi = g_config.dylibs[i].override_count;
        if (oi >= MAX_OVERRIDES) break;
        strlcpy(g_config.dylibs[i].overrides[oi].pattern, pattern, 256);
        g_config.dylibs[i].overrides[oi].allow =
            (strcmp(policy_str, "allow") == 0) ? 1 : 0;
        g_config.dylibs[i].override_count++;
        break;
      }

    } else if (strcmp(key, "allow") == 0 && g_config.allow_count < MAX_RULES) {
      strlcpy(g_config.allow_rules[g_config.allow_count], value, PATH_MAX);
      g_config.allow_count++;

    } else if (strcmp(key, "deny") == 0 && g_config.deny_count < MAX_RULES) {
      strlcpy(g_config.deny_rules[g_config.deny_count], value, PATH_MAX);
      g_config.deny_count++;

    } else if (strcmp(key, "ui_apps") == 0) {
      g_config.inject_ui_apps =
          (strcmp(value, "no") != 0 && strcmp(value, "0") != 0);

    } else if (strcmp(key, "skip_helpers") == 0) {
      g_config.skip_helpers =
          (strcmp(value, "no") != 0 && strcmp(value, "0") != 0);
    }
  }

  fclose(file);
}

typedef enum {
  MATCH_INJECT = 1,
  SKIP_HELPER = -1,
  SKIP_DENIED = -2,
  SKIP_NO_GUI = -3,
} MatchResult;

static const char* match_skip_reason(MatchResult result) {
  switch (result) {
    case SKIP_HELPER:
      return "helper";
    case SKIP_DENIED:
      return "denied";
    case SKIP_NO_GUI:
      return "no_gui";
    default:
      return "unknown";
  }
}

static int path_is_ui_app(const char* path) {
  static const char* ui_prefixes[] = {"/Applications/", "/System/Applications/",
                                      "/System/Library/CoreServices/", NULL};
  size_t prefix_len;
  int i;

  for (i = 0; ui_prefixes[i] != NULL; i++) {
    prefix_len = strlen(ui_prefixes[i]);

    if (strncmp(path, ui_prefixes[i], prefix_len) != 0) {
      continue;
    }
    if (strstr(path + prefix_len, ".app/") != NULL) {
      return 1;
    }
  }

  return 0;
}

static int name_is_helper(const char* name) {
  static const char* helper_patterns[] = {" Helper", NULL};
  int i;

  for (i = 0; helper_patterns[i] != NULL; i++) {
    if (strstr(name, helper_patterns[i]) != NULL) {
      return 1;
    }
  }

  return 0;
}

static MatchResult check_match(const char* process_name,
                               const char* process_path) {
  int i;

  if (g_config.skip_helpers && name_is_helper(process_name)) {
    return SKIP_HELPER;
  }

  for (i = 0; i < g_config.deny_count; i++) {
    if (strstr(process_name, g_config.deny_rules[i]) != NULL ||
        strstr(process_path, g_config.deny_rules[i]) != NULL) {
      return SKIP_DENIED;
    }
  }

  for (i = 0; i < g_config.allow_count; i++) {
    if (strstr(process_name, g_config.allow_rules[i]) != NULL ||
        strstr(process_path, g_config.allow_rules[i]) != NULL) {
      return MATCH_INJECT;
    }
  }

  if (g_config.inject_ui_apps && path_is_ui_app(process_path)) {
    return MATCH_INJECT;
  }

  return SKIP_NO_GUI;
}

static mach_vm_address_t g_posix_spawn_addr = 0;
static mach_vm_address_t g_execve_addr = 0;

static mach_vm_address_t strip_pac(void* function_pointer) {
  return (mach_vm_address_t)ptrauth_strip(function_pointer,
                                          ptrauth_key_function_pointer);
}

static int find_intercept_addresses(void) {
  void* posix_spawn_sym;
  void* execve_sym;

  posix_spawn_sym = dlsym(RTLD_DEFAULT, "posix_spawn");
  execve_sym = dlsym(RTLD_DEFAULT, "execve");

  if (posix_spawn_sym == NULL && execve_sym == NULL) {
    LOG("ERROR posix_spawn and execve not found via dlsym");
    return -1;
  }

  if (posix_spawn_sym != NULL) {
    g_posix_spawn_addr = strip_pac(posix_spawn_sym);
    VLOG("addr posix_spawn @0x%llx", (unsigned long long)g_posix_spawn_addr);
  }

  if (execve_sym != NULL) {
    g_execve_addr = strip_pac(execve_sym);
    VLOG("addr execve @0x%llx", (unsigned long long)g_execve_addr);
  }

  return 0;
}

#define INFO_PLIST_MAX (1024 * 1024)

/* CFBundleIdentifier from one Info.plist. The file is opened without
 * following a symlink and read with a size limit. */
static int read_info_plist_identifier(const char* plist_path, char* out,
                                      size_t out_size) {
  struct stat st;
  uint8_t* bytes = NULL;
  CFDataRef data = NULL;
  CFPropertyListRef plist = NULL;
  ssize_t got = 0;
  size_t total = 0;
  int found = 0;
  int fd;

  fd = open(plist_path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0) return 0;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
      st.st_size > INFO_PLIST_MAX) {
    close(fd);
    return 0;
  }
  bytes = malloc((size_t)st.st_size);
  while (bytes != NULL && total < (size_t)st.st_size &&
         (got = read(fd, bytes + total, (size_t)st.st_size - total)) > 0) {
    total += (size_t)got;
  }
  close(fd);
  if (bytes == NULL || total != (size_t)st.st_size) {
    free(bytes);
    return 0;
  }

  data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, bytes,
                                     (CFIndex)total, kCFAllocatorNull);
  if (data != NULL) {
    plist = CFPropertyListCreateWithData(kCFAllocatorDefault, data,
                                         kCFPropertyListImmutable, NULL, NULL);
  }
  if (plist != NULL && CFGetTypeID(plist) == CFDictionaryGetTypeID()) {
    CFTypeRef value =
        CFDictionaryGetValue((CFDictionaryRef)plist, CFSTR("CFBundleIdentifier"));
    if (value != NULL && CFGetTypeID(value) == CFStringGetTypeID() &&
        CFStringGetCString((CFStringRef)value, out, (CFIndex)out_size,
                           kCFStringEncodingASCII) &&
        out[0] != '\0') {
      found = 1;
    }
  }
  if (plist != NULL) CFRelease(plist);
  if (data != NULL) CFRelease(data);
  free(bytes);
  if (!found && out_size > 0) out[0] = '\0';
  return found;
}

/* The bundle identifier of the app an executable belongs to: the innermost
 * ".app" directory in its resolved path. Returns 1 with the identifier, 0
 * when the path is not inside an app bundle, and -1 (identifier empty) when
 * it is but no identifier could be read. */
static int bundle_identifier_for_executable(const char* executable_path,
                                            char* out, size_t out_size) {
  char resolved[PATH_MAX];
  char plist_path[PATH_MAX];
  const char* path = executable_path;
  const char* scan;
  const char* last = NULL;
  size_t bundle_len;

  if (out_size > 0) out[0] = '\0';
  if (realpath(executable_path, resolved) != NULL) path = resolved;

  for (scan = path; (scan = strstr(scan, ".app/")) != NULL; scan += 5) {
    last = scan;
  }
  if (last == NULL) return 0;
  bundle_len = (size_t)(last - path) + 4;

  if (snprintf(plist_path, sizeof(plist_path), "%.*s/Contents/Info.plist",
               (int)bundle_len, path) < (int)sizeof(plist_path) &&
      read_info_plist_identifier(plist_path, out, out_size)) {
    return 1;
  }
  if (snprintf(plist_path, sizeof(plist_path), "%.*s/Info.plist",
               (int)bundle_len, path) < (int)sizeof(plist_path) &&
      read_info_plist_identifier(plist_path, out, out_size)) {
    return 1;
  }
  return -1;
}

/* A dylib's policy for one subject: the first override whose pattern is in
 * it wins, else the dylib's default. */
static int dylib_policy_for(int i, const char* subject, int ignore_case,
                            const char** reason) {
  int j;

  for (j = 0; j < g_config.dylibs[i].override_count; j++) {
    const char* pattern = g_config.dylibs[i].overrides[j].pattern;
    if ((ignore_case ? strcasestr(subject, pattern) : strstr(subject, pattern)) !=
        NULL) {
      *reason = g_config.dylibs[i].overrides[j].allow ? "override allow"
                                                      : "override deny";
      return g_config.dylibs[i].overrides[j].allow;
    }
  }
  *reason = g_config.dylibs[i].default_allow ? "default allow" : "default deny";
  return g_config.dylibs[i].default_allow;
}

/* `bundle_id` is the launchd label, which whoever submits the job chooses.
 * `verified` is "application.<bundle identifier>." built from the launched
 * app's own Info.plist, or NULL when the program is not in an app bundle. A
 * dylib is injected only if its policy says so for both, so a made-up label
 * can neither pull a dylib into an app it isn't meant for nor dodge a deny. */
static const char* build_dyld_for_bundle(const char* bundle_id,
                                         const char* verified, char* out_buf,
                                         size_t out_size) {
  int i;
  int first;

  strlcpy(out_buf, "DYLD_INSERT_LIBRARIES=", out_size);
  first = 1;

  for (i = 0; i < g_config.dylib_count; i++) {
    const char* reason = "";
    int should_inject = dylib_policy_for(i, bundle_id, 0, &reason);

    if (should_inject && verified != NULL) {
      const char* verified_reason = "";
      if (!dylib_policy_for(i, verified, 1, &verified_reason)) {
        LOG("SKIP dylib[%d] %s: the label %s says inject, the app's own "
            "identifier (%s) says %s",
            i, g_config.dylibs[i].path, bundle_id, verified, verified_reason);
        should_inject = 0;
        reason = "label and app identifier disagree";
      }
    }

    VLOG("policy dylib[%d] %s: %s %s", i, g_config.dylibs[i].path, reason,
         should_inject ? "INJECT" : "skip");

    if (!should_inject) {
      continue;
    }

    if (access(g_config.dylibs[i].path, F_OK) != 0) {
      LOG("SKIP dylib[%d] %s: file not found (remove from config to suppress)",
          i, g_config.dylibs[i].path);
      continue;
    }

    /* Never hand dyld part of a path. */
    size_t used = strlen(out_buf);
    size_t needed = strlen(g_config.dylibs[i].path) + (!first ? 1 : 0);
    if (needed >= out_size - used) {
      LOG("SKIP dylib[%d] %s: injection value full", i,
          g_config.dylibs[i].path);
      continue;
    }

    if (!first) {
      strlcat(out_buf, ":", out_size);
    }
    strlcat(out_buf, g_config.dylibs[i].path, out_size);
    first = 0;
  }

  return first ? NULL : out_buf;
}

static int dylib_count_in_value(const char* dyld_value) {
  const char* p;
  int count;

  p = strchr(dyld_value, '=');
  if (p == NULL || *(p + 1) == '\0') {
    return 0;
  }

  count = 1;
  p++;
  while (*p) {
    if (*p == ':') count++;
    p++;
  }
  return count;
}

/* Reads a NUL-terminated string from the target into local_buffer. It reads at
 * most to the next 4 KiB boundary at a time (every page boundary is one), so a
 * short string that ends just before an unmapped page still reads. Returns the
 * length read (local_buffer is always terminated; a string longer than
 * buffer_size - 1 is cut there), or -1 if a page before the string's end, or
 * the buffer's end, couldn't be read. */
static ssize_t read_remote_string(task_t task, mach_vm_address_t remote_address,
                                  char* local_buffer, size_t buffer_size) {
  size_t got;

  if (local_buffer == NULL || buffer_size == 0) {
    return -1;
  }
  memset(local_buffer, 0, buffer_size);
  if (remote_address == 0) {
    return -1;
  }

  got = 0;
  while (got < buffer_size - 1) {
    mach_vm_address_t address = remote_address + got;
    size_t to_boundary = 4096 - (size_t)(address & 4095);
    size_t want = buffer_size - 1 - got;
    mach_vm_size_t bytes_read = 0;
    kern_return_t kr;

    if (want > to_boundary) {
      want = to_boundary;
    }
    kr = mach_vm_read_overwrite(task, address, want,
                                (mach_vm_address_t)(local_buffer + got),
                                &bytes_read);
    if (kr != KERN_SUCCESS || bytes_read != want) {
      memset(local_buffer, 0, buffer_size);
      return -1;
    }
    if (memchr(local_buffer + got, '\0', want) != NULL) {
      return (ssize_t)strlen(local_buffer);
    }
    got += want;
  }

  local_buffer[buffer_size - 1] = '\0';
  return (ssize_t)(buffer_size - 1);
}

/* Returns 0 and the value, or -1 if the target's memory couldn't be read. A
 * failed read is not the same as a NULL entry. */
static int read_remote_u64(task_t task, mach_vm_address_t remote_address,
                           uint64_t* value) {
  mach_vm_size_t bytes_read;
  kern_return_t kr;

  *value = 0;
  bytes_read = 0;

  kr = mach_vm_read_overwrite(task, remote_address, sizeof(*value),
                              (mach_vm_address_t)value, &bytes_read);

  if (kr != KERN_SUCCESS || bytes_read != sizeof(*value)) {
    *value = 0;
    return -1;
  }

  return 0;
}

static size_t envp_pointer_count(int existing_count, int has_dyld,
                                 size_t capacity) {
  if (existing_count < 0) return 0;
  size_t required = (size_t)existing_count + (has_dyld ? 0 : 1) + 1;
  return required <= capacity ? required : 0;
}

static mach_vm_address_t make_envp_with_dyld(
    task_t task, mach_vm_address_t original_envp_address,
    const char* dyld_value) {
  mach_vm_address_t existing_ptrs[512];
  int existing_count;
  int dyld_entry_index;

  /* 511 existing entries, one new DYLD entry, and the NULL terminator. */
  mach_vm_address_t new_ptr_array[513];
  int new_count;

  size_t dyld_string_len;
  size_t ptr_array_bytes;
  size_t total_allocation;
  mach_vm_address_t allocation_base;
  mach_vm_address_t string_address;

  kern_return_t kr;
  char preview[64];
  int i;

  if (original_envp_address == 0) {
    LOG("ERROR envp pointer (x5) is NULL");
    return 0;
  }

  existing_count = 0;
  dyld_entry_index = -1;

  for (i = 0; i < 511; i++) {
    mach_vm_address_t probe_address;
    mach_vm_address_t entry_value;

    probe_address = original_envp_address + (mach_vm_address_t)(i * 8);
    if (read_remote_u64(task, probe_address, &entry_value) != 0) {
      LOG("SKIP envp: entry %d unreadable", i);
      return 0;
    }

    if (entry_value == 0) {
      break;
    }

    existing_ptrs[existing_count] = entry_value;

    /* Unreadable, we can't tell whether it's an existing DYLD entry. */
    if (read_remote_string(task, entry_value, preview, sizeof(preview)) < 0) {
      LOG("SKIP envp: string %d unreadable", i);
      return 0;
    }
    if (strncmp(preview, "DYLD_INSERT_LIBRARIES=", 22) == 0) {
      dyld_entry_index = existing_count;
    }

    existing_count++;
  }

  /* Do not silently drop the remainder of an unusually large environment. */
  if (i == 511) {
    uint64_t next;
    if (read_remote_u64(task, original_envp_address + (mach_vm_address_t)(i * 8),
                        &next) != 0 ||
        next != 0) {
      LOG("SKIP envp: too many entries");
      return 0;
    }
  }

  dyld_string_len = strlen(dyld_value) + 1;
  size_t pointer_count = envp_pointer_count(
      existing_count, dyld_entry_index >= 0,
      sizeof(new_ptr_array) / sizeof(new_ptr_array[0]));
  if (pointer_count == 0) {
    LOG("SKIP envp: pointer array capacity exceeded");
    return 0;
  }
  ptr_array_bytes = pointer_count * sizeof(new_ptr_array[0]);
  total_allocation = ptr_array_bytes + dyld_string_len + 16;

  allocation_base = 0;
  kr = mach_vm_allocate(task, &allocation_base, total_allocation,
                        VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS) {
    LOG("ERROR mach_vm_allocate envp: %s", mach_error_string(kr));
    return 0;
  }

  string_address = allocation_base + ptr_array_bytes;

  kr = mach_vm_write(task, string_address, (vm_offset_t)dyld_value,
                     (mach_msg_type_number_t)dyld_string_len);
  if (kr != KERN_SUCCESS) {
    LOG("ERROR mach_vm_write DYLD string: %s", mach_error_string(kr));
    mach_vm_deallocate(task, allocation_base, total_allocation);
    return 0;
  }

  new_count = 0;

  for (i = 0; i < existing_count; i++) {
    if (i == dyld_entry_index) {
      new_ptr_array[new_count] = string_address;
    } else {
      new_ptr_array[new_count] = existing_ptrs[i];
    }
    new_count++;
  }

  if (dyld_entry_index < 0) {
    new_ptr_array[new_count] = string_address;
    new_count++;
  }

  new_ptr_array[new_count] = 0;

  kr = mach_vm_write(task, allocation_base, (vm_offset_t)new_ptr_array,
                     (mach_msg_type_number_t)((new_count + 1) * 8));
  if (kr != KERN_SUCCESS) {
    LOG("ERROR mach_vm_write envp pointer array: %s", mach_error_string(kr));
    mach_vm_deallocate(task, allocation_base, total_allocation);
    return 0;
  }

  VLOG("envp %d entries, new array @0x%llx (DYLD at index %d)", new_count,
       (unsigned long long)allocation_base, new_count - 1);

  return allocation_base;
}

static int set_hw_bps(task_t task, int enable) {
  thread_act_array_t thread_list;
  mach_msg_type_number_t thread_count;
  arm_debug_state64_t debug_state;
  mach_msg_type_number_t debug_count;
  kern_return_t kr;
  mach_msg_type_number_t i;

  kr = task_threads(task, &thread_list, &thread_count);
  if (kr != KERN_SUCCESS) {
    return -1;
  }

  for (i = 0; i < thread_count; i++) {
    debug_count = ARM_DEBUG_STATE64_COUNT;
    kr = thread_get_state(thread_list[i], ARM_DEBUG_STATE64,
                          (thread_state_t)&debug_state, &debug_count);
    if (kr != KERN_SUCCESS) {
      mach_port_deallocate(mach_task_self(), thread_list[i]);
      continue;
    }

    if (enable) {
      if (g_posix_spawn_addr != 0) {
        debug_state.__bvr[0] = g_posix_spawn_addr;
        debug_state.__bcr[0] = HW_BP_BCR_ENABLE;
      }
      if (g_execve_addr != 0) {
        debug_state.__bvr[1] = g_execve_addr;
        debug_state.__bcr[1] = HW_BP_BCR_ENABLE;
      }
    } else {
      debug_state.__bvr[0] = 0;
      debug_state.__bcr[0] = 0;
      debug_state.__bvr[1] = 0;
      debug_state.__bcr[1] = 0;
    }

    thread_set_state(thread_list[i], ARM_DEBUG_STATE64,
                     (thread_state_t)&debug_state, debug_count);

    mach_port_deallocate(mach_task_self(), thread_list[i]);
  }

  vm_deallocate(mach_task_self(), (vm_address_t)thread_list,
                thread_count * sizeof(thread_act_t));
  return 0;
}

#pragma pack(4)
typedef struct {
  mach_msg_header_t header;
  mach_msg_body_t body;
  mach_msg_port_descriptor_t thread_port;
  mach_msg_port_descriptor_t task_port;
  NDR_record_t ndr;
  exception_type_t exception_type;
  mach_msg_type_number_t code_count;
  mach_exception_data_type_t codes[2];
  uint8_t padding[128];
} ExceptionRequest;

typedef struct {
  mach_msg_header_t header;
  NDR_record_t ndr;
  kern_return_t return_code;
} ExceptionReply;
#pragma pack()

static void send_exception_reply(mach_msg_header_t* request,
                                 kern_return_t return_code) {
  ExceptionReply reply;

  memset(&reply, 0, sizeof(reply));

  reply.header.msgh_bits = request->msgh_bits & MACH_MSGH_BITS_REMOTE_MASK;
  reply.header.msgh_size = sizeof(reply);
  reply.header.msgh_remote_port = request->msgh_remote_port;
  reply.header.msgh_local_port = MACH_PORT_NULL;
  reply.header.msgh_id = request->msgh_id + 100;
  reply.ndr = NDR_record;
  reply.return_code = return_code;

  mach_msg(&reply.header, MACH_SEND_MSG, sizeof(reply), 0, MACH_PORT_NULL,
           MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

static kern_return_t receive_exception(mach_port_t port, int timeout_ms,
                                       ExceptionRequest* out_request) {
  memset(out_request, 0, sizeof(*out_request));
  out_request->header.msgh_local_port = port;
  out_request->header.msgh_size = sizeof(*out_request);

  return mach_msg(&out_request->header,
                  MACH_RCV_MSG | MACH_RCV_TIMEOUT |
                      MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
                      MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
                  0, sizeof(*out_request), port,
                  (mach_msg_timeout_t)timeout_ms, MACH_PORT_NULL);
}

#define MACH_EXCEPTION_RAISE_ID 2405

/* The target can read its own exception port (task_get_exception_ports) and
 * send anything to it, so a received message is only used if it is a
 * mach_exception_raise that the kernel sent: the right shape, and a sender
 * audit token with pid 0, which no user process has. Anything else must be
 * dropped with mach_msg_destroy and none of its fields used. */
static int exception_request_valid(const ExceptionRequest* request) {
  const mach_msg_header_t* header = &request->header;
  const mach_msg_audit_trailer_t* trailer;
  size_t fixed_size = offsetof(ExceptionRequest, codes);

  if ((header->msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0 ||
      header->msgh_id != MACH_EXCEPTION_RAISE_ID ||
      header->msgh_size < fixed_size) {
    return 0;
  }
  if (request->body.msgh_descriptor_count != 2 ||
      request->thread_port.type != MACH_MSG_PORT_DESCRIPTOR ||
      request->task_port.type != MACH_MSG_PORT_DESCRIPTOR ||
      request->thread_port.disposition != MACH_MSG_TYPE_PORT_SEND ||
      request->task_port.disposition != MACH_MSG_TYPE_PORT_SEND) {
    return 0;
  }
  if (request->code_count > 2 ||
      header->msgh_size !=
          fixed_size + request->code_count * sizeof(request->codes[0])) {
    return 0;
  }

  trailer = (const mach_msg_audit_trailer_t*)((const uint8_t*)request +
                                              round_msg(header->msgh_size));
  if ((const uint8_t*)trailer + sizeof(*trailer) >
          (const uint8_t*)request + sizeof(*request) ||
      trailer->msgh_trailer_size < sizeof(*trailer)) {
    return 0;
  }
  return audit_token_to_pid(trailer->msgh_audit) == 0;
}

/* Copies text that came from outside (a launchd label, a path read from the
 * target) for the log, so it can't start a new line. With ascii_only, bytes
 * above 0x7E become '?' too. */
static void copy_printable(char* out, size_t out_size, const char* in,
                           size_t in_len, int ascii_only) {
  size_t i;

  if (out_size == 0) return;
  for (i = 0; in != NULL && i < in_len && i < out_size - 1 && in[i] != '\0';
       i++) {
    unsigned char c = (unsigned char)in[i];
    out[i] = (c < 0x20 || c == 0x7F || (ascii_only && c > 0x7E)) ? '?'
                                                                 : (char)c;
  }
  out[i] = '\0';
}

static int handle_posix_spawn_bp(task_t task, pid_t xpcproxy_pid,
                                 const char* service_name,
                                 thread_act_t exc_thread,
                                 arm_thread_state64_t* thread_state,
                                 mach_msg_type_number_t state_count) {
  char app_path[PATH_MAX];
  char dyld_value[4096];
  char app_log[NAME_MAX + 1];
  const char* app_name;
  MatchResult match_result;
  mach_vm_address_t new_envp_address;
  kern_return_t kr;

  /* x1 contains the path of the binary xpcproxy is about to spawn */
  if (read_remote_string(task, thread_state->__x[1], app_path,
                         sizeof(app_path)) <= 0) {
    LOG("%s SKIP (spawn path unreadable)", service_name);
    return 0;
  }

  app_name = strrchr(app_path, '/');
  if (app_name != NULL) {
    app_name = app_name + 1;
  } else {
    app_name = app_path;
  }

  copy_printable(app_log, sizeof(app_log), app_name, strlen(app_name), 0);
  VLOG("caught pid=%d posix_spawn(%s)", (int)xpcproxy_pid, app_log);
  (void)service_name;

  match_result = check_match(app_name, app_path);

  if (match_result != MATCH_INJECT) {
    LOG("%s SKIP (%s)", service_name, match_skip_reason(match_result));
    return 0;
  }

  VLOG("match pid=%d %s", (int)xpcproxy_pid, app_log);

  /* x5 points to xpcproxy envp array */
  if (thread_state->__x[5] == 0) {
    LOG("%s SKIP (envp is NULL)", service_name);
    return -1;
  }

  VLOG("policy pid=%d evaluating dylib policies for bundle: %s",
       (int)xpcproxy_pid, service_name);

  {
    char identifier[200];
    char verified[256];
    int in_bundle = bundle_identifier_for_executable(app_path, identifier,
                                                     sizeof(identifier));
    if (in_bundle != 0) {
      /* In a bundle without a readable identifier: no allow override can
       * match, deny overrides and defaults still apply. */
      snprintf(verified, sizeof(verified), "application.%s.", identifier);
    }
    build_dyld_for_bundle(service_name, in_bundle != 0 ? verified : NULL,
                          dyld_value, sizeof(dyld_value));
  }

  if (dyld_value[strlen("DYLD_INSERT_LIBRARIES=")] == '\0') {
    LOG("%s SKIP (no dylibs allowed for this bundle)", service_name);
    return 0;
  }

  new_envp_address = make_envp_with_dyld(
      task, (mach_vm_address_t)thread_state->__x[5], dyld_value);

  if (new_envp_address == 0) {
    LOG("%s SKIP (make_envp_with_dyld failed)", service_name);
    return -1;
  }

  thread_state->__x[5] = (uint64_t)new_envp_address;

  kr = thread_set_state(exc_thread, ARM_THREAD_STATE64,
                        (thread_state_t)thread_state, state_count);
  if (kr != KERN_SUCCESS) {
    LOG("%s SKIP (thread_set_state: %s)", service_name, mach_error_string(kr));
    return -1;
  }

  LOG("%s(%s) MATCH (%d dylib(s) injected)", service_name, app_log,
      dylib_count_in_value(dyld_value));

  return 1;
}

typedef struct {
  pid_t pid;
  task_t task;
  mach_port_t exception_port;
  char service_name[256];
} XpcHandlerArgs;

/* A receive right with one send right under the same name, which
 * task_set_exception_ports copies into the target. */
static kern_return_t make_exception_port(mach_port_t* port) {
  kern_return_t kr;

  *port = MACH_PORT_NULL;
  kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, port);
  if (kr != KERN_SUCCESS) {
    return kr;
  }
  kr = mach_port_insert_right(mach_task_self(), *port, *port,
                              MACH_MSG_TYPE_MAKE_SEND);
  if (kr != KERN_SUCCESS) {
    mach_port_mod_refs(mach_task_self(), *port, MACH_PORT_RIGHT_RECEIVE, -1);
    *port = MACH_PORT_NULL;
  }
  return kr;
}

/* Drops both rights. Dropping only the receive right leaves the send right
 * behind as a dead name, one per intercepted launch. */
static void release_exception_port(mach_port_t port) {
  mach_port_destruct(mach_task_self(), port, -1, 0);
}

static void* xpc_handler_thread(void* raw_args) {
  XpcHandlerArgs* args;
  task_t task;
  pid_t pid;
  mach_port_t exc_port;
  char service_name[256];
  ExceptionRequest exc_request;
  arm_thread_state64_t thread_state;
  mach_msg_type_number_t state_count;
  uint64_t pc_raw;
  kern_return_t kr;
  char app_path[PATH_MAX];
  const char* app_name;

  args = (XpcHandlerArgs*)raw_args;
  task = args->task;
  pid = args->pid;
  exc_port = args->exception_port;

  strlcpy(service_name, args->service_name, sizeof(service_name));
  free(args);

  kr = receive_exception(exc_port, BP_WAIT_TIMEOUT_MS, &exc_request);

  if (kr == MACH_RCV_TIMED_OUT) {
    LOG("%s SKIP (timeout)", service_name);
    goto cleanup;
  }

  if (kr != MACH_MSG_SUCCESS) {
    LOG("%s SKIP (mach_msg error: %s)", service_name, mach_error_string(kr));
    goto cleanup;
  }

  if (!exception_request_valid(&exc_request)) {
    LOG("%s SKIP (exception message not from the kernel)", service_name);
    mach_msg_destroy(&exc_request.header);
    goto cleanup;
  }

  if (exc_request.exception_type != EXC_BREAKPOINT) {
    VLOG("ERROR pid=%d unexpected exception type %d", (int)pid,
         (int)exc_request.exception_type);
    send_exception_reply(&exc_request.header, KERN_SUCCESS);
    mach_port_deallocate(mach_task_self(), exc_request.thread_port.name);
    mach_port_deallocate(mach_task_self(), exc_request.task_port.name);
    goto cleanup;
  }

  state_count = ARM_THREAD_STATE64_COUNT;
  kr = thread_get_state(exc_request.thread_port.name, ARM_THREAD_STATE64,
                        (thread_state_t)&thread_state, &state_count);
  if (kr != KERN_SUCCESS) {
    LOG("ERROR thread_get_state: %s", mach_error_string(kr));
    send_exception_reply(&exc_request.header, KERN_SUCCESS);
    mach_port_deallocate(mach_task_self(), exc_request.thread_port.name);
    mach_port_deallocate(mach_task_self(), exc_request.task_port.name);
    goto cleanup;
  }

  mach_port_deallocate(mach_task_self(), exc_request.task_port.name);

  pc_raw = (uint64_t)ptrauth_strip((void*)thread_state.__opaque_pc,
                                   ptrauth_key_function_pointer);

  set_hw_bps(task, 0);

  if (pc_raw == g_posix_spawn_addr) {
    handle_posix_spawn_bp(task, pid, service_name, exc_request.thread_port.name,
                          &thread_state, state_count);

  } else if (pc_raw == g_execve_addr) {
    memset(app_path, 0, sizeof(app_path));
    read_remote_string(task, thread_state.__x[0], app_path, sizeof(app_path));
    app_name = strrchr(app_path, '/');
    app_name = (app_name != NULL) ? (app_name + 1) : app_path;
    LOG("%s SKIP (execve path)", service_name);

  } else {
    VLOG("ERROR pid=%d unexpected bp @0x%llx", (int)pid,
         (unsigned long long)pc_raw);
  }

  send_exception_reply(&exc_request.header, KERN_SUCCESS);
  mach_port_deallocate(mach_task_self(), exc_request.thread_port.name);

cleanup:
  set_hw_bps(task, 0);
  mach_port_deallocate(mach_task_self(), task);
  release_exception_port(exc_port);
  return NULL;
}

static int spawn_xpc_handler(pid_t pid, task_t task, mach_port_t exc_port,
                             const char* service_name, size_t service_len) {
  XpcHandlerArgs* args;
  pthread_t thread;
  pthread_attr_t attr;
  int create_result;

  args = calloc(1, sizeof(*args));
  if (args == NULL) {
    LOG("ERROR calloc XpcHandlerArgs failed");
    return -1;
  }

  args->pid = pid;
  args->task = task;
  args->exception_port = exc_port;

  if (service_name != NULL && service_len > 0) {
    size_t copy_len = service_len < sizeof(args->service_name) - 1
                          ? service_len
                          : sizeof(args->service_name) - 1;
    memcpy(args->service_name, service_name, copy_len);
    args->service_name[copy_len] = '\0';
  }

  size_t si;
  for (si = 0; si < sizeof(args->service_name) - 1 && args->service_name[si];
       si++) {
    unsigned char c = (unsigned char)args->service_name[si];
    if (c < 0x20 || c > 0x7E) {
      args->service_name[si] = '?';
    }
  }

  if (args->service_name[0] == '\0' || args->service_name[0] == '?') {
    strlcpy(args->service_name, "?", sizeof(args->service_name));
  }

  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

  create_result = pthread_create(&thread, &attr, xpc_handler_thread, args);

  pthread_attr_destroy(&attr);

  if (create_result != 0) {
    LOG("ERROR pthread_create: %d", create_result);
    free(args);
    return -1;
  }

  return 0;
}

static const char* g_daemon_patterns[] = {
  "mdworker",
  "mds_stores",
  "searchpartyd",
  "symptomsd",
  "symptomsd-diag",
  "corecaptured",
  "revisiond",
  "logd",
  "notifyd",
  "newsyslog",
  "nsurlsessiond",
  "rapportd",
  "cloudd",
  "bird",
  "appleevents",
  "itunescloudd",
  "cloudkeychainproxy",
  "cfprefsd",
  "usernoted",
  "contextstored",
  "knowledgegraphd",
  "coreduetd",
  "trustd",
  "AddressBook.",
  "audio.SandboxHelper",
  "filesystems.netfs",
  "distnoted",
  "BackgroundShortcutRunner",
  "intents-helper",
  "WebKit.GPU",
  "WebKit.Networking",
  "WebKit.WebContent",
  "MTLCompilerService",
  "security.authhost",
  "dock.external.extra",
  "IOUserBluetoothSerialDriver",
  "remotemanagement.",
  "extensionkitservice",
  "mdmclient.daemon",
  "siri.context.service",
  NULL };

static int service_name_is_system_daemon(const char* service_name,
                                         size_t service_len) {
  int i;

  for (i = 0; g_daemon_patterns[i] != NULL; i++) {
    if (strnstr(service_name, g_daemon_patterns[i], service_len) != NULL) {
      return 1;
    }
  }

  return 0;
}

static const char* g_ui_bundle_patterns[] = {
    "application.",    "com.apple.Finder",
    "com.apple.Dock.", "com.apple.controlcenter",
    "homebrew.",       NULL};

static int bundle_id_wants_injection(const char* bundle_id, size_t bundle_len) {
  int i;

  for (i = 0; i < g_config.allow_count; i++) {
    if (strnstr(bundle_id, g_config.allow_rules[i], bundle_len) != NULL) {
      return 1;
    }
  }

  for (i = 0; i < g_config.deny_count; i++) {
    if (strnstr(bundle_id, g_config.deny_rules[i], bundle_len) != NULL) {
      return 0;
    }
  }

  for (i = 0; g_ui_bundle_patterns[i] != NULL; i++) {
    if (strnstr(bundle_id, g_ui_bundle_patterns[i], bundle_len) != NULL) {
      return 1;
    }
  }

  return 0;
}

#define XPCPROXY_PATH "/usr/libexec/xpcproxy"

/* Only Apple's xpcproxy: a path that merely contains "xpcproxy" lets any
 * program have itself intercepted. */
static int exec_target_is_xpcproxy(const char* path, size_t path_len,
                                   int is_platform_binary) {
  return is_platform_binary && path != NULL &&
         path_len == strlen(XPCPROXY_PATH) &&
         memcmp(path, XPCPROXY_PATH, path_len) == 0;
}

static void handle_auth_exec(es_client_t* client, const es_message_t* message) {
  const es_process_t* current_process;
  const es_process_t* target_process;
  char service_log[256];
  pid_t pid;
  uint32_t arg_count;
  es_string_token_t service_token;

  memset(&service_token, 0, sizeof(service_token));
  task_t task;
  mach_port_t exc_port;
  kern_return_t kr;

  current_process = message->process;
  target_process = message->event.exec.target;

  if (current_process == NULL || target_process == NULL) {
    es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
    return;
  }

  /* only intercept xpcproxy */
  if (target_process->executable == NULL ||
      !exec_target_is_xpcproxy(target_process->executable->path.data,
                               target_process->executable->path.length,
                               target_process->is_platform_binary)) {
    es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
    return;
  }

  pid = audit_token_to_pid(current_process->audit_token);

  arg_count = es_exec_arg_count(&message->event.exec);
  if (arg_count < 2) {
    es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
    return;
  }

  service_token = es_exec_arg(&message->event.exec, 1);
  copy_printable(service_log, sizeof(service_log), service_token.data,
                 service_token.length, 1);
  VLOG("pid=%d %s evaluating bundleID", (int)pid, service_log);

  if (service_token.data != NULL && service_token.length > 0) {
    if (service_name_is_system_daemon(service_token.data,
                                      service_token.length)) {
      LOG("%s SKIP (system_daemon)", service_log);
      es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
      return;
    }

    if (!bundle_id_wants_injection(service_token.data, service_token.length)) {
      VLOG("%s SKIP (not UI bundle)", service_log);
      es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
      return;
    }
  } else {
    es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
    return;
  }

  VLOG("xpcproxy pid=%d intercepting", (int)pid);

  task = MACH_PORT_NULL;
  kr = task_for_pid(mach_task_self(), pid, &task);

  if (kr != KERN_SUCCESS) {
    LOG("%s SKIP (task_for_pid: %s)", "xpcproxy", mach_error_string(kr));
    es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
    return;
  }

  exc_port = MACH_PORT_NULL;

  kr = make_exception_port(&exc_port);
  if (kr != KERN_SUCCESS) {
    LOG("ERROR exception port: %s", mach_error_string(kr));
    mach_port_deallocate(mach_task_self(), task);
    es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
    return;
  }

  kr = task_set_exception_ports(task, EXC_MASK_BREAKPOINT, exc_port,
                                EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
                                ARM_THREAD_STATE64);
  if (kr != KERN_SUCCESS) {
    LOG("%s SKIP (task_set_exception_ports: %s)", service_log,
        mach_error_string(kr));
    mach_port_deallocate(mach_task_self(), task);
    release_exception_port(exc_port);
    es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
    return;
  }

  if (set_hw_bps(task, 1) != 0) {
    LOG("%s SKIP (set_hw_bps failed)", service_log);
    mach_port_deallocate(mach_task_self(), task);
    release_exception_port(exc_port);
    es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
    return;
  }

  VLOG("hw-bp pid=%d armed in ES callback", (int)pid);

  if (spawn_xpc_handler(pid, task, exc_port, service_token.data,
                        service_token.length) != 0) {
    set_hw_bps(task, 0);
    mach_port_deallocate(mach_task_self(), task);
    release_exception_port(exc_port);
  }

  es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
}

int main(int argc, char* argv[]) {
  const char* config_path;
  es_client_t* es_client;
  es_new_client_result_t client_result;
  es_event_type_t events[1];
  es_return_t subscribe_result;
  int i;

  const char* log_path = NULL;
  int verbose = 0;

  setvbuf(stdout, NULL, _IONBF, 0);

  config_set_defaults();
  config_path = NULL;

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
      config_path = argv[++i];

    } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
      log_path = argv[++i];

    } else if (strcmp(argv[i], "-v") == 0) {
      verbose = 1;

    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      fprintf(stderr,
              "usage: dynjectd [-c config] [-l logfile] [-v]\n\n"
              "  -c config    config file\n"
              "  -l logfile   log file (default: stderr)\n"
              "  -v           verbose output\n"
              "\n");
      return 0;
    }
  }

  if (config_path != NULL) {
    config_load(config_path);
  } else {
    config_load("/opt/dynject/etc/dynjectd.conf");
  }

  if (geteuid() != 0) {
    fprintf(stderr, "error: must run as root\n");
    return 1;
  }

  if (g_config.dylib_count == 0) {
    fprintf(stderr, "error: no dylibs configured\n");
    return 1;
  }

  if (find_intercept_addresses() != 0) {
    return 1;
  }

  log_init("dynjectd", log_path, verbose);

  LOG("starting");

  for (i = 0; i < g_config.dylib_count; i++) {
    LOG("dylib[%d] %s (%s, %d override(s))", i, g_config.dylibs[i].path,
        g_config.dylibs[i].default_allow ? "allow-all" : "deny-all",
        g_config.dylibs[i].override_count);
  }

  es_client = NULL;
  client_result = es_new_client(
      &es_client, ^(es_client_t* client, const es_message_t* message) {
        handle_auth_exec(client, message);
      });

  switch (client_result) {
    case ES_NEW_CLIENT_RESULT_SUCCESS:
      break;

    case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
      fprintf(stderr, "ES not permitted\n");
      return 1;

    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
      fprintf(stderr, "error: must run as root\n");
      return 1;

    default:
      fprintf(stderr, "error: es_new_client failed: %d\n", (int)client_result);
      return 1;
  }

  events[0] = ES_EVENT_TYPE_AUTH_EXEC;
  subscribe_result = es_subscribe(es_client, events, 1);

  if (subscribe_result != ES_RETURN_SUCCESS) {
    fprintf(stderr, "error: es_subscribe failed: %d\n", (int)subscribe_result);
    es_delete_client(es_client);
    return 1;
  }

  dispatch_main();

  es_unsubscribe_all(es_client);
  es_delete_client(es_client);

  return 0;
}
