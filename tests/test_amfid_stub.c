#define main dynject_loader_main
#include "../dynject_loader.c"
#undef main

#include <assert.h>
#include <sys/mman.h>

static long g_original_result;
static int g_original_calls;

__attribute__((noinline)) static long original_validation(void) {
  g_original_calls++;
  return g_original_result;
}

typedef long (*Validator)(void);

/* Builds the real code page next to a data page, the way install_hook lays
 * them out in amfid, and returns the stub as a callable function. The
 * "validator" is four NOPs followed by original_validation. */
static Validator make_stub(uint64_t deadline, uint32_t** flag) {
  static const uint32_t nops[4] = {0xD503201FU, 0xD503201FU, 0xD503201FU,
                                   0xD503201FU};
  uint8_t* pages = mmap(NULL, 2 * PAGE_SZ, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON, -1, 0);
  uint64_t continue_addr = (uint64_t)ptrauth_strip(
      (void*)original_validation, ptrauth_key_function_pointer);

  assert(pages != MAP_FAILED);
  assert(build_code_page(pages, (const uint8_t*)nops, continue_addr,
                         (uint64_t)(pages + TRAMPOLINE_OFFSET), deadline,
                         (uint64_t)(pages + PAGE_SZ)) == 0);
  __builtin___clear_cache((char*)pages, (char*)pages + PAGE_SZ);
  assert(mprotect(pages, PAGE_SZ, PROT_READ | PROT_EXEC) == 0);
  *flag = (uint32_t*)(void*)(pages + PAGE_SZ);
  return (Validator)ptrauth_sign_unauthenticated(
      (void*)(pages + STUB_OFFSET), ptrauth_key_function_pointer, 0);
}

static uint64_t in_ms(int ms) {
  return counter_ticks() + counter_frequency() / 1000 * (uint64_t)ms;
}

int main(void) {
  uint32_t* flag;
  Validator validate;

  /* One "no" becomes "yes", then never again. */
  validate = make_stub(in_ms(60000), &flag);
  g_original_result = 0;
  g_original_calls = 0;
  assert(*flag == 0);
  assert(validate() == 1);
  assert(*flag == 1);
  assert(validate() == 0);
  assert(validate() == 0);
  assert(g_original_calls == 3); /* the real validation always runs */

  /* A "yes" passes through and doesn't use the override. */
  validate = make_stub(in_ms(60000), &flag);
  g_original_result = 1;
  assert(validate() == 1);
  assert(validate() == 1);
  assert(*flag == 0);
  /* The result is a BOOL: only its low byte counts. */
  g_original_result = 0x100;
  assert(validate() == 1);
  assert(*flag == 1);
  g_original_result = 0;
  assert(validate() == 0);

  /* Past the deadline nothing is overridden, used or not. */
  validate = make_stub(in_ms(50), &flag);
  g_original_result = 0;
  usleep(80 * 1000);
  assert(validate() == 0);
  assert(*flag == 0);

  /* What install_hook finds at the validator's entry. */
  {
    uint8_t original[HOOK_SIZE], hooked[HOOK_SIZE], other[HOOK_SIZE];
    uint32_t ldr = INSN_LDR_X17_8, br = INSN_BR_X17;
    uint64_t target = 0x1234;
    for (int i = 0; i < HOOK_SIZE; i++) original[i] = (uint8_t)(i + 1);
    memcpy(hooked, &ldr, 4);
    memcpy(hooked + 4, &br, 4);
    memcpy(hooked + 8, &target, 8);
    memcpy(other, original, HOOK_SIZE);
    other[5] ^= 1;
    assert(entry_state(original, original) == ENTRY_ORIGINAL);
    assert(entry_state(hooked, original) == ENTRY_HOOKED);
    assert(entry_state(other, original) == ENTRY_UNKNOWN);
  }

  /* What may be copied into the trampoline. */
  {
    /* the validator's entry on macOS 27.2: pacibsp; sub sp; stp; stp */
    static const uint8_t real[HOOK_SIZE] = {0x7f, 0x23, 0x03, 0xd5, 0xff, 0x43, 0x03, 0xd1,
                                            0xfc, 0x6f, 0x07, 0xa9, 0xfa, 0x67, 0x08, 0xa9};
    static const uint32_t cannot[] = {
        0x14000010U, /* b */        0x94000010U, /* bl */      0x54000040U, /* b.eq */
        0xB4000040U, /* cbz */      0x35000040U, /* cbnz */    0x36000040U, /* tbz */
        0x10000040U, /* adr */      0x90000000U, /* adrp */    0x58000051U, /* ldr x17, literal */
        0xD65F03C0U, /* ret */      0xD61F0220U, /* br x17 */  0xD63F0220U, /* blr x17 */
    };
    assert(entry_can_move(real));
    for (size_t i = 0; i < sizeof(cannot) / sizeof(cannot[0]); i++) {
      uint8_t entry[HOOK_SIZE];
      memcpy(entry, real, HOOK_SIZE);
      memcpy(entry + 8, &cannot[i], 4);
      assert(!insn_can_move(cannot[i]));
      assert(!entry_can_move(entry));
    }
    assert(insn_can_move(0xD503201FU)); /* nop */
    assert(insn_can_move(0x910003FDU)); /* mov x29, sp */
    /* the task has no thread in a range nothing runs in; this one is in main */
    assert(task_has_pc_in(mach_task_self(), 0x1000, 0x1010) == 0);
  }

  puts("amfid stub: one override, self-expiring; entry states; movable entry passed");
  return 0;
}
