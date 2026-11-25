/* The stub the loader copies into amfid in place of the validator's entry.
 * The loader fills the three 64-bit literals at the end.
 *
 * The original validation always runs. Its "no" is turned into "yes" at most
 * once, and only before the counter deadline, so the override ends by itself:
 * after the first use, or after the deadline if the loader died before it
 * could take the entry hook out again. */
.text
.globl _amfid_stub_template
.globl _amfid_stub_template_end
.p2align 3
_amfid_stub_template:
    stp x29, x30, [sp, #-16]!
    ldr x17, 1f
    blr x17                     /* the original validator, via the trampoline */
    tst w0, #0xff
    b.ne 3f                     /* it said yes: nothing to override */
    mrs x16, CNTVCT_EL0
    ldr x17, 2f
    cmp x16, x17
    b.hs 3f                     /* past the deadline */
    ldr x17, 4f
    mov w16, #1
    swpal w16, w15, [x17]       /* used = 1, old value in w15 */
    cbnz w15, 3f                /* the one override was already used */
    mov x0, #1
3:  ldp x29, x30, [sp], #16
    ret
1:  .quad 0                     /* 0x40: trampoline address */
2:  .quad 0                     /* 0x48: counter deadline */
4:  .quad 0                     /* 0x50: address of the 32-bit "used" flag */
_amfid_stub_template_end:
