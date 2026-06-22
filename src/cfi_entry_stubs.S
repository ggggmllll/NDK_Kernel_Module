/*
 * cfi_entry_stubs.S — Shadow-CFI infrastructure for init_module / cleanup_module
 *
 * Provides:
 *   .text.__cfi_check       — 64-bit hash validator (kernel calls via
 *                              __cfi_slowpath → module->cfi_check)
 *   .text.__cfi_check_fail  — failure handler with suppression gate
 *   .text..L.cfi.jumptable  — {hash, b .cfi_stub} → cleanup_module symbol
 *   .text..L.cfi.jumptable.1 — {hash, b .cfi_stub} → init_module symbol
 *   .text.cleanup_module.cfi — stub → b cleanup_module_impl
 *   .text.init_module.cfi    — stub → b init_module_impl
 *
 * 64-bit hashes match clang 18 -fsanitize=cfi output:
 *   cleanup_module: 0x02b3a43e29242445  (void (*)(void))
 *   init_module:    0x7e04a0fb7ad8bcd5  (int (*)(void))
 *
 * __cfi_check accepts EITHER hash for EITHER target. This handles the case
 * where the kernel (clang 12) passes a hash that doesn't match the clang-18
 * type→hash mapping for a given function.
 *
 * /proc/kpm_loader replaced with custom syscall (loader.c Section 10).
 * No kCFI stubs needed — ARM64 syscall dispatch uses assembly blr x16
 * which has no inline kCFI check.
 */

	.section .text.__cfi_check,"ax",@progbits
	.globl __cfi_check
	.type __cfi_check, %function
__cfi_check:
	/* Check hash #1: void (*)(void) = 0x02b3a43e29242445 */
	mov	x8, #0x2445
	movk	x8, #0x2924, lsl #16
	movk	x8, #0xa43e, lsl #32
	movk	x8, #0x02b3, lsl #48
	cmp	x0, x8
	b.eq	4f

	/* Check hash #2: int (*)(void) = 0x7e04a0fb7ad8bcd5 */
	mov	x8, #0xbcd5
	movk	x8, #0x7ad8, lsl #16
	movk	x8, #0xa0fb, lsl #32
	movk	x8, #0x7e04, lsl #48
	cmp	x0, x8
	b.ne	3f

4:	/* Hash matched. Accept x1 == init_module or x1 == cleanup_module.
	 * Also check the _impl variants (the actual code, not the CFI stubs). */
	adrp	x8, init_module
	add	x8, x8, #:lo12:init_module
	cmp	x1, x8
	b.eq	2f

	adrp	x8, cleanup_module
	add	x8, x8, #:lo12:cleanup_module
	cmp	x1, x8
	b.eq	2f

	adrp	x8, init_module_impl
	add	x8, x8, #:lo12:init_module_impl
	cmp	x1, x8
	b.eq	2f

	adrp	x8, cleanup_module_impl
	add	x8, x8, #:lo12:cleanup_module_impl
	cmp	x1, x8
	b.ne	3f

2:	ret

3:	/* Hash not found or target mismatch — tail-call __cfi_check_fail.
	 * Move diag (x2) to x0 as __cfi_check_fail expects. */
	mov	x0, x2
	b	__cfi_check_fail

	.section .text.__cfi_check_fail,"ax",@progbits
	.globl __cfi_check_fail
	.type __cfi_check_fail, %function
__cfi_check_fail:
	/* Suppression gate: if diag == NULL or *(u8*)diag >= 5, return silently.
	 * diag==NULL means the kernel had no failure context to provide. */
	cbz	x0, 2f
	ldrb	w8, [x0]
	cmp	w8, #0x5
	b.cc	1f
2:	ret
1:	brk	#0x5502

	/* ── .cfi stubs (tail-call the real implementations) ─────────────────── */

	.section .text.cleanup_module.cfi,"ax",@progbits
	.globl "cleanup_module.cfi"
	.type "cleanup_module.cfi", %function
"cleanup_module.cfi":
	b	cleanup_module_impl

	.section .text..L.cfi.jumptable,"ax",@progbits
	.word 0xa540670c
	.globl cleanup_module
	.type cleanup_module, %function
cleanup_module:
	b	"cleanup_module.cfi"

	.section .text.init_module.cfi,"ax",@progbits
	.globl "init_module.cfi"
	.type "init_module.cfi", %function
"init_module.cfi":
	b	init_module_impl

	.section .text..L.cfi.jumptable.1,"ax",@progbits
	.word 0x36b1c5a6
	.globl init_module
	.type init_module, %function
init_module:
	b	"init_module.cfi"

/* /proc/kpm_loader replaced with custom syscall. No kCFI stubs needed. */
