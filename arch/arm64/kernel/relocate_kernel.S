/*
 * kexec for arm64
 *
 * Copyright (C) Linaro.
 * Copyright (C) Futurewei Technologies.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <asm/assembler.h>
#include <asm/kexec.h>
#include <asm/memory.h>
#include <asm/page.h>

/* The list entry flags. */
#define IND_DESTINATION_BIT 0
#define IND_INDIRECTION_BIT 1
#define IND_DONE_BIT        2
#define IND_SOURCE_BIT      3

#define TEGRA_PMC_BASE			0x7000E400

/*
 * relocate_new_kernel - Put a 2nd stage kernel image in place and boot it.
 *
 * The memory that the old kernel occupies may be overwritten when coping the
 * new image to its final location.  To assure that the relocate_new_kernel
 * routine which does that copy is not overwritten all code and data needed
 * by relocate_new_kernel must be between the symbols relocate_new_kernel and
 * relocate_new_kernel_end.  The machine_kexec() routine will copy
 * relocate_new_kernel to the kexec control_code_page, a special page which
 * has been set up to be preserved during the copy operation.
 */
.globl relocate_new_kernel
relocate_new_kernel:

	/* Setup the list loop variables. */
	ldr	x18, arm64_kexec_kimage_head	/* x18 = list entry */
	dcache_line_size x17, x0		/* x17 = dcache line size */
	mov	x16, xzr			/* x16 = segment start */
	mov	x15, xzr			/* x15 = entry ptr */
	mov	x14, xzr			/* x14 = copy dest */

	/* Check if the new image needs relocation. */
	cbz	x18, .Ldone
	tbnz	x18, IND_DONE_BIT, .Ldone

.Lloop:
	and	x13, x18, PAGE_MASK		/* x13 = addr */

	/* Test the entry flags. */
.Ltest_source:
	tbz	x18, IND_SOURCE_BIT, .Ltest_indirection

	mov x20, x14				/*  x20 = copy dest */
	mov x21, x13				/*  x21 = copy src */

	/* Invalidate dest page to PoC. */
	mov	x0, x20
	add	x19, x0, #PAGE_SIZE
	sub	x1, x17, #1
	bic	x0, x0, x1
1:	dc	ivac, x0
	add	x0, x0, x17
	cmp	x0, x19
	b.lo	1b
	dsb	sy

	/* Copy page. */
1:	ldp	x22, x23, [x21]
	ldp	x24, x25, [x21, #16]
	ldp	x26, x27, [x21, #32]
	ldp	x28, x29, [x21, #48]
	add	x21, x21, #64
	stnp	x22, x23, [x20]
	stnp	x24, x25, [x20, #16]
	stnp	x26, x27, [x20, #32]
	stnp	x28, x29, [x20, #48]
	add	x20, x20, #64
	tst	x21, #(PAGE_SIZE - 1)
	b.ne	1b

	/* dest += PAGE_SIZE */
	add	x14, x14, PAGE_SIZE
	b	.Lnext

.Ltest_indirection:
	tbz	x18, IND_INDIRECTION_BIT, .Ltest_destination

	/* ptr = addr */
	mov	x15, x13
	b	.Lnext

.Ltest_destination:
	tbz	x18, IND_DESTINATION_BIT, .Lnext

	mov	x16, x13

	/* dest = addr */
	mov	x14, x13

.Lnext:
	/* entry = *ptr++ */
	ldr	x18, [x15], #8

	/* while (!(entry & DONE)) */
	tbz	x18, IND_DONE_BIT, .Lloop

.Ldone:
	dsb	sy
	isb
	ic	ialluis
	dsb	sy
	isb

#ifdef CONFIG_KEXEC_HARDBOOT
	ldr	x0, kexec_hardboot
	cmp	x0, #0
	bne	hardboot
#endif

	/* Start new image. */
	ldr	x4, arm64_kexec_kimage_start
	mov	x0, xzr
	mov	x1, xzr
	mov	x2, xzr
	mov	x3, xzr
	br	x4

#ifdef CONFIG_KEXEC_HARDBOOT
hardboot:
	/* Stash boot arguments in hardboot page:
	 *  0: KEXEC_HB_PAGE_MAGIC
	 *  4: kexec_start_address
	 *  8: kexec_mach_type (doesn't apply, set to 0)
	 * 12: kexec_boot_atags
	 * 16: kexec_boot_atags_len
	 * 20: kexec_kernel_len */
	ldr	x0, =KEXEC_HB_PAGE_ADDR
	str	x1, [x0, #4]
	ldr	x1, #0
	str	x1, [x0, #8]
	ldr	x1, kexec_boot_atags
	str	x1, [x0, #12]
	ldr	x1, kexec_boot_atags_len
	str	x1, [x0, #16]
	ldr	x1, kexec_kernel_len
	str	x1, [x0, #20]
	ldr	x1, =KEXEC_HB_PAGE_MAGIC
	str	x1, [x0]

	ldr     x0, =TEGRA_PMC_BASE
	ldr	x1, [x0]
	orr	x1, x1, #0x10
	str	x1, [x0]
loop:	b	loop

	.ltorg
#endif

.align 3	/* To keep the 64-bit values below naturally aligned. */

/* The machine_kexec routines set these variables. */

/*
 * arm64_kexec_kimage_start - Copy of image->start, the entry point of the new
 * image.
 */
.globl arm64_kexec_kimage_start
arm64_kexec_kimage_start:
	.quad	0x0

#ifdef CONFIG_KEXEC_HARDBOOT
	.globl kexec_boot_atags
kexec_boot_atags:
	.quad	0x0

	.globl kexec_boot_atags_len
kexec_boot_atags_len:
	.quad	0x0

	.globl kexec_kernel_len
kexec_kernel_len:
	.quad	0x0

	.globl kexec_hardboot
kexec_hardboot:
	.quad	0x0
#endif

/*
 * arm64_kexec_kimage_head - Copy of image->head, the list of kimage entries.
 */
.globl arm64_kexec_kimage_head
arm64_kexec_kimage_head:
	.quad	0x0

.Lrelocate_new_kernel_end:

/*
 * relocate_new_kernel_size - Number of bytes to copy to the control_code_page.
 */
.globl relocate_new_kernel_size
relocate_new_kernel_size:
	.quad .Lrelocate_new_kernel_end - relocate_new_kernel

.org	KEXEC_CONTROL_PAGE_SIZE
