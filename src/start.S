/*-
 * Copyright (c) 2024 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <machine/asm.h>
#include <machine/pte.h>
#include <machine/cpuregs.h>
#include <machine/vmparam.h>
#include <machine/param.h>

#define	BIT(x)			(1ULL << (x))
#define MXSTATUS_THEADISAEE	BIT(22) /* T-HEAD ISA extensions enable */
#define MXSTATUS_CLINTEE	BIT(17) /* CLINT timer/software interrupt supervisor extension enable bit */
#define MXSTATUS_MM		BIT(15) /* misaligned access enable */

#define MHCR_IE			BIT(0)	/* icache enable */
#define MHCR_DE			BIT(1)	/* dcache enable */
#define MHCR_WA			BIT(2)	/* dcache write allocate */
#define MHCR_WB			BIT(3)	/* dcache write back */
#define MHCR_RS			BIT(4)	/* return stack enable */
#define MHCR_BPE		BIT(5)	/* branch prediction enable */
#define MHCR_BTB_C906		BIT(6)	/* branch target prediction enable */
#define MHCR_WBR		BIT(8)	/* write burst enable */
#define MHCR_BTB_E906		BIT(12) /* branch target prediction enable */

#define MHINT_DPLD		BIT(2)	/* dcache prefetch enable */
#define MHINT_AMR_PAGE		(0x0 << 3)
#define MHINT_AMR_LIMIT_3	(0x1 << 3)
#define MHINT_AMR_LIMIT_64	(0x2 << 3)
#define MHINT_AMR_LIMIT_128	(0x3 << 3)
#define MHINT_IPLD		BIT(8)	/* icache prefetch enable */
#define MHINT_IWPE		BIT(9)	/* icache way prediction enable */
#define MHINT_D_DIS_PREFETCH_2	(0x0 << 13)
#define MHINT_D_DIS_PREFETCH_4	(0x1 << 13)
#define MHINT_D_DIS_PREFETCH_8	(0x2 << 13)
#define MHINT_D_DIS_PREFETCH_16	(0x3 << 13)
#define MHINT_AEE		BIT(20) /* accurate exception enable */

	.globl	kernbase
	.set	kernbase, KERNBASE

	.globl	dmapbase
	.set	dmapbase, DMAPBASE

	.text

ASM_ENTRY(_start)
	fence.i
	fence

	/* hart id */
	li	a0, 0

	/* Allow dcache instr. */
	li t0, (MXSTATUS_THEADISAEE | MXSTATUS_MM | MXSTATUS_CLINTEE)
	csrs mxstatus, t0

	li t0, (MHCR_BTB_C906 | MHCR_BPE | MHCR_RS | MHCR_WB | MHCR_WA)
	csrs mhcr, t0

	li t0, (MHINT_IWPE | MHINT_IPLD | MHINT_IPLD)
	csrs mhint, t0

	li t1, 0x30013
	csrs mcor, t1

	/* ICache enable */
	li t0, MHCR_IE
	csrs mhcr, t0

	/* DCache enable */
	li t0, MHCR_DE
	csrs mhcr, t0

#ifdef __riscv_atomic
	/* Pick a hart to run the boot process. */
	li	t1, 1
	lla	t0, cpu_lottery
	amoadd.w t0, t1, 0(t0)

	/*
	 * We must jump to mpentry because the offset is too large to fit
	 * in a 12-bit branch immediate.
	 */
	beqz	t0, 1f
	j	mpentry
1:
#endif

#ifdef MDX_RISCV_SUPERVISOR_MODE
	/* Page tables setup */
pagetables:
	/*
	 * Make a direct mapping:
	 * 0xffffffd000000000 (va) -> 0 (pa),
	 * using 4 x L1 superpages (1GiB each)
	 */

	/* Physical base address. */
	li	s9, 0

	/* Level 1 superpages (1GiB each) */
	lla	s1, pagetable_l1

	li	s2, DMAPBASE
	srli	s2, s2, L1_SHIFT
	andi	s2, s2, 0x1ff

	li	t0, PTE_SIZE
	mul	s2, s2, t0

	li	t0, (PTE_KERN | PTE_X)
	li	t1, 0			/* Start ppn */
	li	t2, 4			/* Build 4 entries */
	add	t3, t1, t2		/* ppn limit */
1:
	slli	t2, t1, PTE_PPN2_S	/* << PTE_PPN2_S */
	or	t4, t0, t2
	add	s3, s1, s2
	sd	t4, 0(s3)		/* Store PTE entry to position */

	addi	s2, s2, PTE_SIZE
	addi	t1, t1, 1
	bltu	t1, t3, 1b

	/* Page tables END */

	/* Setup supervisor trap vector */
2:
	lla	t0, va
	sub	t0, t0, s9
	li	t1, DMAPBASE
	add	t0, t0, t1
	csrw	stvec, t0

	/* Set page tables base register */
	lla	s2, pagetable_l1
	srli	s2, s2, PAGE_SHIFT
	li	t0, SATP_MODE_SV39
	or	s2, s2, t0
	sfence.vma
	csrw	satp, s2

	.align 2
va:
#endif /* !MDX_RISCV_SUPERVISOR_MODE */

	lla	t0, cpu_exception_handler
	csrw	REG_TVEC, t0

	/* Clear BSS. */
	lla	t0, _sbss	# start of BSS section
	lla	t1, _ebss	# end of BSS section
1:
	beq	t0, t1, 2f
	li	t2, 0
	sb	t2, 0(t0)
	addi	t0, t0, 1
	j	1b
2:

	/* Load our stack pointer. */
	lla	t0, idle_thread_stack
	li	t1, MDX_THREAD_STACK_SIZE
	mul	t2, t1, a0	# Offset to start of our stack
	add	t2, t2, t0	# Start of our stack
	add	sp, t2, t1	# End of our stack

	fence

	mv	s0, a0
	mv	s1, a1

#ifdef MDX_OF
	mv	a0, a1
#ifdef MDX_RISCV_SUPERVISOR_MODE
	li	t0, DMAPBASE
	add	a0, a0, t0		/* Map to VA space. */
#endif
	lla	t0, mdx_of_install_dtbp
	jalr	t0
#endif

	mv	a0, s0
	j	md_init

	/* NOT REACHED */

ASM_ENTRY(mpentry)
#ifdef MDX_SCHED_SMP
	lla	t0, __riscv_boot_ap
	add	t0, t0, a0

1:
	lb	t1, 0(t0)
	beqz	t1, 1b

#ifdef MDX_RISCV_SUPERVISOR_MODE
	/* Setup supervisor trap vector */
	lla	t0, mpva
	sub	t0, t0, s9
	li	t1, DMAPBASE
	add	t0, t0, t1
	csrw	stvec, t0

	/* Set page tables base register */
	lla	s2, pagetable_l1
	srli	s2, s2, PAGE_SHIFT
	li	t0, SATP_MODE_SV39
	or	s2, s2, t0
	sfence.vma
	csrw	satp, s2

	.align 2
mpva:
#endif

	lla	t0, idle_thread_stack
	li	t1, MDX_THREAD_STACK_SIZE
	mul	t2, t1, a0	# Offset to start of our stack
	add	t2, t2, t0	# Start of our stack
	add	sp, t2, t1	# End of our stack

	lla	t0, cpu_exception_handler
	csrw	REG_TVEC, t0

	call	md_init_secondary
#else
1:
	j	1b
#endif
END(mpentry)

get_physmem:
	lla	t0, virt_map	/* physical address of virt_map */
	REG_L	t1, 0(t0)	/* virtual address of virt_map */
	sub	t1, t1, t0	/* calculate phys->virt delta */
	li	t2, KERNBASE
	sub	s9, t2, t2	/* s9 = physmem base */
	ret

	.align 12
pagetable_l1:
	.space	PAGE_SIZE

	.align 3
virt_map:
	.quad	virt_map
cpu_lottery:
	.space 4
