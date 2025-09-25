// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/arch/alpha/mm/fault.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 */

#include <linux/sched/signal.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/io.h>

#define __EXTERN_INLINE inline
#include <asm/mmu_context.h>
#include <asm/tlbflush.h>
#undef  __EXTERN_INLINE

#include <linux/signal.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/extable.h>
#include <linux/uaccess.h>
#include <linux/perf_event.h>

extern void die_if_kernel(char *,struct pt_regs *,long, unsigned long *);


/*
 * Force a new ASN for a task.
 */

#ifndef CONFIG_SMP
unsigned long last_asn = ASN_FIRST_VERSION;
#endif

void
__load_new_mm_context(struct mm_struct *next_mm)
{
	unsigned long mmc;
	struct pcb_struct *pcb;

	mmc = __get_new_mm_context(next_mm, smp_processor_id());
	next_mm->context[smp_processor_id()] = mmc;

	pcb = &current_thread_info()->pcb;
	pcb->asn = mmc & HARDWARE_ASN_MASK;
	pcb->ptbr = ((unsigned long) next_mm->pgd - IDENT_ADDR) >> PAGE_SHIFT;

	__reload_thread(pcb);
}


/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to handle_mm_fault().
 *
 * mmcsr:
 *	0 = translation not valid
 *	1 = access violation
 *	2 = fault-on-read
 *	3 = fault-on-execute
 *	4 = fault-on-write
 *
 * cause:
 *	-1 = instruction fetch
 *	0 = load
 *	1 = store
 *
 * Registers $9 through $15 are saved in a block just prior to `regs' and
 * are saved and restored around the call to allow exception code to
 * modify them.
 */

/* Macro for exception fixup code to access integer registers.  */
#define dpf_reg(r)							\
	(((unsigned long *)regs)[(r) <= 8 ? (r) : (r) <= 15 ? (r)-17 :	\
				 (r) <= 18 ? (r)+11 : (r)-10])

// asmlinkage: 指示编译器从堆栈传递参数，用于处理内核/用户空间切换。
// address: 触发缺页的虚拟地址。
// mmcsr: Alpha架构的机器状态寄存器值。
// cause: 缺页原因（0=读缺页, 1=写缺页, 负值=执行缺页）。
// regs: 指向内核保存的寄存器状态的指针。
asmlinkage void
do_page_fault(unsigned long address, unsigned long mmcsr,
	      long cause, struct pt_regs *regs)
{
	struct vm_area_struct * vma;	// vma: 将保存地址对应的虚拟内存区域。
	struct mm_struct *mm = current->mm;	// mm: 当前进程的内存描述符。
	const struct exception_table_entry *fixup;	// fixup: 用于内核异常修复的指针。
	int si_code = SEGV_MAPERR;  // si_code: 发送信号的错误代码。
	vm_fault_t fault;	// fault: 处理缺页后的返回状态。
	unsigned int flags = FAULT_FLAG_DEFAULT;  // flags: 控制缺页处理行为的标志。

	/* As of EV6, a load into $31/$f31 is a prefetch, and never faults
	   (or is suppressed by the PALcode).  Support that for older CPUs
	   by ignoring such an instruction.  */
	if (cause == 0) {
		unsigned int insn;
		__get_user(insn, (unsigned int __user *)regs->pc);
		if ((insn >> 21 & 0x1f) == 0x1f &&
		    /* ldq ldl ldt lds ldg ldf ldwu ldbu */
		    (1ul << (insn >> 26) & 0x30f00001400ul)) {
			regs->pc += 4;
			return;
		}
	}

	// 如果当前是内核线程（mm = NULL）或处在中断上下文，跳转至 no_context（内核错误处理）。
	if (!mm || faulthandler_disabled())
		goto no_context;

#ifdef CONFIG_ALPHA_LARGE_VMALLOC
	if (address >= TASK_SIZE)
		goto vmalloc_fault;
#endif
	if (user_mode(regs))
		flags |= FAULT_FLAG_USER;  // 设置用户模式标志
	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);  // 记录缺页事件
retry:
	vma = lock_mm_and_find_vma(mm, address, regs);
	if (!vma)
		goto bad_area_nosemaphore;

	/* Ok, we have a good vm_area for this memory access, so
	   we can handle it.  */
	si_code = SEGV_ACCERR;
	if (cause < 0) {
		if (!(vma->vm_flags & VM_EXEC))
			goto bad_area;
	} else if (!cause) {
		/* Allow reads even for write-only mappings */
		if (!(vma->vm_flags & (VM_READ | VM_WRITE)))
			goto bad_area;
	} else {
		if (!(vma->vm_flags & VM_WRITE))
			goto bad_area;
		flags |= FAULT_FLAG_WRITE;
	}

	/* If for any reason at all we couldn't handle the fault,
	   make sure we exit gracefully rather than endlessly redo
	   the fault.  */
	fault = handle_mm_fault(vma, address, flags, regs);

	if (fault_signal_pending(fault, regs)) {
		if (!user_mode(regs))
			goto no_context;
		return;
	}

	/* The fault is fully completed (including releasing mmap lock) */
	if (fault & VM_FAULT_COMPLETED)
		return;

	if (unlikely(fault & VM_FAULT_ERROR)) {
		if (fault & VM_FAULT_OOM)
			goto out_of_memory;
		else if (fault & VM_FAULT_SIGSEGV)
			goto bad_area;
		else if (fault & VM_FAULT_SIGBUS)
			goto do_sigbus;
		BUG();
	}

	if (fault & VM_FAULT_RETRY) {
		flags |= FAULT_FLAG_TRIED;

		/* No need to mmap_read_unlock(mm) as we would
		 * have already released it in __lock_page_or_retry
		 * in mm/filemap.c.
		 */

		goto retry;
	}

	mmap_read_unlock(mm);

	return;

	/* Something tried to access memory that isn't in our memory map.
	   Fix it, but check if it's kernel or user first.  */
 bad_area:
	mmap_read_unlock(mm);

 bad_area_nosemaphore:
	if (user_mode(regs))
		goto do_sigsegv;

 no_context:
	/* Are we prepared to handle this fault as an exception?  */
	if ((fixup = search_exception_tables(regs->pc)) != 0) {
		unsigned long newpc;
		newpc = fixup_exception(dpf_reg, fixup, regs->pc);
		regs->pc = newpc;
		return;
	}

	/* Oops. The kernel tried to access some bad page. We'll have to
	   terminate things with extreme prejudice.  */
	printk(KERN_ALERT "Unable to handle kernel paging request at "
	       "virtual address %016lx\n", address);
	die_if_kernel("Oops", regs, cause, (unsigned long*)regs - 16);
	make_task_dead(SIGKILL);

	/* We ran out of memory, or some other thing happened to us that
	   made us unable to handle the page fault gracefully.  */
 out_of_memory:
	mmap_read_unlock(mm);
	if (!user_mode(regs))
		goto no_context;
	pagefault_out_of_memory();
	return;

 do_sigbus:
	mmap_read_unlock(mm);
	/* Send a sigbus, regardless of whether we were in kernel
	   or user mode.  */
	force_sig_fault(SIGBUS, BUS_ADRERR, (void __user *) address);
	if (!user_mode(regs))
		goto no_context;
	return;

 do_sigsegv:
	force_sig_fault(SIGSEGV, si_code, (void __user *) address);
	return;

#ifdef CONFIG_ALPHA_LARGE_VMALLOC
 vmalloc_fault:
	if (user_mode(regs))
		goto do_sigsegv;
	else {
		/* Synchronize this task's top level page-table
		   with the "reference" page table from init.  */
		long index = pgd_index(address);
		pgd_t *pgd, *pgd_k;

		pgd = current->active_mm->pgd + index;
		pgd_k = swapper_pg_dir + index;
		if (!pgd_present(*pgd) && pgd_present(*pgd_k)) {
			pgd_val(*pgd) = pgd_val(*pgd_k);
			return;
		}
		goto no_context;
	}
#endif
}
