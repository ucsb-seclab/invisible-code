/*
 *	linux/arch/arm/mm/fault.c
 *
 *	Copyright (C) 1995	Linus Torvalds
 *	Modifications for ARM processor (c) 1995-2004 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/signal.h>
#include <linux/mm.h>
#include <linux/hardirq.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/page-flags.h>
#include <linux/sched.h>
#include <linux/highmem.h>
#include <linux/perf_event.h>
#include <drm_code/drm_execution_forwarding.h>

#include <asm/exception.h>
#include <asm/pgtable.h>
#include <asm/system_misc.h>
#include <asm/system_info.h>
#include <asm/tlbflush.h>
#include <drm_code/abort_helpers.h>

#include <linux/arm-smccc.h>
#include "fault.h"
#include "drm_tee_private.h"
#include <linux/tee_drv.h>
#include <linux/sched.h>

#include <linux/delay.h>

#define OPTEE_MSG_FORWARD_EXECUTION 123

struct thread_svc_regs {
	uint32_t spsr;
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r4;
	uint32_t r5;
	uint32_t r6;
	uint32_t r7;
	uint32_t lr;
};

struct thread_abort_regs {
	uint32_t usr_sp;
	uint32_t usr_lr;
	uint32_t pad;
	uint32_t spsr;
	uint32_t elr;
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r4;
	uint32_t r5;
	uint32_t r6;
	uint32_t r7;
	uint32_t r8;
	uint32_t r9;
	uint32_t r10;
	uint32_t r11;
	uint32_t ip;
};

#ifdef CONFIG_MMU

#ifdef CONFIG_KPROBES
static inline int notify_page_fault(struct pt_regs *regs, unsigned int fsr)
{
	int ret = 0;

	if (!user_mode(regs)) {
		/* kprobe_running() needs smp_processor_id() */
		preempt_disable();
		if (kprobe_running() && kprobe_fault_handler(regs, fsr))
			ret = 1;
		preempt_enable();
	}

	return ret;
}
#else
static inline int notify_page_fault(struct pt_regs *regs, unsigned int fsr)
{
	return 0;
}
#endif

/*
 * This is useful to dump out the page tables associated with
 * 'addr' in mm 'mm'.
 */
void show_pte(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;

	if (!mm)
		mm = &init_mm;

	pr_alert("pgd = %p\n", mm->pgd);
	pgd = pgd_offset(mm, addr);
	pr_alert("[%08lx] *pgd=%08llx",
		 addr, (long long)pgd_val(*pgd));

	do {
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;

		if (pgd_none(*pgd))
			break;

		if (pgd_bad(*pgd)) {
			pr_cont("(bad)");
			break;
		}

		pud = pud_offset(pgd, addr);
		if (PTRS_PER_PUD != 1)
			pr_cont(", *pud=%08llx", (long long)pud_val(*pud));

		if (pud_none(*pud))
			break;

		if (pud_bad(*pud)) {
			pr_cont("(bad)");
			break;
		}

		pmd = pmd_offset(pud, addr);
		if (PTRS_PER_PMD != 1)
			pr_cont(", *pmd=%08llx", (long long)pmd_val(*pmd));

		if (pmd_none(*pmd))
			break;

		if (pmd_bad(*pmd)) {
			pr_cont("(bad)");
			break;
		}

		/* We must not map this if we have highmem enabled */
		if (PageHighMem(pfn_to_page(pmd_val(*pmd) >> PAGE_SHIFT)))
			break;

		pte = pte_offset_map(pmd, addr);
		pr_cont(", *pte=%08llx", (long long)pte_val(*pte));
#ifndef CONFIG_ARM_LPAE
		pr_cont(", *ppte=%08llx",
			   (long long)pte_val(pte[PTE_HWTABLE_PTRS]));
#endif
		pte_unmap(pte);
	} while(0);

	pr_cont("\n");
}
#else					/* CONFIG_MMU */
void show_pte(struct mm_struct *mm, unsigned long addr)
{ }
#endif					/* CONFIG_MMU */

/*
 * Oops.  The kernel tried to access some page that wasn't present.
 */
static void
__do_kernel_fault(struct mm_struct *mm, unsigned long addr, unsigned int fsr,
		  struct pt_regs *regs)
{
	/*
	 * Are we prepared to handle this kernel fault?
	 */
	if (fixup_exception(regs))
		return;

	/*
	 * No handler, we'll have to terminate things with extreme prejudice.
	 */
	bust_spinlocks(1);
	pr_alert("Unable to handle kernel %s at virtual address %08lx\n",
		 (addr < PAGE_SIZE) ? "NULL pointer dereference" :
		 "paging request", addr);

	show_pte(mm, addr);
	die("Oops", regs, fsr);
	bust_spinlocks(0);
	do_exit(SIGKILL);
}

/*
 * Something tried to access memory that isn't in our memory map..
 * User mode accesses just cause a SIGSEGV
 */
static void
__do_user_fault(struct task_struct *tsk, unsigned long addr,
		unsigned int fsr, unsigned int sig, int code,
		struct pt_regs *regs)
{
	struct siginfo si;

#ifdef CONFIG_DEBUG_USER
	if (((user_debug & UDBG_SEGV) && (sig == SIGSEGV)) ||
		((user_debug & UDBG_BUS)  && (sig == SIGBUS))) {
		printk(KERN_DEBUG "%s: unhandled page fault (%d) at 0x%08lx, code 0x%03x\n",
			   tsk->comm, sig, addr, fsr);
		show_pte(tsk->mm, addr);
		show_regs(regs);
	}
#endif

	tsk->thread.address = addr;
	tsk->thread.error_code = fsr;
	tsk->thread.trap_no = 14;
	si.si_signo = sig;
	si.si_errno = 0;
	si.si_code = code;
	si.si_addr = (void __user *)addr;
	force_sig_info(sig, &si, tsk);
}

void do_bad_area(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	struct task_struct *tsk = current;
	struct mm_struct *mm = tsk->active_mm;

	/*
	 * If we are in kernel mode at this point, we
	 * have no context to handle this fault with.
	 */
	if (user_mode(regs))
		__do_user_fault(tsk, addr, fsr, SIGSEGV, SEGV_MAPERR, regs);
	else
		__do_kernel_fault(mm, addr, fsr, regs);
}

#ifdef CONFIG_MMU
#define VM_FAULT_BADMAP		0x010000
#define VM_FAULT_BADACCESS	0x020000

/*
 * Check that the permissions on the VMA allow for the fault which occurred.
 * If we encountered a write fault, we must have write permission, otherwise
 * we allow any permission.
 */
static inline bool access_error(unsigned int fsr, struct vm_area_struct *vma)
{
	unsigned int mask = VM_READ | VM_WRITE | VM_EXEC;

	if (fsr & FSR_WRITE)
		mask = VM_WRITE;
	if (fsr & FSR_LNX_PF)
		mask = VM_EXEC;

	return vma->vm_flags & mask ? false : true;
}

static int __kprobes
__do_page_fault(struct mm_struct *mm, unsigned long addr, unsigned int fsr,
		unsigned int flags, struct task_struct *tsk)
{
	struct vm_area_struct *vma;
	int fault;

	vma = find_vma(mm, addr);
	fault = VM_FAULT_BADMAP;
	if (unlikely(!vma))
		goto out;
	if (unlikely(vma->vm_start > addr))
		goto check_stack;

	/*
	 * Ok, we have a good vm_area for this
	 * memory access, so we can handle it.
	 */
 good_area:
	if (access_error(fsr, vma)) {
		fault = VM_FAULT_BADACCESS;
		goto out;
	}

	return handle_mm_fault(mm, vma, addr & PAGE_MASK, flags);

 check_stack:
	/* Don't allow expansion below FIRST_USER_ADDRESS */
	if (vma->vm_flags & VM_GROWSDOWN &&
		addr >= FIRST_USER_ADDRESS && !expand_stack(vma, addr))
		goto good_area;
 out:
	return fault;
}

static int __kprobes
do_page_fault(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	int fault, sig, code;
	unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;

	if (notify_page_fault(regs, fsr))
		return 0;

	tsk = current;
	mm	= tsk->mm;

	/* Enable interrupts if they were enabled in the parent context. */
	if (interrupts_enabled(regs))
		local_irq_enable();

	/*
	 * If we're in an interrupt or have no user
	 * context, we must not take the fault..
	 */
	if (faulthandler_disabled() || !mm)
		goto no_context;

	if (user_mode(regs))
		flags |= FAULT_FLAG_USER;
	if (fsr & FSR_WRITE)
		flags |= FAULT_FLAG_WRITE;

	/*
	 * As per x86, we may deadlock here.  However, since the kernel only
	 * validly references user space from well defined areas of the code,
	 * we can bug out early if this is from code which shouldn't.
	 */
	if (!down_read_trylock(&mm->mmap_sem)) {
		if (!user_mode(regs) && !search_exception_tables(regs->ARM_pc))
			goto no_context;
	retry:
		down_read(&mm->mmap_sem);
	} else {
		/*
		 * The above down_read_trylock() might have succeeded in
		 * which case, we'll have missed the might_sleep() from
		 * down_read()
		 */
		might_sleep();
#ifdef CONFIG_DEBUG_VM
		if (!user_mode(regs) &&
			!search_exception_tables(regs->ARM_pc))
			goto no_context;
#endif
	}

	fault = __do_page_fault(mm, addr, fsr, flags, tsk);

	/* If we need to retry but a fatal signal is pending, handle the
	 * signal first. We do not need to release the mmap_sem because
	 * it would already be released in __lock_page_or_retry in
	 * mm/filemap.c. */
	if ((fault & VM_FAULT_RETRY) && fatal_signal_pending(current))
		return 0;

	/*
	 * Major/minor page fault accounting is only done on the
	 * initial attempt. If we go through a retry, it is extremely
	 * likely that the page will be found in page cache at that point.
	 */

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, addr);
	if (!(fault & VM_FAULT_ERROR) && flags & FAULT_FLAG_ALLOW_RETRY) {
		if (fault & VM_FAULT_MAJOR) {
			tsk->maj_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ, 1,
				      regs, addr);
		} else {
			tsk->min_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN, 1,
				      regs, addr);
		}
		if (fault & VM_FAULT_RETRY) {
			/* Clear FAULT_FLAG_ALLOW_RETRY to avoid any risk
			 * of starvation. */
			flags &= ~FAULT_FLAG_ALLOW_RETRY;
			flags |= FAULT_FLAG_TRIED;
			goto retry;
		}
	}

	up_read(&mm->mmap_sem);

	/*
	 * Handle the "normal" case first - VM_FAULT_MAJOR / VM_FAULT_MINOR
	 */
	if (likely(!(fault & (VM_FAULT_ERROR | VM_FAULT_BADMAP | VM_FAULT_BADACCESS))))
		return 0;

	/*
	 * If we are in kernel mode at this point, we
	 * have no context to handle this fault with.
	 */
	if (!user_mode(regs))
		goto no_context;

	if (fault & VM_FAULT_OOM) {
		/*
		 * We ran out of memory, call the OOM killer, and return to
		 * userspace (which will retry the fault, or kill us if we
		 * got oom-killed)
		 */
		pagefault_out_of_memory();
		return 0;
	}

	if (fault & VM_FAULT_SIGBUS) {
		/*
		 * We had some memory, but were unable to
		 * successfully fix up this page fault.
		 */
		sig = SIGBUS;
		code = BUS_ADRERR;
	} else {
		/*
		 * Something tried to access memory that
		 * isn't in our memory map..
		 */
		sig = SIGSEGV;
		code = fault == VM_FAULT_BADACCESS ?
			SEGV_ACCERR : SEGV_MAPERR;
	}

	__do_user_fault(tsk, addr, fsr, sig, code, regs);
	return 0;

 no_context:
	__do_kernel_fault(mm, addr, fsr, regs);
	return 0;
}
#else					/* CONFIG_MMU */
static int
do_page_fault(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	return 0;
}
#endif					/* CONFIG_MMU */

/*
 * First Level Translation Fault Handler
 *
 * We enter here because the first level page table doesn't contain
 * a valid entry for the address.
 *
 * If the address is in kernel space (>= TASK_SIZE), then we are
 * probably faulting in the vmalloc() area.
 *
 * If the init_task's first level page tables contains the relevant
 * entry, we copy the it to this task.	If not, we send the process
 * a signal, fixup the exception, or oops the kernel.
 *
 * NOTE! We MUST NOT take any locks for this case. We may be in an
 * interrupt or a critical region, and should only copy the information
 * from the master page table, nothing more.
 */
#ifdef CONFIG_MMU
static int __kprobes
do_translation_fault(unsigned long addr, unsigned int fsr,
			 struct pt_regs *regs)
{
	unsigned int index;
	pgd_t *pgd, *pgd_k;
	pud_t *pud, *pud_k;
	pmd_t *pmd, *pmd_k;

	if (addr < TASK_SIZE)
		return do_page_fault(addr, fsr, regs);

	if (user_mode(regs))
		goto bad_area;

	index = pgd_index(addr);

	pgd = cpu_get_pgd() + index;
	pgd_k = init_mm.pgd + index;

	if (pgd_none(*pgd_k))
		goto bad_area;
	if (!pgd_present(*pgd))
		set_pgd(pgd, *pgd_k);

	pud = pud_offset(pgd, addr);
	pud_k = pud_offset(pgd_k, addr);

	if (pud_none(*pud_k))
		goto bad_area;
	if (!pud_present(*pud))
		set_pud(pud, *pud_k);

	pmd = pmd_offset(pud, addr);
	pmd_k = pmd_offset(pud_k, addr);

#ifdef CONFIG_ARM_LPAE
	/*
	 * Only one hardware entry per PMD with LPAE.
	 */
	index = 0;
#else
	/*
	 * On ARM one Linux PGD entry contains two hardware entries (see page
	 * tables layout in pgtable.h). We normally guarantee that we always
	 * fill both L1 entries. But create_mapping() doesn't follow the rule.
	 * It can create inidividual L1 entries, so here we have to call
	 * pmd_none() check for the entry really corresponded to address, not
	 * for the first of pair.
	 */
	index = (addr >> SECTION_SHIFT) & 1;
#endif
	if (pmd_none(pmd_k[index]))
		goto bad_area;

	copy_pmd(pmd, pmd_k);
	return 0;

 bad_area:
	do_bad_area(addr, fsr, regs);
	return 0;
}
#else					/* CONFIG_MMU */
static int
do_translation_fault(unsigned long addr, unsigned int fsr,
			 struct pt_regs *regs)
{
	return 0;
}
#endif					/* CONFIG_MMU */

/*
 * Some section permission faults need to be handled gracefully.
 * They can happen due to a __{get,put}_user during an oops.
 */
#ifndef CONFIG_ARM_LPAE
static int
do_sect_fault(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	do_bad_area(addr, fsr, regs);
	return 0;
}
#endif /* CONFIG_ARM_LPAE */

/*
 * This abort handler always returns "fault".
 */
static int
do_bad(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	return 1;
}

struct fsr_info {
	int	(*fn)(unsigned long addr, unsigned int fsr, struct pt_regs *regs);
	int	sig;
	int	code;
	const char *name;
};

/* FSR definition */
#ifdef CONFIG_ARM_LPAE
#include "fsr-3level.c"
#else
#include "fsr-2level.c"
#endif

void __init
hook_fault_code(int nr, int (*fn)(unsigned long, unsigned int, struct pt_regs *),
		int sig, int code, const char *name)
{
	if (nr < 0 || nr >= ARRAY_SIZE(fsr_info))
		BUG();

	fsr_info[nr].fn   = fn;
	fsr_info[nr].sig  = sig;
	fsr_info[nr].code = code;
	fsr_info[nr].name = name;
}

/*
 * Dispatch a data abort to the relevant handler.
 */
asmlinkage void __exception
do_DataAbort(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	const struct fsr_info *inf = fsr_info + fsr_fs(fsr);
	struct siginfo info;

	if (!inf->fn(addr, fsr & ~FSR_LNX_PF, regs))
		return;

	pr_alert("Unhandled fault: %s (0x%03x) at 0x%08lx\n",
		 inf->name, fsr, addr);
	show_pte(current->mm, addr);

	info.si_signo = inf->sig;
	info.si_errno = 0;
	info.si_code  = inf->code;
	info.si_addr  = (void __user *)addr;
	arm_notify_die("", regs, &info, fsr, 0);
}


void __init
hook_ifault_code(int nr, int (*fn)(unsigned long, unsigned int, struct pt_regs *),
		 int sig, int code, const char *name)
{
	if (nr < 0 || nr >= ARRAY_SIZE(ifsr_info))
		BUG();

	ifsr_info[nr].fn   = fn;
	ifsr_info[nr].sig  = sig;
	ifsr_info[nr].code = code;
	ifsr_info[nr].name = name;
}

static struct page *page_by_address(const struct mm_struct *const mm,
							 const unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	struct page *page = NULL;

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		goto do_return;

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		goto do_return;

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		goto do_return;

	pte = pte_offset_kernel(pmd, address);
	if (!pte_present(*pte))
		goto do_return;

	page = pte_page(*pte);
do_return:
	return page;
}

typedef void (optee_invoke_fn)(unsigned long, unsigned long, unsigned long,
			       unsigned long, unsigned long, unsigned long,
			       unsigned long, unsigned long,
			       void *);

extern optee_invoke_fn *global_invoke_fn;

typedef struct tee_shm *drm_global_shm_alloc(size_t, u32);

extern drm_global_shm_alloc global_shm_alloc;

struct thread_abort_regs;
void copy_pt_to_abort_regs(struct thread_abort_regs *target_regs, struct pt_regs *src_regs, unsigned long addr);

#ifdef DRM_DEBUG
static void print_abort_regs(struct thread_abort_regs *regs)
{
	printk("[-] dumping regs\n");
	printk("\t usr_sp = 0x%x", regs->usr_sp);
	printk("\t usr_lr = 0x%x", regs->usr_lr);
	printk("\t spsr= 0x%x", regs->spsr);
	printk("\t elr = 0x%x\n", regs->elr);
	printk("\t r0 = 0x%x", regs->r0);
	printk("\t r1 = 0x%x", regs->r1);
	printk("\t r2 = 0x%x", regs->r2);
	printk("\t r3 = 0x%x\n", regs->r3);
	printk("\t r4 = 0x%x", regs->r4);
	printk("\t r5 = 0x%x", regs->r5);
	printk("\t r6 = 0x%x", regs->r6);
	printk("\t r7 = 0x%x\n", regs->r7);
	printk("\t r8 = 0x%x", regs->r8);
	printk("\t r9 = 0x%x", regs->r9);
	printk("\t r10 = 0x%x\n", regs->r10);
	printk("\t r11 = 0x%x", regs->r11);
	printk("\t ip = 0x%x", regs->ip);
	printk("\t pad = 0x%x\n\n", regs->pad);
}
#endif

asmlinkage void __exception
do_PrefetchAbort(unsigned long addr, unsigned int ifsr, struct pt_regs *regs)
{
	const struct fsr_info *inf = ifsr_info + fsr_fs(ifsr);
	struct siginfo info;
	//struct arm_smccc_res res;
	struct tee_shm *shm = NULL;
	struct page *page = NULL;

	struct task_struct *target_proc = current;

	struct thread_abort_regs *shm_regs;

	phys_addr_t paddr, shm_pa; // this is the physical address of the blob
	const long int OPTEE_MIN = 0xe100000;
	const long int OPTEE_MAX = 0xef00000;


	if (ifsr == 0x01f) { // page permission fault
	
		page = page_by_address(target_proc->mm, addr);
		paddr = page_to_phys(page);
		if( paddr < OPTEE_MIN  || paddr > OPTEE_MAX)
			goto die;

#ifdef DRM_DEBUG
		printk("[!] %s prefetch abort: %s (0x%03x) at 0x%08lx with lr %p\n",
				__func__, inf->name, ifsr, addr, (void*)regs->ARM_lr);
#endif
		if(target_proc->dfc_regs == NULL) {
		    // This is the first time, process in non-secure side
		    // faulted, trying to execute secure side code.
		    shm = global_shm_alloc(sizeof(struct thread_abort_regs), TEE_SHM_MAPPED | TEE_SHM_DMA_BUF);

		    if (!shm)
			    goto die; //-ENOMEM

		    if (IS_ERR(shm))
			    goto die; //-ERESTART

		    shm_regs = (struct thread_abort_regs*)tee_shm_get_va(shm, 0);
		    copy_pt_to_abort_regs(shm_regs, regs, addr);

			target_proc->dfc_regs = shm_regs; // XXX: do we need to copy the regs global loc?

#ifdef DRM_DEBUG
			print_abort_regs(target_proc->dfc_regs);
		    printk("[+] fault.c before optee_do_call_from_abort (PC: %lx)\n",
					(unsigned long)shm_regs->ip);
#endif

		    tee_shm_get_pa(shm, 0, &shm_pa);

			// here we pass both the physical address of the shared memory and 
			// shm pointer for the secure world to release the memory.
		    optee_do_call_from_abort(OPTEE_MSG_FORWARD_EXECUTION, shm_pa, (unsigned long)shm, target_proc->pid, 0, 0, 0, 0);
		    tee_shm_free(shm);
	} else {
	    // we should copy to the shared memory allocated by the secure side
	    copy_pt_to_abort_regs((struct thread_abort_regs*)target_proc->dfc_regs, regs, addr);

		//target_proc->dfc_regs = shm_regs; // XXX: do we need to copy the regs global loc?
#ifdef DRM_DEBUG
		print_abort_regs(target_proc->dfc_regs);
	    printk("[+] fault.c in else before optee_do_call_from_abort\n");
#endif
	
		// here we pass both the physical address of the shared memory and 
		// shm pointer for the secure world to release the memory.
		optee_do_call_from_abort(OPTEE_MSG_FORWARD_EXECUTION, shm_pa,
								(unsigned long)shm, target_proc->pid, 0, 0, 0, 0);
	}

#ifdef DRM_DEBUG
		printk("[+] %s: Returning from forward execution\n", __func__);
		printk("[+] fault.c after do_call_from_abort with PC set to %p, lr %p, cpsr %p\n",
				(void*)regs->ARM_pc, (void*)regs->ARM_lr, (void*)regs->ARM_cpsr);
#endif

		return;
}

die:
	if (!inf->fn(addr, ifsr | FSR_LNX_PF, regs))
		return;

	pr_alert("Unhandled prefetch abort: %s (0x%03x) at 0x%08lx\n",
			 inf->name, ifsr, addr);

	info.si_signo = inf->sig;
	info.si_errno = 0;
	info.si_code  = inf->code;
	info.si_addr  = (void __user *)addr;
	arm_notify_die("", regs, &info, ifsr, 0);
}

int drm_data_abort(uint64_t addr, uint64_t fsr, struct pt_regs *regs) {
	do_DataAbort((unsigned long)addr, (unsigned int)fsr, regs);
	return 0;
}

int drm_prefetch_abort(uint64_t addr, uint64_t ifsr, struct pt_regs *regs) {
	do_PrefetchAbort((unsigned long)addr, (unsigned int)ifsr, regs);
	return 0;
}

/*
 * Abort handler to be used only during first unmasking of asynchronous aborts
 * on the boot CPU. This makes sure that the machine will not die if the
 * firmware/bootloader left an imprecise abort pending for us to trip over.
 */
static int __init early_abort_handler(unsigned long addr, unsigned int fsr,
					  struct pt_regs *regs)
{
	pr_warn("Hit pending asynchronous external abort (FSR=0x%08x) during "
		"first unmask, this is most likely caused by a "
		"firmware/bootloader bug.\n", fsr);

	return 0;
}

void __init early_abt_enable(void)
{
	fsr_info[22].fn = early_abort_handler;
	local_abt_enable();
	fsr_info[22].fn = do_bad;
}

#ifndef CONFIG_ARM_LPAE
static int __init exceptions_init(void)
{
	if (cpu_architecture() >= CPU_ARCH_ARMv6) {
		hook_fault_code(4, do_translation_fault, SIGSEGV, SEGV_MAPERR,
				"I-cache maintenance fault");
	}

	if (cpu_architecture() >= CPU_ARCH_ARMv7) {
		/*
		 * TODO: Access flag faults introduced in ARMv6K.
		 * Runtime check for 'K' extension is needed
		 */
		hook_fault_code(3, do_bad, SIGSEGV, SEGV_MAPERR,
				"section access flag fault");
		hook_fault_code(6, do_bad, SIGSEGV, SEGV_MAPERR,
				"section access flag fault");
	}

	return 0;
}

arch_initcall(exceptions_init);
#endif
