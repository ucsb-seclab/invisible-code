#ifndef LINUX_MM_TYPES_H
/*
 * vm_flags in vm_area_struct, see mm_types.h.
 */
#define VM_NONE		0x00000000

#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

/* mprotect() hardcodes VM_MAYREAD >> 4 == VM_READ, and so for r/w/x bits. */
#define VM_MAYREAD	0x00000010	/* limits for mprotect() etc */
#define VM_MAYWRITE	0x00000020
#define VM_MAYEXEC	0x00000040
#define VM_MAYSHARE	0x00000080

#define VM_GROWSDOWN	0x00000100	/* general info on the segment */
#define VM_UFFD_MISSING	0x00000200	/* missing pages tracking */
#define VM_PFNMAP	0x00000400	/* Page-ranges managed without "struct page", just pure PFN */
#define VM_DENYWRITE	0x00000800	/* ETXTBSY on write attempts.. */
#define VM_UFFD_WP	0x00001000	/* wrprotect pages tracking */

#define VM_LOCKED	0x00002000
#define VM_IO           0x00004000	/* Memory mapped I/O or similar */

					/* Used by sys_madvise() */
#define VM_SEQ_READ	0x00008000	/* App will access data sequentially */
#define VM_RAND_READ	0x00010000	/* App will not benefit from clustered reads */

#define VM_DONTCOPY	0x00020000      /* Do not copy this vma on fork */
#define VM_DONTEXPAND	0x00040000	/* Cannot expand with mremap() */
#define VM_LOCKONFAULT	0x00080000	/* Lock the pages covered when they are faulted in */
#define VM_ACCOUNT	0x00100000	/* Is a VM accounted object */
#define VM_NORESERVE	0x00200000	/* should the VM suppress accounting */
#define VM_HUGETLB	0x00400000	/* Huge TLB Page VM */
#define VM_ARCH_1	0x01000000	/* Architecture-specific flag */
#define VM_ARCH_2	0x02000000
#define VM_DONTDUMP	0x04000000	/* Do not include in the core dump */

#ifdef CONFIG_MEM_SOFT_DIRTY
# define VM_SOFTDIRTY	0x08000000	/* Not soft dirty clean area */
#else
# define VM_SOFTDIRTY	0
#endif

#define VM_MIXEDMAP	0x10000000	/* Can contain "struct page" and pure PFN pages */
#define VM_HUGEPAGE	0x20000000	/* MADV_HUGEPAGE marked this vma */
#define VM_NOHUGEPAGE	0x40000000	/* MADV_NOHUGEPAGE marked this vma */
#define VM_MERGEABLE	0x80000000	/* KSM may merge identical pages */

#if defined(CONFIG_X86)
# define VM_PAT		VM_ARCH_1	/* PAT reserves whole VMA at once (x86) */
#elif defined(CONFIG_PPC)
# define VM_SAO		VM_ARCH_1	/* Strong Access Ordering (powerpc) */
#elif defined(CONFIG_PARISC)
# define VM_GROWSUP	VM_ARCH_1
#elif defined(CONFIG_METAG)
# define VM_GROWSUP	VM_ARCH_1
#elif defined(CONFIG_IA64)
# define VM_GROWSUP	VM_ARCH_1
#elif !defined(CONFIG_MMU)
# define VM_MAPPED_COPY	VM_ARCH_1	/* T if mapped copy of data (nommu mmap) */
#endif

#if defined(CONFIG_X86)
/* MPX specific bounds table or bounds directory */
# define VM_MPX		VM_ARCH_2
#endif

#ifndef VM_GROWSUP
# define VM_GROWSUP	VM_NONE
#endif

/* Bits set in the VMA until the stack is in its final location */
#define VM_STACK_INCOMPLETE_SETUP	(VM_RAND_READ | VM_SEQ_READ)

#ifndef VM_STACK_DEFAULT_FLAGS		/* arch can override this */
#define VM_STACK_DEFAULT_FLAGS VM_DATA_DEFAULT_FLAGS
#endif

#ifdef CONFIG_STACK_GROWSUP
#define VM_STACK	VM_GROWSUP
#else
#define VM_STACK	VM_GROWSDOWN
#endif

#define VM_STACK_FLAGS	(VM_STACK | VM_STACK_DEFAULT_FLAGS | VM_ACCOUNT)

/*
 * Special vmas that are non-mergable, non-mlock()able.
 * Note: mm/huge_memory.c VM_NO_THP depends on this definition.
 */
#define VM_SPECIAL (VM_IO | VM_DONTEXPAND | VM_PFNMAP | VM_MIXEDMAP)

/* This mask defines which mm->def_flags a process can inherit its parent */
#define VM_INIT_DEF_MASK	VM_NOHUGEPAGE

/* This mask is used to clear all the VMA flags used by mlock */
#define VM_LOCKED_CLEAR_MASK	(~(VM_LOCKED | VM_LOCKONFAULT))
#endif
