#ifndef DRM_UTILS_H
#define DRM_UTILS_H

#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/list.h>
#include <asm/smp_plat.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "../optee_private.h"

#define DFC_ERR_HDR "DFC_ERROR in %s:"
#define DFC_WARN_HDR "DFC_WARN in %s:"

typedef uint64_t PHY_ADDR_TYPE; 
typedef uint64_t VA_ADDR_TYPE;
typedef uint64_t LEN_TYPE;
typedef uint64_t MM_ATTR_TYPE;


typedef unsigned int (*LPSYSCALL) (unsigned long long,
				   unsigned long long,
				   unsigned long long);



struct dfc_mem_map {
	VA_ADDR_TYPE va;
	PHY_ADDR_TYPE pa;
	LEN_TYPE size;
	MM_ATTR_TYPE attr; 
}; 

// linked list of all va<->pa mappings of the
// process shared by the non-secure OS.
struct dfc_local_map {
	VA_ADDR_TYPE va;
	PHY_ADDR_TYPE pa;
	LEN_TYPE size;
	MM_ATTR_TYPE attr;
	struct page *target_page;
	bool is_locked;
	struct list_head list;
};

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

// XXX: only support for 32 bits registers here?
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

// typedef struct dfc_mem_map DFC_MEMORY_MAP;


/*
 * this function will add the given pa start-end range to the
 * global dfc sec mem map, it will also clear the relative va entry
 * in the linux task and put a new one with the secure world pa
 * */
int add_secure_mem(struct task_struct *target_proc,
		const unsigned long va,
		const unsigned long pa_start,
		const unsigned long pa_end);

	/*
 * This function checks if the provided address is in secure world.
 *
 * @param phy_addr: The address which needs to be checked.
 *
 *
 * @return true/false depending on whether the address is in secure memory or not.
 */
bool is_secure_mem(unsigned long phy_addr);

/*
 * This function gets the page that corresponds to the provided address in
 * the memory map of the provided task.
 *
 * @param target_proc: Target process in whose memory map the page needs
 *                     to be fetched.
 *
 * @param addr: The virtual address whose page needs to be fetched.
 *
 * @return pointer to the page corresponding to the provided virtual address.
 *
 */
struct page *get_task_page(struct task_struct *target_proc, const unsigned long addr);

/*
 * This function checks if the provided address is mapped (i.e has physical page)
 * allocated in the memory map of the provided task
 *
 * @param target_proc: Target process in whose memory map the address need
 *                     need to be checked.
 *
 * @param addr: Address which needs to be checked in the memory map of the
 *                       process.
 *
 * @return true/false depending on whether the address is mapped or not.
 *
 */
bool is_address_mapped(struct task_struct *target_proc, unsigned long addr_to_check);

/*
 * Get all memory map blobs for data pages
 * of the provided process.
 *
 * @param target_proc: Target process for which data pages need to be fetched.
 * @param target_mm_blob: Output pointer where the array of the destination 
 * 						 array of blobs will be stored.
 * @param num_of_entries: Output pointer where the number of mem map 
 *						 entries will be stored.
 * @param local_map: Output pointer where the linked list of
 *					 all the va<->pa mappings computed.
 *					 This is local information, helps in unlocking
 *					the pages.
 * @return 0 if success else non-zero.
 */
int get_all_data_pages(struct task_struct *target_proc, 
					   uint64_t *num_of_entries,
					   struct dfc_local_map **local_map);

/* Copy the target mm in the given dst (result_map)
 * @param num_entries: number of entries in the mem map
 * @param local_mm_blob: the local map (linked list)
 * @param result_map: the resulting array of dfc_mem_map structures
 *						which will be passed to optee
 */
int finalize_data_pages(
		unsigned long num_entries,
		struct dfc_mem_map *local_mm_blob,
		struct dfc_local_map *result_map);

/*
 *
 * This function releases references to all the memory pages referenced by local_map list.
 * It also marks the dirty bit if the page was writable.
 *
 * @param local_map: Pointer which points to the list of local_maps allocated by
 *                   get_all_data_pages function.
 */
void release_all_data_pages(struct dfc_local_map **local_map);

/*
 * This function changes the user mode saved registers of the provided task.
 * This is needed so that we can jump into user mode to arbitrary location reported by secure side blob.
 *
 * @param target_proc: Target task whose registers need to be changed.
 *
 * @param target_regs: New values of the registers.
 *
 */
void modify_task_regs(struct task_struct *target_proc, struct pt_regs *target_regs);

/*
 * This function converts the provided pt_regs structure contents into abort_regs contents.
 *
 * @param target_regs: Thread abort regs to which the registers need to be copied.
 *
 * @param src_regs: Source registers which need to converted.
 */
void copy_pt_to_abort_regs(struct thread_abort_regs *target_regs, struct pt_regs *src_regs);

#endif
