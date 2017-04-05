#ifndef DRM_UTILS_H
#define DRM_UTILS_H

#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/list.h>
#include <asm/smp_plat.h>
#include <linux/module.h>
#include <linux/slab.h>

#define DFC_ERR_HDR "DFC_ERROR in %s:"

typedef uint64_t PHY_ADDR_TYPE; 
typedef uint64_t VA_ADDR_TYPE;
typedef uint64_t LEN_TYPE;
typedef uint64_t MM_ATTR_TYPE;


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

typedef struct dfc_mem_map DFC_MEMORY_MAP;

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
					   DFC_MEMORY_MAP **target_mm_blob, 
					   uint64_t *num_of_entries,
					   struct dfc_local_map **local_map);

/*
 *
 * This function releases references to all the memory pages referenced by local_map list.
 * It also marks the dirty bit if the page was writable.
 *
 * @param local_map: Pointer which points to the list of local_maps allocated by
 *                   get_all_data_pages function.
 */
void release_all_data_pages(struct dfc_local_map **local_map);

#endif
