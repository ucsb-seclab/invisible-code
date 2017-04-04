#ifndef DRM_UTILS_H
#define DRM_UTILS_H

#include <linux/sched.h>

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
 * @return 0 if success else non-zero.
 */
int get_all_data_pages(struct task_struct *target_proc, 
					   DFC_MEMORY_MAP **target_mm_blob, 
					   uint64_t *num_of_entries);

#endif
