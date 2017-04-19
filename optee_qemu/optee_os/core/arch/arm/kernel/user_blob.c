#include <assert.h>
#include <compiler.h>
#include <keep.h>
#include <kernel/panic.h>
#include <kernel/tee_blob_manager.h>
#include <kernel/dfc_blob_common.h>
#include <kernel/thread.h>
#include <kernel/user_blob.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mm.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>


/*
 * loads the blob into memory
 */
TEE_Result blob_load(struct blob_info *blob)
{
	/*
	 * load_blob_data will copy a given mem_blob from non-secure world memory
	 * */
	TEE_Result res;
	void *curr_mem;
	void *allocated_mem;
	uint64_t orig_blob_len;
	paddr_t orig_blob_addr;
	allocated_mem = NULL;
	curr_mem = NULL;

	// read the blob addr and blob len
	orig_blob_addr = blob->pa;
	orig_blob_len = blob->size;

	// get the VA corresponding to the provided blob memory.
	curr_mem = phys_to_virt(orig_blob_addr, MEM_AREA_NSEC_SHM);

	if(!curr_mem) {
		res = TEE_ERROR_GENERIC;
		goto err_out;
	}

	// make sure that this is in non-secure memory.
	if (!tee_vbuf_is_non_sec(curr_mem, orig_blob_len)) {
		res = TEE_ERROR_SECURITY;
		goto err_out;
	}
	
	// allocate memory in the secure world.
	// TODO: use secure memory,
	// reference user_ta.c:alloc_code and get_code_pa

	allocated_mem = malloc(orig_blob_len);
	if(!allocated_mem) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err_out;
	}

	// copy blob into secure world.
	memcpy(allocated_mem, curr_mem, orig_blob_len);

	// copy the pointer and size into provided arguments.
	//*out_blob_addr = allocated_mem;
	//*out_blob_len = orig_blob_len;

	return TEE_SUCCESS;

	err_out:
		// error occured.
		if(allocated_mem != NULL) {
			free(allocated_mem);
		}
	return res;	
}
