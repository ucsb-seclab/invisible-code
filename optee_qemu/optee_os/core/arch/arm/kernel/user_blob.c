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
#include <tee/tee_svc.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>


/*
 * loads the blob into memory
 */
TEE_Result blob_load(struct blob_info *blob, struct tee_blob_session *session)
{
	/*
	 * load_blob_data will copy a given mem_blob from non-secure world memory
	 * */
	TEE_Result res;
	void *curr_mem;
	void *allocated_mem;
	void *shellcode;
	uint64_t orig_blob_len;
	paddr_t orig_blob_addr;
	uint64_t page;
	void *temp_stack;
	uint64_t stack_size;

	uint32_t panicked;
	uint32_t panic_code;

	allocated_mem = NULL;
	temp_stack = NULL;
	curr_mem = NULL;

	stack_size = 1000;

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

	temp_stack = malloc(stack_size); // this is some temp mem to use as stack
								// until we share memory mappings
	if(!temp_stack) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err_out;
	}
	memset(temp_stack, 0, stack_size);

	// copy blob into secure world.
	memcpy(allocated_mem, curr_mem, orig_blob_len);
	page = (uint64_t)(unsigned long)allocated_mem;
	page = page >> 24;
	page = page << 24;

	// +1 because we are considering a thumb function, this will
	// be transparent when memory mapping is shared and we are using
	// the abort handlers to jump around
	shellcode = (void *)((unsigned long)allocated_mem + 1);

	res = thread_enter_user_mode(0x33c0ffee, tee_svc_kaddr_to_uref(session),
			0xb00b7175, 0xd33d6041, (vaddr_t)temp_stack,
			(vaddr_t)shellcode, true, &panicked, &panic_code);

	//serr = TEE_ORIGIN_TRUSTED_APP; // just follow the GP spec also for blobs

	asm volatile (
			"blx %[blobref]\n\t"
			:: [blobref] "r" (shellcode) : //"r0", "r1", "r2", "r3", "r4", "r5", "r6", "lr", "ip", "r8", "r9", "r10"
	);

	// copy the pointer and size into provided arguments.
	//*out_blob_addr = allocated_mem;
	//*out_blob_len = orig_blob_len;
	
	free(allocated_mem);
	free(temp_stack);
	return TEE_SUCCESS;

	err_out:
		// error occured.
		if(allocated_mem != NULL) {
			free(allocated_mem);
		}
	return res;
}

/*
 * user_blob_enter prepares everything to start a user thread
 
static TEE_Result user_blob_enter(TEE_ErrorOrigin *err __unused,
				struct tee_blob_session *session __unused,
				uint32_t cmd __unused,
				struct tee_blob_param *param __unused)
{

	return TEE_SUCCESS;
}
*/
