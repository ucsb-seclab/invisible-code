#include <assert.h>
#include <compiler.h>
#include <keep.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>
#include <kernel/tee_blob_manager.h>
#include <kernel/dfc_blob_common.h>
#include <kernel/thread.h>
#include <kernel/user_blob.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mm.h>
#include <mm/core_memprot.h>
#include <tee/tee_svc.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>

#include "elf_common.h"

// DISCLAIMER: some of the code here has been shamelessly stolen from user_ta.c and adapted :)

static paddr_t get_code_pa(struct user_blob_ctx *utc)
{
	return tee_mm_get_smem(utc->mm);
}

static TEE_Result alloc_code(struct user_blob_ctx *ubc, size_t vasize){
	ubc->mm = tee_mm_alloc(&tee_mm_sec_ddr, vasize);
	if(!ubc->mm){
		EMSG("Failed to allocate %zu bytes for code", vasize);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	return TEE_SUCCESS;
}

static uint32_t elf_flags_to_mattr(uint32_t flags, bool init_attrs)
{
	uint32_t mattr = 0;

	if (init_attrs)
		mattr = TEE_MATTR_PRW;
	else {
		if (flags & PF_X)
			mattr |= TEE_MATTR_UX;
		if (flags & PF_W)
			mattr |= TEE_MATTR_UW;
		if (flags & PF_R)
			mattr |= TEE_MATTR_UR;
	}

	return mattr;
}

static TEE_Result setup_code_segment(struct user_blob_ctx *ubc, bool init_attrs)
{
	paddr_t pa;
	uint32_t mattr;

	const uint32_t code_attrs = PF_R | PF_X;

	mattr = elf_flags_to_mattr(code_attrs, init_attrs);

	// clear memory map
	tee_mmu_blob_map_clear(ubc);

	// we don't need to add any other segment,
	// let's just create the memory mapping
	// for the code section

	pa = get_code_pa(ubc);

	// add the segment to memory mappings

	// res = tee_mmu_blob_map_add_segment(ubc, pa, 0, ubc->blobinfo.size, mattr);
	// we don't need to use the map_add_segment, we just setup the single page
	// we need to allocate code :)
	
	return tee_mmu_map_blob_code(ubc, pa, mattr);
}


static TEE_Result decrypt_blob(void *dst, void *src, ssize_t size, unsigned char key __maybe_unused){


	//XXX: temporarily disable decryption
#ifdef DRM_DECRYPT
	unsigned char *dest;
	dest = memcpy(dst, src, size);
	if(false)
		for (--size; size; size--) *(dst+size) = *(dst+size) ^ key;
#else
	memcpy(dst, src, size);
#endif

	return TEE_SUCCESS;
}

/*
 * loads the blob into memory
 */
static TEE_Result blob_load(struct blob_info *blob,
		struct tee_blob_ctx **ctx)
{
	/*
	 * load_blob_data will copy a given mem_blob from non-secure world memory
	 * */
	TEE_Result res;
	void *curr_mem;
	uint64_t orig_blob_len;
	paddr_t orig_blob_addr;

	size_t vasize;
	void *va;

	struct user_blob_ctx *ubc;

	ubc = (struct user_blob_ctx *)calloc(1, sizeof(struct user_blob_ctx));
	if (!ubc) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	// read the blob addr and blob len

	// XXX: need to modify this to get the same memory map
	// existing in normal world

	orig_blob_addr = blob->pa;
	orig_blob_len = blob->size;
	memcpy(&ubc->blobinfo, blob, sizeof(struct blob_info));

	// get the VA corresponding to the provided blob memory.
	curr_mem = phys_to_virt(orig_blob_addr, MEM_AREA_NSEC_SHM);

	if(!curr_mem) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	// make sure that this is in non-secure memory.
	if (!tee_vbuf_is_non_sec(curr_mem, orig_blob_len)) {
		res = TEE_ERROR_SECURITY;
		goto out;
	}
	
	// allocate memory in the secure world.
	// TODO: use secure memory,
	// reference user_ta.c:alloc_code and get_code_pa
	
	ubc->ctx.flags = TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR;

	res = alloc_code(ubc, orig_blob_len);
	if(res != TEE_SUCCESS) {
		goto out;
	}

	res = tee_mmu_blob_init(ubc);
	if (res != TEE_SUCCESS)
		goto out;

	// init memory mapping
	res = setup_code_segment(ubc, true);

	if (res != TEE_SUCCESS)
		goto out;

	tee_mmu_blob_set_ctx(&ubc->ctx);

	res = decrypt_blob((void *)(unsigned long)blob->va, curr_mem, orig_blob_len, EMBEDDED_KEY);

	assert((void*)(unsigned long)blob->va == (void *)tee_mmu_get_blob_load_addr(&ubc->ctx));
	
	if (res != TEE_SUCCESS)
		goto out;

	// finalize memory mapping
	res = setup_code_segment(ubc, false);
	
	tee_mmu_blob_set_ctx(&ubc->ctx);

	if (res != TEE_SUCCESS)
		goto out;

	*ctx = &ubc->ctx;

	res = TEE_SUCCESS;

	assert((void *)tee_mmu_get_blob_load_addr(&ubc->ctx) == (void*)ubc->mmu->ta_private_vmem_start);

	va = (void*)ubc->mmu->ta_private_vmem_start;
	vasize = ubc->mmu->ta_private_vmem_end - ubc->mmu->ta_private_vmem_start;
	
	cache_maintenance_l1(DCACHE_AREA_CLEAN,
			va, vasize);
	cache_maintenance_l1(ICACHE_AREA_INVALIDATE,
			va, vasize);
	blob->pa = get_code_pa(ubc);
out:
		// error occured.
	return res;
}

TEE_Result user_blob_load(TEE_ErrorOrigin *err __unused,
		struct tee_blob_session *session,
		enum utee_entry_func func __unused,
		uint32_t cmd __unused,
		struct tee_blob_param *param __unused,
		struct blob_info *blob)
{
	TEE_Result res;
	
	//struct user_blob_ctx *ubc;

	res = blob_load((void*)blob, &session->ctx);
	DMSG("blob_load: pa=%llx", blob->pa);
	if (res != TEE_SUCCESS) {
		EMSG("blob_load failed");
		goto out;
	}

	//ubc = to_user_blob_ctx(session->ctx);

	// let's tell zulu that this is our first blob exec
	thread_get_tsd()->first_blob_exec = true;
	
	//res = thread_enter_user_mode(0x33c0ffee, tee_svc_kaddr_to_uref(session),
	//					0xb10b7175, 0xd33d6041, 0x400000,
	//					(vaddr_t)blob->va+1, true, &ubc->ctx.panicked, &ubc->ctx.panic_code);
out:
	return res;
}


/* ============ other stuff left lying around ======== */

// copy blob into secure world.
//memcpy(allocated_mem, curr_mem, orig_blob_len);

// +1 because we are considering a thumb function, this will
// be transparent when memory mapping is shared and we are using
// the abort handlers to jump around
// shellcode = (void *)((unsigned long)allocated_mem + 1);

//res = thread_enter_user_mode(0x33c0ffee, tee_svc_kaddr_to_uref(session),
//		0xb00b7175, 0xd33d6041, (vaddr_t)temp_stack,
//		(vaddr_t)shellcode, true, &ubc->ctx.panicked, &ubc->ctx.panic_code);

//serr = TEE_ORIGIN_TRUSTED_APP; // just follow the GP spec also for blobs

//asm volatile (
//		"blx %[blobref]\n\t"
//		:: [blobref] "r" (shellcode) : //"r0", "r1", "r2", "r3", "r4", "r5", "r6", "lr", "ip", "r8", "r9", "r10"
//);

// copy the pointer and size into provided arguments.
//*out_blob_addr = allocated_mem;
//*out_blob_len = orig_blob_len;
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
