#ifndef KERNEL_USER_BLOB_H
#define KERNEL_USER_BLOB_H

#include <assert.h>
#include <kernel/tee_blob_manager.h>
#include <kernel/dfc_blob_common.h>
#include <kernel/thread.h>
#include <mm/tee_mm.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>


struct user_blob_ctx {
	uaddr_t entry_func;
	bool is_32bit;
	struct tee_blob_session_head open_sessions;
	// other stuff cryp_state/objects can be added here
	
	tee_mm_entry_t *mm; /* secure world memory (mostly blob code/data?) */
	uint32_t base_addr; /* base addr, XXX: should this be passed from normal world? */
	uint32_t context;

	struct blob_info blobinfo; /* this contains the info about the .secure_code
							  section that will be passed from normal world */

	struct tee_mmu_info *mmu; /*saved MMU information (ddr)*/

#if defined(CFG_WITH_VFP)
	struct thread_user_vfp_state vfp;
#endif
	struct tee_blob_ctx ctx;
};

TEE_Result user_blob_load(TEE_ErrorOrigin *err,
		struct tee_blob_session *session,
		enum utee_entry_func func,
		uint32_t cmd,
		struct tee_blob_param *param,
		struct blob_info *blob);

#endif
