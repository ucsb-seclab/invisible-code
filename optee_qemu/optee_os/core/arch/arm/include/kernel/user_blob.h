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


TEE_Result blob_load(struct blob_info *blob, struct tee_blob_session *session);


#endif
