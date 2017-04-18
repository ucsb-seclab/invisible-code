
#ifndef TEE_BLOB_MANAGER_H
#define TEE_BLOB_MANAGER_H

#include <types_ext.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <utee_types.h>
#include <kernel/tee_common.h>
#include <kernel/mutex.h>
#include <tee_api_types.h>
#include <user_ta_header.h>


struct tee_blob_ctx {
	uint64_t yolo;
};

struct tee_blob_session {
	struct tee_blob_ctx *ctx; /* blob context aka DFC_PROCESS */
};


TEE_Result tee_blob_open_session(TEE_ErrorOrigin *err __unused);

TEE_Result tee_blob_close_session(struct tee_blob_session *sess __unused,
										const TEE_Identity *clnt_id __unused);

#endif
