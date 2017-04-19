
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


// this list contains the current blob sessions (processes)
TAILQ_HEAD(tee_blob_session_head, tee_blob_session);


struct tee_blob_ctx {
	uint64_t yolo;
};

struct tee_blob_param {
	uint32_t types;
	TEE_Param params[TEE_NUM_PARAMS];
	uint32_t param_attr[TEE_NUM_PARAMS];
};

struct tee_blob_session {
	TAILQ_ENTRY(tee_blob_session) link;
	TAILQ_ENTRY(tee_blob_session) link_tsd;
	struct tee_blob_ctx *ctx; /* blob context aka DFC_PROCESS */
	struct condvar lock_cv; /* condvar used to wait for lock */
	int lock_thread; /* thread holding the lock */
	bool unlink; /* session to be unlinked? */
};

struct tee_blob_session *tee_blob_get_session(uint32_t id, bool exclusive,
			struct tee_blob_session_head *open_sessions);

TEE_Result tee_blob_open_session(TEE_ErrorOrigin *err __unused,
				struct tee_blob_session **sess,
				struct tee_blob_session_head *open_sessions,
				const TEE_Identity *clnt_id __unused,
				uint32_t cancel_req_to __unused,
				struct tee_blob_param *param __unused);

TEE_Result tee_blob_close_session(struct tee_blob_session *sess __unused,
										const TEE_Identity *clnt_id __unused);

#endif
