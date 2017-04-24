#include <types_ext.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arm.h>
#include <assert.h>
#include <kernel/mutex.h>
#include <kernel/tee_blob_manager.h>
#include <kernel/dfc_blob_common.h>
#include <kernel/user_blob.h>
#include <tee_api_types.h>
#include <trace.h>
#include <utee_types.h>

struct mutex tee_blob_mutex = MUTEX_INITIALIZER;


static TEE_Result tee_blob_init_session(
		TEE_ErrorOrigin *err __unused,
		struct tee_blob_session_head *open_sessions,
		struct tee_blob_session **sess)
{
	struct tee_blob_session *s = calloc(1, sizeof(struct tee_blob_session));

	if(!s)
		return TEE_ERROR_OUT_OF_MEMORY;

	condvar_init(&s->lock_cv);
	s->lock_thread = THREAD_ID_INVALID;


	mutex_lock(&tee_blob_mutex);
	TAILQ_INSERT_TAIL(open_sessions, s, link);

	*sess = s;
	mutex_unlock(&tee_blob_mutex);
	return TEE_SUCCESS;
}


static struct tee_blob_session *find_session(uint32_t id,
		struct tee_blob_session_head *open_sessions)
{
	struct tee_blob_session *s;

	TAILQ_FOREACH(s, open_sessions, link) {
		if ((vaddr_t)s == id)
			return s;
	}
	return NULL;
}

struct tee_blob_session *tee_blob_get_session(uint32_t id, bool exclusive,
			struct tee_blob_session_head *open_sessions)
{
	struct tee_blob_session *s = NULL;

	mutex_lock(&tee_blob_mutex);

	while(true) {
		s = find_session(id, open_sessions);

		if (!s)
			break;
		if (s->unlink) {
			s = NULL;
			break;
		}
		if(!exclusive)
			break;

		assert(s->lock_thread != thread_get_id());

		while(s->lock_thread != THREAD_ID_INVALID && !s->unlink)
			condvar_wait(&s->lock_cv, &tee_blob_mutex);

		if (s->unlink) {
			s = NULL;
			break;
		}

		s->lock_thread = thread_get_id();
		break;
	}

	mutex_unlock(&tee_blob_mutex);
	return s;
}

TEE_Result tee_blob_open_session(TEE_ErrorOrigin *err __unused,
				struct tee_blob_session **sess,
				struct tee_blob_session_head *open_sessions,
				const TEE_Identity *clnt_id __unused,
				uint32_t cancel_req_to __unused,
				struct tee_blob_param *param __unused,
				struct blob_info *blob)
{

	TEE_Result res;
	struct tee_blob_session *s = NULL;

	DMSG("DFC: opening blob session\n");
	res = tee_blob_init_session(err, open_sessions, &s);

	if (res != TEE_SUCCESS) {
		DMSG("blob init session failed 0x%x\n", res);
		return res;
	}

	res = blob_load((void*)blob, *sess);
	// blob_start?

	if(res != TEE_SUCCESS){
		tee_blob_close_session(s, open_sessions, clnt_id);
		return res;
	}
	
	*sess = s;

	return res;

}

static void tee_blob_unlink_session(struct tee_blob_session *s,
			struct tee_blob_session_head *open_sessions)
{
	mutex_lock(&tee_blob_mutex);

	//assert(s->ref_count >= 1);
	assert(s->lock_thread == thread_get_id());
	assert(!s->unlink);

	s->unlink = true;
	condvar_broadcast(&s->lock_cv);

	//while (s->ref_count != 1)
	//	condvar_wait(&s->refc_cv, &tee_ta_mutex);

	TAILQ_REMOVE(open_sessions, s, link);

	mutex_unlock(&tee_blob_mutex);
}

TEE_Result tee_blob_close_session(struct tee_blob_session *csess,
				struct tee_blob_session_head *open_sessions,
				const TEE_Identity *clnt_id __unused)
{

	struct tee_blob_session *sess;

	DMSG("DFC: closing blob session (0x%" PRIxVA ")",  (vaddr_t)csess);

	if(!csess)
		return TEE_ERROR_ITEM_NOT_FOUND;

	sess = tee_blob_get_session((vaddr_t)csess, true, open_sessions);

	if (!sess) {
		EMSG("session 0x%" PRIxVA " to be removed is not found",
								(vaddr_t)csess);
				return TEE_ERROR_ITEM_NOT_FOUND;
	}

	tee_blob_unlink_session(sess, open_sessions);
	free(sess);

	return TEE_SUCCESS;
}

