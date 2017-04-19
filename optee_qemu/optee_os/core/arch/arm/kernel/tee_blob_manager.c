#include <types_ext.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arm.h>
#include <assert.h>
#include <kernel/mutex.h>
#include <kernel/tee_blob_manager.h>
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
				struct tee_blob_param *param __unused)
{

	TEE_Result res;
	struct tee_blob_session *s = NULL;

	res = tee_blob_init_session(err, open_sessions, &s);

	if (res != TEE_SUCCESS) {
		DMSG("blob init session failed 0x%x", res);
		return res;
	}

	res = blob_load((void*)&res);
	DMSG("DFC: opening blob session");
	
	*sess = s;

	return res;

}


TEE_Result tee_blob_close_session(struct tee_blob_session *sess,
										const TEE_Identity *clnt_id __unused)
{

	DMSG("DFC: closing blob session (0x%" PRIxVA ")",  (vaddr_t)sess);

	free(sess);

	return TEE_SUCCESS;
}

