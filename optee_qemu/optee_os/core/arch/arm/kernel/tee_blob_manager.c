#include <types_ext.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arm.h>
#include <assert.h>
#include <kernel/tee_blob_manager.h>
#include <kernel/user_blob.h>
#include <tee_api_types.h>
#include <trace.h>
#include <utee_types.h>


TEE_Result tee_blob_open_session(TEE_ErrorOrigin *err __unused)
{

	TEE_Result res;

	res = blob_load();
	DMSG("DFC: opening blob session");
	return res;
}


TEE_Result tee_blob_close_session(struct tee_blob_session *sess __unused,
										const TEE_Identity *clnt_id __unused)
{
	DMSG("DFC: closing blob session");
	return TEE_SUCCESS;
}

