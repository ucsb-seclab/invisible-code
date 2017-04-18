#include <types_ext.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arm.h>
#include <assert.h>

#include <kernel/tee_blob_manager.h>
#include <tee_api_types.h>
#include <trace.h>
#include <utee_types.h>


TEE_Result tee_blob_open_session(TEE_ErrorOrigin *err __unused)
{

	DMSG("DFC: opening blob session");
	return TEE_SUCCESS;
}


TEE_Result tee_blob_close_session(struct tee_ta_session *sess __unused,
						struct tee_ta_session_head *open_sessions __unused,
										const TEE_Identity *clnt_id __unused)
{
	DMSG("DFC: opening blob session");
	return TEE_SUCCESS;
}

