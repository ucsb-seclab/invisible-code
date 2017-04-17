#include <types_ext.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arm.h>
#include <assert.h>

#include <tee_blob_manager.h>
#include <tee_api_types.h>
#include <trace.h>
#include <utee_types.h>


TEE_Result tee_blob_open_session(TEE_ErrorOrigin *err __unused,

		)
{

	DMESG("DFC: opening blob session");
	return TEE_SUCCESS;
}
