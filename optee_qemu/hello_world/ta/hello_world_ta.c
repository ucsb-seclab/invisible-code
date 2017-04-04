/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define STR_TRACE_USER_TA "HELLO_WORLD"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "hello_world_ta.h"

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");
	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	DMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	DMSG("Goodbye!\n");
}


static TEE_Result inc_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	/* const char *test = "ABCABCABC\n\0"; */
	uint32_t ret_sys = 0xDEd;
	uint32_t i=10;
	DMSG("has been called");
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("Got value: %u from NW", params[0].value.a);
	params[0].value.a++;
	DMSG("Increase value to: %u", params[0].value.a);

	asm volatile(
		     "mov r0, #0\n\t"
		     "mov r7, #132\n\t" /* getpgid */
		     "svc #0\n\t"
		     "mov %[res], r0\n\t": [res] "=r" (ret_sys)::"r6", "r7");


	
	DMSG("DRM CODE: Syscall 49 is going to be executed");
	while(i>0) {
		ret_sys = 0xDEd;
		DMSG("%d, BEFORE SYSCALL:%x\n", ret_sys, i);
		asm volatile(
				 "mov r6, #1\n\t"
				 "mov r7, #49\n\t" /* Random syscall, iirc it should be geteuid */
				 "svc #0\n\t"
				 "mov %[res], r0\n\t": [res] "=r" (ret_sys)::"r6", "r7");
			 
		//DMSG("AFTER SYSCALL:%x BEFORE ASSIGNING\n", ret_sys);
		//asm volatile("mov %[res], R0": [res] "=r" (ret_sys)::);
		DMSG("%d, AFTER SYSCALL:%d\n", ret_sys, i);
		i--;
		
	}
	/* asm volatile( */
	/* 	     "mov r0, #1\n\t"  */
	/* 	     "mov r1, %[buf]\n\t" */
	/* 	     "mov r2, #11\n\t" */
	/* 	     "mov r7, #4\n\t" */
	/* 	     "svc #0" : : [buf] "r" (test) : "r0", "r1", "r2", "r7", "memory" */
	/* 	     ); */
	
	
	DMSG("[+] I'm back after syscall execution in normal world :)");
	//asm volatile("mov R0, %[ret]": :[ret] "r" (TEE_SUCCESS):);
	DMSG("AFTER FANCY\n");
	return TEE_SUCCESS;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_HELLO_WORLD_CMD_INC_VALUE:
		inc_value(param_types, params);
		DMSG("In THE INVOKE\n");
		return TEE_SUCCESS;
#if 0
	case TA_HELLO_WORLD_CMD_XXX:
		return ...
		break;
	case TA_HELLO_WORLD_CMD_YYY:
		return ...
		break;
	case TA_HELLO_WORLD_CMD_ZZZ:
		return ...
		break;
	...
#endif
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
