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

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <hello_blob_ta.h>

__attribute__((section(".secure_code"))) int foo()
{
	return 1;
}


int main(int argc, char *argv[])
{

	// small thumb shellcode that executes exit(0)
	// kstool thumb "$(echo "eor r0,r0\nldr r7, =0x1\nswi 0")" 0
	// unsigned char shellcode[] = {0x80, 0xea, 0x00, 0x00, 0x00, 0x4f, 0x00, 0xdf, 0x01, 0x00, 0x00, 0x00};
	// kstool thumb "$(echo "ldr r3, =0x133760A7\n blx r3\n eor r0,r0\nldr r7, =0x1\nswi 0")" 0
	// 02 4b 98 47 80 ea 00 00 01 4f 00 df a7 60 37 13 01 00 00 00
	unsigned char shellcode[] = {0x02, 0x4b, 0x98, 0x47, 0x80, 0xea, 0x00, 0x00, 0x01, 0x4f, 0x00, 0xdf, 0xa7, 0x60, 0x37, 0x13, 0x01, 0x00, 0x00, 0x00};

	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	//TEEC_Operation op;
	TEEC_UUID uuid = TA_HELLO_BLOB_UUID;
	uint32_t err_origin;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/*
	 * Open a session to the "hello world" TA, the TA will print "hello
	 * world!" in the log when the session is created.
	 */
	printf("(Host ta) Loading blob from %p, size %u\n", foo, sizeof(foo));
	res = TEEC_OpenBlobSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin, (void*)foo, sizeof(foo));
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	printf("foo function returned 0x%X", foo());

	/*
	 * Execute a function in the TA by invoking it, in this case
	 * we're incrementing a number.
	 *
	 * The value of command ID part and how the parameters are
	 * interpreted is part of the interface provided by the TA.
	 */

	/* Clear the TEEC_Operation struct */
	//memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	//op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
	//				 TEEC_NONE, TEEC_NONE);
	//op.params[0].value.a = 42;

	/*
	 * TA_HELLO_WORLD_CMD_INC_VALUE is the actual function in the TA to be
	 * called.
	 */
	//printf("Invoking TA to increment %d\n", op.params[0].value.a);
	//res = TEEC_InvokeCommand(&sess, TA_HELLO_WORLD_CMD_INC_VALUE, &op,
	//			 &err_origin);
	//if (res != TEEC_SUCCESS)
	//	errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
	//		res, err_origin);
	//printf("TA incremented value to %d\n", op.params[0].value.a);

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseBlobSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
