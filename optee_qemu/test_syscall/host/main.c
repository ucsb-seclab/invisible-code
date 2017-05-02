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
#include <invisible_code_test_syscall.h>

/**
 *  \brief Setup registers to perform syscall
 *
 *  This function sets the values of the registers in a TEEC_Operation struct
 *  used to invoke a function in a TA. This is done to test syscalls execution
 *
 *  \param op a pointer to the TEEC_Operation struct to be filled
 *  \param r7 value of r7 register, it is the System Call number
 *  \param r0 value of r0 register
 *  \param r1 value of r1 register
 *  \param r2 value of r2 register
 *  \param r3 value of r3 register
 *  \param r4 value of r4 register
 *  \return return void
 */
void setup_syscall(TEEC_Operation *op, uint32_t r7, uint32_t r0, uint32_t r1, uint32_t r2, uint32_t r3, uint32_t r4){
  op->params[0].value.a = r7;
  op->params[0].value.b = r0;
  op->params[1].value.a = r1;
  op->params[1].value.b = r2;
  op->params[2].value.a = r3;
  op->params[2].value.b = r4;
}

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_INVISIBLE_CODE_TEST_SYSCALL_UUID;
	uint32_t err_origin;

	const char *test = "DOLPHINS!\n";

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/*
	 * Open a session to the "test_syscall" TA, the TA will print
	 * "Test syscall TA" in the log when the session is created.
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	/*
	 * Execute a function in the TA by invoking it, in this case
	 * we're incrementing a number.
	 *
	 * The value of command ID part and how the parameters are
	 * interpreted is part of the interface provided by the TA.
	 */

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. The first three arguments are used to 
	 * store the value of the registers r0, r1, r2, r3, r4 and r7.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT,
					 TEEC_VALUE_INOUT, TEEC_NONE);
	

	/*
	 * We are going to set all the registers in order to perform the syscall.
	 * In this case we are testing the write syscall
	 */
	setup_syscall(&op, 4, 1, (uint32_t)test, 11, 0, 0);
	
	printf("Invoking TA to test syscall %d\n", op.params[0].value.a);
	
	/*
	 * TA_INVISIBLE_CODE_TEST_SYSCALL is the actual function in the TA to be
	 * called.
	 */
	res = TEEC_InvokeCommand(&sess, TA_INVISIBLE_CODE_TEST_SYSCALL, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	printf("[+] Normal world: Result of the syscall execution %d\n", op.params[0].value.b);

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
