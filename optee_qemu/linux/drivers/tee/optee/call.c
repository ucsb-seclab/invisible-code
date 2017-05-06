/*
 * Copyright (c) 2015, Linaro Limited
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/arm-smccc.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/tee_drv.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include "optee_private.h"
#include "optee_smc.h"
#include "drm_code/drm_utils.h"

struct optee_call_waiter {
	struct list_head list_node;
	struct completion c;
	bool completed;
};

static void optee_cq_wait_init(struct optee_call_queue *cq,
			       struct optee_call_waiter *w)
{
	mutex_lock(&cq->mutex);

	/*
	 * We add ourselves to the queue, but we don't wait. This
	 * guarantees that we don't lose a completion if secure world
	 * returns busy and another thread just exited and try to complete
	 * someone.
	 */
	w->completed = false;
	init_completion(&w->c);
	list_add_tail(&w->list_node, &cq->waiters);

	mutex_unlock(&cq->mutex);
}

static void optee_cq_wait_for_completion(struct optee_call_queue *cq,
					 struct optee_call_waiter *w)
{
	wait_for_completion(&w->c);

	mutex_lock(&cq->mutex);

	/* Move to end of list to get out of the way for other waiters */
	list_del(&w->list_node);
	w->completed = false;
	reinit_completion(&w->c);
	list_add_tail(&w->list_node, &cq->waiters);

	mutex_unlock(&cq->mutex);
}

static void optee_cq_complete_one(struct optee_call_queue *cq)
{
	struct optee_call_waiter *w;

	list_for_each_entry(w, &cq->waiters, list_node) {
		if (!w->completed) {
			complete(&w->c);
			w->completed = true;
			break;
		}
	}
}

static void optee_cq_wait_final(struct optee_call_queue *cq,
				struct optee_call_waiter *w)
{
	mutex_lock(&cq->mutex);

	/* Get out of the list */
	list_del(&w->list_node);

	optee_cq_complete_one(cq);
	/*
	 * If we're completed we've got a completion that some other task
	 * could have used instead.
	 */
	if (w->completed)
		optee_cq_complete_one(cq);

	mutex_unlock(&cq->mutex);
}

/* Requires the filpstate mutex to be held */
static struct optee_session *find_session(struct optee_context_data *ctxdata,
					  u32 session_id)
{
	struct optee_session *sess;

	list_for_each_entry(sess, &ctxdata->sess_list, list_node)
		if (sess->session_id == session_id)
			return sess;

	return NULL;
}

/**
 * optee_do_call_with_arg() - Do an SMC to OP-TEE in secure world
 * @ctx:	calling context
 * @parg:	physical address of message to pass to secure world
 *
 * Does and SMC to OP-TEE in secure world and handles eventual resulting
 * Remote Procedure Calls (RPC) from OP-TEE.
 *
 * Returns return code from secure world, 0 is OK
 */
u32 optee_do_call_with_arg(struct tee_context *ctx, phys_addr_t parg)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	struct optee_call_waiter w;
	struct optee_rpc_param param = { };
	u32 ret;

	u32 break_loop = 0;

	param.a0 = OPTEE_SMC_CALL_WITH_ARG;
	reg_pair_from_64(&param.a1, &param.a2, parg);
	/* Initialize waiter */
	optee_cq_wait_init(&optee->call_queue, &w);
	while (true) {
	  struct arm_smccc_res res;

	  
	  printk("Entering into secure\n");
	  printk("[+] Address of invoke fn %x\n", optee->invoke_fn);
	  
		optee->invoke_fn(param.a0, param.a1, param.a2, param.a3,
				 param.a4, param.a5, param.a6, param.a7,
				 &res);
	  printk("Exiting from secure\n");
		
		if (res.a0 == OPTEE_SMC_RETURN_ETHREAD_LIMIT) {
			/*
			 * Out of threads in secure world, wait for a thread
			 * become available.
			 */
			optee_cq_wait_for_completion(&optee->call_queue, &w);
		} else if (OPTEE_SMC_RETURN_IS_RPC(res.a0)) {
			param.a0 = res.a0;
			param.a1 = res.a1;
			param.a2 = res.a2;
			param.a3 = res.a3;
			break_loop = optee_handle_rpc(ctx, &param);

			if (break_loop == 1) {
			  printk("[!] Breaking the loop\n");
			  break;
			}

		} else {
		  printk("WE ARE IN THE ELSE\n");
			ret = res.a0;
			break;
		}
	}

	/*
	 * We're done with our thread in secure world, if there's any
	 * thread waiters wake up one.
	 */
	optee_cq_wait_final(&optee->call_queue, &w);

	return ret;
}



u32 optee_do_call_from_abort(unsigned long p0, unsigned long p1, unsigned long p2,
				unsigned long p3, unsigned long p4, unsigned long p5,
				unsigned long p6, unsigned long p7)
{

    struct tee_context *ctx = (struct tee_context *)current->optee_ctx;
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	struct optee_call_waiter w;
	struct optee_rpc_param param = { };
	u32 ret;

	u32 break_loop = 0;

	//param.a0 = OPTEE_SMC_CALL_WITH_ARG;
	//reg_pair_from_64(&param.a1, &param.a2, parg);
	/* Initialize waiter */
	param.a0 = p0;
	param.a1 = p1;
	param.a2 = p2;
	param.a3 = p3;
	param.a4 = p4;
	param.a5 = p5;
	param.a6 = p6;
	param.a7 = p7;
	
	optee_cq_wait_init(&optee->call_queue, &w);
	while (true) {
	  struct arm_smccc_res res;

	  
	  printk("Entering into secure new\n");
	  printk("[+] Address of invoke fn %x\n", optee->invoke_fn);
	  
		optee->invoke_fn(param.a0, param.a1, param.a2, param.a3,
				 param.a4, param.a5, param.a6, param.a7,
				 &res);
	  printk("Exiting from secure new\n");
		
		if (res.a0 == OPTEE_SMC_RETURN_ETHREAD_LIMIT) {
			/*
			 * Out of threads in secure world, wait for a thread
			 * become available.
			 */
			optee_cq_wait_for_completion(&optee->call_queue, &w);
		} else if (OPTEE_SMC_RETURN_IS_RPC(res.a0)) {
			param.a0 = res.a0;
			param.a1 = res.a1;
			param.a2 = res.a2;
			param.a3 = res.a3;
			break_loop = optee_handle_rpc(ctx, &param);

			if (break_loop == 1) {
			  printk("[!] Breaking the loop new\n");
			  break;
			}

		} else {
		  printk("WE ARE IN THE ELSE new\n");
			ret = res.a0;
			break;
		}
	}

	/*
	 * We're done with our thread in secure world, if there's any
	 * thread waiters wake up one.
	 */
	optee_cq_wait_final(&optee->call_queue, &w);

	return ret;
}

EXPORT_SYMBOL(optee_do_call_from_abort);

static struct tee_shm *get_msg_arg(struct tee_context *ctx, size_t num_params,
				   struct optee_msg_arg **msg_arg,
				   phys_addr_t *msg_parg)
{
	int rc;
	struct tee_shm *shm;
	struct optee_msg_arg *ma;

	shm = tee_shm_alloc(ctx, OPTEE_MSG_GET_ARG_SIZE(num_params),
			    TEE_SHM_MAPPED);
	if (IS_ERR(shm))
		return shm;

	ma = tee_shm_get_va(shm, 0);
	if (IS_ERR(ma)) {
		rc = PTR_ERR(ma);
		goto out;
	}

	rc = tee_shm_get_pa(shm, 0, msg_parg);
	if (rc)
		goto out;

	memset(ma, 0, OPTEE_MSG_GET_ARG_SIZE(num_params));
	ma->num_params = num_params;
	*msg_arg = ma;
out:
	if (rc) {
		tee_shm_free(shm);
		return ERR_PTR(rc);
	}

	return shm;
}

int optee_open_session(struct tee_context *ctx,
		       struct tee_ioctl_open_session_arg *arg,
		       struct tee_param *param)
{
	struct optee_context_data *ctxdata = ctx->data;
	int rc;
	struct tee_shm *shm;
	struct optee_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	struct optee_msg_param *msg_param;
	struct optee_session *sess = NULL;

	/* +2 for the meta parameters added below */
	shm = get_msg_arg(ctx, arg->num_params + 2, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = OPTEE_MSG_CMD_OPEN_SESSION;
	msg_arg->cancel_id = arg->cancel_id;
	msg_param = OPTEE_MSG_GET_PARAMS(msg_arg);

	/*
	 * Initialize and add the meta parameters needed when opening a
	 * session.
	 */
	msg_param[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT |
			    OPTEE_MSG_ATTR_META;
	msg_param[1].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT |
			    OPTEE_MSG_ATTR_META;
	memcpy(&msg_param[0].u.value, arg->uuid, sizeof(arg->uuid));
	memcpy(&msg_param[1].u.value, arg->uuid, sizeof(arg->clnt_uuid));
	msg_param[1].u.value.c = arg->clnt_login;

	rc = optee_to_msg_param(msg_param + 2, arg->num_params, param);
	if (rc)
		goto out;

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess) {
		rc = -ENOMEM;
		goto out;
	}

	if (optee_do_call_with_arg(ctx, msg_parg)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	if (msg_arg->ret == TEEC_SUCCESS) {
		/* A new session has been created, add it to the list. */
		sess->session_id = msg_arg->session;
		mutex_lock(&ctxdata->mutex);
		list_add(&sess->list_node, &ctxdata->sess_list);
		mutex_unlock(&ctxdata->mutex);
	} else {
		kfree(sess);
	}

	if (optee_from_msg_param(param, arg->num_params, msg_param + 2)) {
		arg->ret = TEEC_ERROR_COMMUNICATION;
		arg->ret_origin = TEEC_ORIGIN_COMMS;
		/* Close session again to avoid leakage */
		optee_close_session(ctx, msg_arg->session);
	} else {
		arg->session = msg_arg->session;
		arg->ret = msg_arg->ret;
		arg->ret_origin = msg_arg->ret_origin;
	}
out:
	tee_shm_free(shm);

	return rc;
}

__maybe_unused static void hexDump (const char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printk ("%s:\n", desc);

    if (len == 0) {
        printk("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printk("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printk ("  %s\n", buff);

            // Output the offset.
            printk ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printk (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printk ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printk ("  %s\n", buff);
}

int optee_open_blob_session(struct tee_context *ctx,
		       struct tee_ioctl_open_blob_session_arg *arg,
		       struct tee_param *param)
{
	struct optee_context_data *ctxdata = ctx->data;
	int rc;
	struct tee_shm *shm = NULL;
	struct optee_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	struct optee_msg_param *msg_param;
	struct optee_session *sess = NULL;
	unsigned long p_size, pa_start;

	struct tee_ioctl_open_blob_session_arg carg;

	carg = *arg;
	printk("Loading blob from parg %p: VA %llx, PA %llx, size %llx\n", arg, carg.blob_va, carg.blob_pa, carg.blob_size);
	printk("[x] optee_open_blob_session: pa=%llx, size=%llx, va=%llx\n", arg->blob_pa, arg->blob_size, arg->blob_va);
	/* +4 for the meta parameters added below */
	shm = get_msg_arg(ctx, arg->num_params + 4, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = DFC_MSG_CMD_OPEN_SESSION;
	msg_arg->cancel_id = arg->cancel_id;
	msg_param = OPTEE_MSG_GET_PARAMS(msg_arg);

	/*
	 * Initialize and add the meta parameters needed when opening a
	 * session.
	 */
	msg_param[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT |
			    OPTEE_MSG_ATTR_META;
	msg_param[1].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT |
			    OPTEE_MSG_ATTR_META;
	memcpy(&msg_param[0].u.value, arg->uuid, sizeof(arg->uuid));
	memcpy(&msg_param[1].u.value, arg->uuid, sizeof(arg->clnt_uuid));
	msg_param[1].u.value.c = arg->clnt_login;

	// the 3rd param is our blob paddr/size
	// TODO: change this also to VALUE_OUTPUT to push back the blob pa
	// from secure world and modify the page table in normal world
	msg_param[2].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INOUT |
				OPTEE_MSG_ATTR_META;
	msg_param[2].u.value.a = arg->blob_pa;
	msg_param[2].u.value.b = arg->blob_size;
	msg_param[2].u.value.c = arg->blob_va;
	printk("[y] optee_open_blob_session: pa=%llx, size=%llx, va=%llx\n", arg->blob_pa, arg->blob_size, arg->blob_va);

	// 4th param is the memory map shared memory (with num of entries)
	msg_param[3].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT |
				OPTEE_MSG_ATTR_META;
	msg_param[3].u.value.a = arg->mm_pa;
	msg_param[3].u.value.b = arg->mm_numofentries;
	msg_param[3].u.value.c = 0;
	rc = optee_to_msg_param(msg_param + 4, arg->num_params, param);
	if (rc)
		goto out;

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess) {
		rc = -ENOMEM;
		goto out;
	}
	
	hexDump("msg_params: ", msg_param, sizeof(struct optee_msg_param)*4);

	if (optee_do_call_with_arg(ctx, msg_parg)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	if (msg_arg->ret == TEEC_SUCCESS) {
		/* A new session has been created, add it to the list. */
		sess->session_id = msg_arg->session;
		mutex_lock(&ctxdata->mutex);
		list_add(&sess->list_node, &ctxdata->sess_list);
		mutex_unlock(&ctxdata->mutex);

		/* now since the session has been created correctly we
		 * can add the physical page of the blob in SW and
		 * add it to the mapping of the process in NW */
		pa_start = msg_param[2].u.value.a;
		pa_start = 0x0e100000;
		printk("[x] optee_open_blob_session: PA %lx, VA %llx, SIZE (PAGE ROUNDED) %lx\n", pa_start, arg->blob_va, PAGE_SIZE);
		//p_size = msg_param[3].u.value.b;
		p_size = arg->blob_size;
		rc = add_secure_mem(current, arg->blob_va, pa_start, PAGE_SIZE);
		if (rc != 0)
			pr_err("error calling add_secure_mem %x", rc);
	} else {
		kfree(sess);
	}

	if (optee_from_msg_param(param, arg->num_params, msg_param + 4)) {
		arg->ret = TEEC_ERROR_COMMUNICATION;
		arg->ret_origin = TEEC_ORIGIN_COMMS;
		/* Close session again to avoid leakage */
		optee_close_blob_session(ctx, msg_arg->session);
	} else {
		arg->session = msg_arg->session;
		arg->ret = msg_arg->ret;
		arg->ret_origin = msg_arg->ret_origin;
	}

out:
	if(shm)
		tee_shm_free(shm);

	return rc;
}

int optee_close_blob_session(struct tee_context *ctx, u32 session)
{
	struct optee_context_data *ctxdata = ctx->data;
	struct tee_shm *shm;
	struct optee_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	struct optee_session *sess;

	/* Check that the session is valid and remove it from the list */
	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, session);
	if (sess)
		list_del(&sess->list_node);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;
	kfree(sess);

	shm = get_msg_arg(ctx, 0, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = DFC_MSG_CMD_CLOSE_SESSION;
	msg_arg->session = session;
	optee_do_call_with_arg(ctx, msg_parg);

	tee_shm_free(shm);
	return 0;
}

int optee_close_session(struct tee_context *ctx, u32 session)
{
	struct optee_context_data *ctxdata = ctx->data;
	struct tee_shm *shm;
	struct optee_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	struct optee_session *sess;

	/* Check that the session is valid and remove it from the list */
	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, session);
	if (sess)
		list_del(&sess->list_node);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;
	kfree(sess);

	shm = get_msg_arg(ctx, 0, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = OPTEE_MSG_CMD_CLOSE_SESSION;
	msg_arg->session = session;
	optee_do_call_with_arg(ctx, msg_parg);

	tee_shm_free(shm);
	return 0;
}

int optee_invoke_func(struct tee_context *ctx, struct tee_ioctl_invoke_arg *arg,
		      struct tee_param *param)
{
	struct optee_context_data *ctxdata = ctx->data;
	struct tee_shm *shm;
	struct optee_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	struct optee_msg_param *msg_param;
	struct optee_session *sess;
	int rc;

	/* Check that the session is valid */
	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, arg->session);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;

	shm = get_msg_arg(ctx, arg->num_params, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);
	msg_arg->cmd = OPTEE_MSG_CMD_INVOKE_COMMAND;
	msg_arg->func = arg->func;
	msg_arg->session = arg->session;
	msg_arg->cancel_id = arg->cancel_id;
	msg_param = OPTEE_MSG_GET_PARAMS(msg_arg);

	rc = optee_to_msg_param(msg_param, arg->num_params, param);
	if (rc)
		goto out;

	if (optee_do_call_with_arg(ctx, msg_parg)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	if (optee_from_msg_param(param, arg->num_params, msg_param)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	arg->ret = msg_arg->ret;
	arg->ret_origin = msg_arg->ret_origin;
out:
	tee_shm_free(shm);
	return rc;
}

int optee_cancel_req(struct tee_context *ctx, u32 cancel_id, u32 session)
{
	struct optee_context_data *ctxdata = ctx->data;
	struct tee_shm *shm;
	struct optee_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	struct optee_session *sess;

	/* Check that the session is valid */
	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, session);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;

	shm = get_msg_arg(ctx, 0, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = OPTEE_MSG_CMD_CANCEL;
	msg_arg->session = session;
	msg_arg->cancel_id = cancel_id;
	optee_do_call_with_arg(ctx, msg_parg);

	tee_shm_free(shm);
	return 0;
}

/**
 * optee_enable_shm_cache() - Enables caching of some shared memory allocation
 *			      in OP-TEE
 * @optee:	main service struct
 */
void optee_enable_shm_cache(struct optee *optee)
{
	struct optee_call_waiter w;

	/* We need to retry until secure world isn't busy. */
	optee_cq_wait_init(&optee->call_queue, &w);
	while (true) {
		struct arm_smccc_res res;

		optee->invoke_fn(OPTEE_SMC_ENABLE_SHM_CACHE, 0, 0, 0, 0, 0, 0,
				 0, &res);
		if (res.a0 == OPTEE_SMC_RETURN_OK)
			break;
		optee_cq_wait_for_completion(&optee->call_queue, &w);
	}
	optee_cq_wait_final(&optee->call_queue, &w);
}

/**
 * optee_enable_shm_cache() - Disables caching of some shared memory allocation
 *			      in OP-TEE
 * @optee:	main service struct
 */
void optee_disable_shm_cache(struct optee *optee)
{
	struct optee_call_waiter w;

	/* We need to retry until secure world isn't busy. */
	optee_cq_wait_init(&optee->call_queue, &w);
	while (true) {
		union {
			struct arm_smccc_res smccc;
			struct optee_smc_disable_shm_cache_result result;
		} res;

		optee->invoke_fn(OPTEE_SMC_DISABLE_SHM_CACHE, 0, 0, 0, 0, 0, 0,
				 0, &res.smccc);
		if (res.result.status == OPTEE_SMC_RETURN_ENOTAVAIL)
			break; /* All shm's freed */
		if (res.result.status == OPTEE_SMC_RETURN_OK) {
			struct tee_shm *shm;

			shm = reg_pair_to_ptr(res.result.shm_upper32,
					      res.result.shm_lower32);
			tee_shm_free(shm);
		} else {
			optee_cq_wait_for_completion(&optee->call_queue, &w);
		}
	}
	optee_cq_wait_final(&optee->call_queue, &w);
}
