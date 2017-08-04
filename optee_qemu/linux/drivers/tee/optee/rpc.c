/*
 * Copyright (c) 2015-2016, Linaro Limited
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
#include <linux/device.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/tee_drv.h>
#include "optee_private.h"
#include "../tee_private.h"
#include "optee_smc.h"
#include "drm_code/drm_utils.h"

// INVISIBLE CODE
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <asm/syscall.h>
#include <asm/ptrace.h> // For pt_regs... I can copy the definition here
// to avoid this include
#include <linux/sched.h>

struct wq_entry {
	struct list_head link;
	struct completion c;
	u32 key;
};

void optee_wait_queue_init(struct optee_wait_queue *priv)
{
	mutex_init(&priv->mu);
	INIT_LIST_HEAD(&priv->db);
}

void optee_wait_queue_exit(struct optee_wait_queue *priv)
{
	mutex_destroy(&priv->mu);
}

static void handle_rpc_func_cmd_get_time(struct optee_msg_arg *arg)
{
	struct optee_msg_param *params;
	struct timespec64 ts;

	if (arg->num_params != 1)
		goto bad;
	params = OPTEE_MSG_GET_PARAMS(arg);
	if ((params->attr & OPTEE_MSG_ATTR_TYPE_MASK) !=
	    OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT)
		goto bad;

	getnstimeofday64(&ts);
	params->u.value.a = ts.tv_sec;
	params->u.value.b = ts.tv_nsec;

	arg->ret = TEEC_SUCCESS;
	return;
 bad:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static struct wq_entry *wq_entry_get(struct optee_wait_queue *wq, u32 key)
{
	struct wq_entry *w;

	mutex_lock(&wq->mu);

	list_for_each_entry(w, &wq->db, link)
		if (w->key == key)
			goto out;

	w = kmalloc(sizeof(*w), GFP_KERNEL);
	if (w) {
		init_completion(&w->c);
		w->key = key;
		list_add_tail(&w->link, &wq->db);
	}
 out:
	mutex_unlock(&wq->mu);
	return w;
}

static void wq_sleep(struct optee_wait_queue *wq, u32 key)
{
	struct wq_entry *w = wq_entry_get(wq, key);

	if (w) {
		wait_for_completion(&w->c);
		mutex_lock(&wq->mu);
		list_del(&w->link);
		mutex_unlock(&wq->mu);
		kfree(w);
	}
}

static void wq_wakeup(struct optee_wait_queue *wq, u32 key)
{
	struct wq_entry *w = wq_entry_get(wq, key);

	if (w)
		complete(&w->c);
}

static void handle_rpc_func_cmd_wq(struct optee *optee,
				   struct optee_msg_arg *arg)
{
	struct optee_msg_param *params;

	if (arg->num_params != 1)
		goto bad;

	params = OPTEE_MSG_GET_PARAMS(arg);
	if ((params->attr & OPTEE_MSG_ATTR_TYPE_MASK) !=
	    OPTEE_MSG_ATTR_TYPE_VALUE_INPUT)
		goto bad;

	switch (params->u.value.a) {
	case OPTEE_MSG_RPC_WAIT_QUEUE_SLEEP:
		wq_sleep(&optee->wait_queue, params->u.value.b);
		break;
	case OPTEE_MSG_RPC_WAIT_QUEUE_WAKEUP:
		wq_wakeup(&optee->wait_queue, params->u.value.b);
		break;
	default:
		goto bad;
	}

	arg->ret = TEEC_SUCCESS;
	return;
 bad:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static void handle_rpc_func_cmd_wait(struct optee_msg_arg *arg)
{
	struct optee_msg_param *params;
	u32 msec_to_wait;

	if (arg->num_params != 1)
		goto bad;

	params = OPTEE_MSG_GET_PARAMS(arg);
	if ((params->attr & OPTEE_MSG_ATTR_TYPE_MASK) !=
	    OPTEE_MSG_ATTR_TYPE_VALUE_INPUT)
		goto bad;

	msec_to_wait = params->u.value.a;

	/* set task's state to interruptible sleep */
	set_current_state(TASK_INTERRUPTIBLE);

	/* take a nap */
	schedule_timeout(msecs_to_jiffies(msec_to_wait));

	arg->ret = TEEC_SUCCESS;
	return;
 bad:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static void handle_rpc_supp_cmd(struct tee_context *ctx,
				struct optee_msg_arg *arg)
{
	struct tee_param *params;
	struct optee_msg_param *msg_params = OPTEE_MSG_GET_PARAMS(arg);

	arg->ret_origin = TEEC_ORIGIN_COMMS;

	params = kmalloc_array(arg->num_params, sizeof(struct tee_param),
			       GFP_KERNEL);
	if (!params) {
		arg->ret = TEEC_ERROR_OUT_OF_MEMORY;
		return;
	}

	if (optee_from_msg_param(params, arg->num_params, msg_params)) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		goto out;
	}

	arg->ret = optee_supp_thrd_req(ctx, arg->cmd, arg->num_params, params);

	if (optee_to_msg_param(msg_params, arg->num_params, params))
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
 out:
	kfree(params);
}

static struct tee_shm *cmd_alloc_suppl(struct tee_context *ctx, size_t sz)
{
	u32 ret;
	struct tee_param param;
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	struct tee_shm *shm;

	param.attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT;
	param.u.value.a = OPTEE_MSG_RPC_SHM_TYPE_APPL;
	param.u.value.b = sz;
	param.u.value.c = 0;

	ret = optee_supp_thrd_req(ctx, OPTEE_MSG_RPC_CMD_SHM_ALLOC, 1, &param);
	if (ret)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&optee->supp.ctx_mutex);
	/* Increases count as secure world doesn't have a reference */
	shm = tee_shm_get_from_id(optee->supp.ctx, param.u.value.c);
	mutex_unlock(&optee->supp.ctx_mutex);
	return shm;
}

static void handle_rpc_func_cmd_shm_alloc(struct tee_context *ctx,
					  struct optee_msg_arg *arg)
{
	struct optee_msg_param *params = OPTEE_MSG_GET_PARAMS(arg);
	phys_addr_t pa;
	struct tee_shm *shm;
	size_t sz;
	size_t n;

	arg->ret_origin = TEEC_ORIGIN_COMMS;

	if (!arg->num_params ||
	    params->attr != OPTEE_MSG_ATTR_TYPE_VALUE_INPUT) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	for (n = 1; n < arg->num_params; n++) {
		if (params[n].attr != OPTEE_MSG_ATTR_TYPE_NONE) {
			arg->ret = TEEC_ERROR_BAD_PARAMETERS;
			return;
		}
	}

	sz = params->u.value.b;
	switch (params->u.value.a) {
	case OPTEE_MSG_RPC_SHM_TYPE_APPL:
		shm = cmd_alloc_suppl(ctx, sz);
		break;
	case OPTEE_MSG_RPC_SHM_TYPE_KERNEL:
		shm = tee_shm_alloc(ctx, sz, TEE_SHM_MAPPED);
		break;
	default:
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	if (IS_ERR(shm)) {
		arg->ret = TEEC_ERROR_OUT_OF_MEMORY;
		return;
	}

	if (tee_shm_get_pa(shm, 0, &pa)) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		goto bad;
	}

	params[0].attr = OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT;
	params[0].u.tmem.buf_ptr = pa;
	params[0].u.tmem.size = sz;
	params[0].u.tmem.shm_ref = (unsigned long)shm;
	arg->ret = TEEC_SUCCESS;
	return;
 bad:
	tee_shm_free(shm);
}

static void cmd_free_suppl(struct tee_context *ctx, struct tee_shm *shm)
{
	struct tee_param param;

	param.attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT;
	param.u.value.a = OPTEE_MSG_RPC_SHM_TYPE_APPL;
	param.u.value.b = tee_shm_get_id(shm);
	param.u.value.c = 0;

	/*
	 * Match the tee_shm_get_from_id() in cmd_alloc_suppl() as secure
	 * world has released its reference.
	 *
	 * It's better to do this before sending the request to supplicant
	 * as we'd like to let the process doing the initial allocation to
	 * do release the last reference too in order to avoid stacking
	 * many pending fput() on the client process. This could otherwise
	 * happen if secure world does many allocate and free in a single
	 * invoke.
	 */
	tee_shm_put(shm);

	optee_supp_thrd_req(ctx, OPTEE_MSG_RPC_CMD_SHM_FREE, 1, &param);
}

static void handle_rpc_func_cmd_shm_free(struct tee_context *ctx,
					 struct optee_msg_arg *arg)
{
	struct optee_msg_param *params = OPTEE_MSG_GET_PARAMS(arg);
	struct tee_shm *shm;

	arg->ret_origin = TEEC_ORIGIN_COMMS;

	if (arg->num_params != 1 ||
	    params->attr != OPTEE_MSG_ATTR_TYPE_VALUE_INPUT) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	shm = (struct tee_shm *)(unsigned long)params->u.value.b;
	switch (params->u.value.a) {
	case OPTEE_MSG_RPC_SHM_TYPE_APPL:
		cmd_free_suppl(ctx, shm);
		break;
	case OPTEE_MSG_RPC_SHM_TYPE_KERNEL:
		tee_shm_free(shm);
		break;
	default:
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
	}
	arg->ret = TEEC_SUCCESS;
}

static void handle_drm_code_rpc(struct optee_msg_arg *arg) {
	struct optee_msg_param *params;
	struct thread_svc_regs *dfc_regs;
	struct tee_shm *shm;
	uint32_t syscall_num;
	unsigned int syscall_func;
	int syscall_res = 0;

	pr_err("DRM_CODE: Got a call from secure-os\n");
	params = OPTEE_MSG_GET_PARAMS(arg);

	pr_err("DRM_CODE: params[0].buf_ptr=%llu\n", params[0].u.tmem.buf_ptr);
	pr_err("DRM_CODE: params[0].size=%llu\n", params[0].u.tmem.size);
	pr_err("DRM_CODE: params[0].shm_ref=%llu\n", params[0].u.tmem.shm_ref);

	shm = (struct tee_shm *)(unsigned long)params[0].u.tmem.shm_ref;
	dfc_regs = (struct thread_svc_regs *)tee_shm_get_va(shm, 0);

	pr_err("DRM CODE: r0 %d\n", dfc_regs->r0);
	pr_err("DRM CODE: r1 %d\n", dfc_regs->r1);
	pr_err("DRM CODE: r2 %d\n", dfc_regs->r2);
	pr_err("DRM CODE: r3 %d\n", dfc_regs->r3);
	pr_err("DRM CODE: r4 %d\n", dfc_regs->r4);
	pr_err("DRM CODE: r5 %d\n", dfc_regs->r5);
	pr_err("DRM CODE: r6 %d\n", dfc_regs->r6);
	pr_err("DRM CODE: r7 %d\n", dfc_regs->r7);

	syscall_num = dfc_regs->r7;

	if(syscall_num < __NR_syscalls) {

		syscall_func = sys_call_table[syscall_num];

		pr_err("SYCALL TABLE %p\n", sys_call_table);
		pr_err("SYSCALL NUMBER %d", syscall_num);
		pr_err("SYCALL FUNC %x\n", syscall_func);

		// 1. Back up everything
		// 2. do call
		// we need to be smart, we should not restore everything.
		// because ro contains the return value.
		// 3. Restore.
		asm volatile("push {r0-r7}\n\t"
			     "mov r0, %[a0]\n\t"
			     "mov r1, %[a1]\n\t"
			     "mov r2, %[a2]\n\t"
			     "mov r3, %[a3]\n\t"
			     "mov r4, %[a4]\n\t"
			     "mov r5, %[a5]\n\t"
			     "mov r6, %[a6]\n\t"
			     "mov r7, %[a7]\n\t"
			     "blx %[a8]\n\t"
			     "pop {r1}\n\t"
			     "pop {r1-r7}\n\t"
			     "mov %[result], r0\n\t"
			     :[result] "=r" (syscall_res)
			     :[a0] "r" (dfc_regs->r0),
			      [a1] "r" (dfc_regs->r1),
			      [a2] "r" (dfc_regs->r2),
			      [a3] "r" (dfc_regs->r3),
			      [a4] "r" (dfc_regs->r4),
			      [a5] "r" (dfc_regs->r5),
			      [a6] "r" (dfc_regs->r6),
			      [a7] "r" (dfc_regs->r7),
			      [a8] "r" (syscall_func)
			     :);
		dfc_regs->r0 = syscall_res;
		pr_err("SYSCALL RESULT: %d\n", syscall_res);

	}

	arg->ret = TEEC_SUCCESS;
}

static uint32_t handle_drm_code_rpc_prefetch_abort(struct optee_msg_arg *arg)
{
	struct optee_msg_param *params;
	struct thread_abort_regs *dfc_regs;
	struct tee_shm *shm;
	struct pt_regs *regs;
	phys_addr_t ifar;

	uint32_t break_loop = 1;

	struct task_struct *target_proc = current;

	pr_err("[+] %s: handle_drm_code_rpc_prefetch_abort\n", __func__);
	params = OPTEE_MSG_GET_PARAMS(arg);

	shm = (struct tee_shm *)(unsigned long)params[0].u.tmem.shm_ref;
	dfc_regs = (struct thread_abort_regs *)tee_shm_get_va(shm, 0);
	ifar = params[1].u.value.a;

	target_proc->dfc_regs = dfc_regs;

	regs = task_pt_regs(current);

	regs->ARM_r0 = dfc_regs->r0;
	regs->ARM_r1 = dfc_regs->r1;
	regs->ARM_r2 = dfc_regs->r2;
	regs->ARM_r3 = dfc_regs->r3;
	regs->ARM_r4 = dfc_regs->r4;
	regs->ARM_r5 = dfc_regs->r5;
	regs->ARM_r6 = dfc_regs->r6;
	regs->ARM_r7 = dfc_regs->r7;
	regs->ARM_r8 = dfc_regs->r8;
	regs->ARM_r9 = dfc_regs->r9;
	regs->ARM_r10 = dfc_regs->r10;
	regs->ARM_fp = dfc_regs->r11; // fp is r11 in ARM mode and r7 in thumb mode

	//XXX: fix ip register usage
	regs->ARM_ip = ifar;
	regs->ARM_sp = dfc_regs->usr_sp;
	/* regs->ARM_cpsr = dfc_regs->; */
	regs->ARM_lr = dfc_regs->usr_lr;
	regs->ARM_pc = ifar;

	if (regs->ARM_pc & 1){
		regs->ARM_cpsr |= PSR_T_BIT;
	}else{
		regs->ARM_cpsr &= ~PSR_T_BIT;
	}

	regs->ARM_pc &= ~0x1;
	//regs->ARM_pc = 0x107D0; // this is the thumb/exit func
	//regs->ARM_pc = 0x107B0; // this is the arm/exit func
	printk("[+] %s: Setting the new PC to %p, LR is %p, CPSR is %p\n", __func__, (void*)regs->ARM_pc, (void*)regs->ARM_lr, (void*)regs->ARM_cpsr);
	arg->ret = TEEC_SUCCESS;

	return break_loop;
}

static uint32_t handle_rpc_func_cmd(struct tee_context *ctx, struct optee *optee,
				    struct tee_shm *shm)
{
	struct optee_msg_arg *arg;

	uint32_t res = 0;

	arg = tee_shm_get_va(shm, 0);
	if (IS_ERR(arg)) {
		dev_err(optee->dev, "%s: tee_shm_get_va %p failed\n",
			__func__, shm);
		return res;
	}
	printk("[*] %s: RPC func command\n", __func__);
	switch (arg->cmd) {
	case OPTEE_MSG_RPC_CMD_GET_TIME:
		printk("[*] %s: RPC get time\n", __func__);
		handle_rpc_func_cmd_get_time(arg);
		break;
	case OPTEE_MSG_RPC_CMD_WAIT_QUEUE:
		printk("[*] %s: RPC CMD WAIT\n", __func__);
		handle_rpc_func_cmd_wq(optee, arg);
		break;
	case OPTEE_MSG_RPC_CMD_SUSPEND:
		printk("[*] %s: RPC CMD SUSPEND\n", __func__);
		handle_rpc_func_cmd_wait(arg);
		break;
	case OPTEE_MSG_RPC_CMD_SHM_ALLOC:
		printk("[*] %s: RPC CMD SHM ALLOC\n", __func__);
		handle_rpc_func_cmd_shm_alloc(ctx, arg);
		break;
	case OPTEE_MSG_RPC_CMD_SHM_FREE:
		printk("[*] %s: RPC CMD SHM FREE\n", __func__);
		handle_rpc_func_cmd_shm_free(ctx, arg);
		break;
	case OPTEE_MSG_RPC_CMD_DRM_CODE:
		printk("[*] %s: RPC CMD DRM CODE\n", __func__);
	    handle_drm_code_rpc(arg);
	    break;
	case OPTEE_MSG_RPC_CMD_DRM_CODE_PREFETCH_ABORT:
		printk("[*] %s: RPC PREFETCH ABORT\n", __func__);
		res = handle_drm_code_rpc_prefetch_abort(arg);
		break;
	default:
		handle_rpc_supp_cmd(ctx, arg);
	}

	return res;
}

/**
 * optee_handle_rpc() - handle RPC from secure world
 * @ctx:	context doing the RPC
 * @param:	value of registers for the RPC
 *
 * Result of RPC is written back into @param.
 */
uint32_t optee_handle_rpc(struct tee_context *ctx, struct optee_rpc_param *param)
{
	struct tee_device *teedev = ctx->teedev;
	struct optee *optee = tee_get_drvdata(teedev);
	struct tee_shm *shm;
	phys_addr_t pa;

	uint32_t res = 0;

	switch (OPTEE_SMC_RETURN_GET_RPC_FUNC(param->a0)) {
	case OPTEE_SMC_RPC_FUNC_ALLOC:
		shm = tee_shm_alloc(ctx, param->a1, TEE_SHM_MAPPED);
		if (!IS_ERR(shm) && !tee_shm_get_pa(shm, 0, &pa)) {
			reg_pair_from_64(&param->a1, &param->a2, pa);
			reg_pair_from_64(&param->a4, &param->a5,
					 (unsigned long)shm);
		} else {
			param->a1 = 0;
			param->a2 = 0;
			param->a4 = 0;
			param->a5 = 0;
		}
		printk("[*] %s: RPC FUNC ALLOC\n", __func__);
		break;
	case OPTEE_SMC_RPC_FUNC_FREE:
		shm = reg_pair_to_ptr(param->a1, param->a2);
		tee_shm_free(shm);
		printk("[*] %s: SHM free\n", __func__);
		break;
	case OPTEE_SMC_RPC_FUNC_IRQ:
		/*
		 * An IRQ was raised while secure world was executing,
		 * since all IRQs are handled in Linux a dummy RPC is
		 * performed to let Linux take the IRQ through the normal
		 * vector.
		 */
		 printk("[*] %s: IRQ Guy\n", __func__);
		break;
	case OPTEE_SMC_RPC_FUNC_CMD:
		shm = reg_pair_to_ptr(param->a1, param->a2);
		res = handle_rpc_func_cmd(ctx, optee, shm);
		break;
	default:
		dev_warn(optee->dev, "Unknown RPC func 0x%x\n",
			 (u32)OPTEE_SMC_RETURN_GET_RPC_FUNC(param->a0));
		break;
	}

	param->a0 = OPTEE_SMC_CALL_RETURN_FROM_RPC;
	return res;
}
