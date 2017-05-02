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

#ifndef OPTEE_PRIVATE_H
#define OPTEE_PRIVATE_H

#include <linux/arm-smccc.h>
#include <linux/semaphore.h>
#include <linux/tee_drv.h>
#include <linux/types.h>
#include "optee_msg.h"

#define OPTEE_MAX_ARG_SIZE	1024

/* Some Global Platform error codes used in this driver */
#define TEEC_SUCCESS			0x00000000
#define TEEC_ERROR_BAD_PARAMETERS	0xFFFF0006
#define TEEC_ERROR_COMMUNICATION	0xFFFF000E
#define TEEC_ERROR_OUT_OF_MEMORY	0xFFFF000C

#define TEEC_ORIGIN_COMMS		0x00000002

typedef void (optee_invoke_fn)(unsigned long, unsigned long, unsigned long,
				unsigned long, unsigned long, unsigned long,
				unsigned long, unsigned long,
				struct arm_smccc_res *);

struct optee_call_queue {
	/* Serializes access to this struct */
	struct mutex mutex;
	struct list_head waiters;
};

struct optee_wait_queue {
	/* Serializes access to this struct */
	struct mutex mu;
	struct list_head db;
};

extern optee_invoke_fn *global_invoke_fn;

/**
 * struct optee_supp - supplicant synchronization struct
 * @ctx			the context of current connected supplicant.
 *			if !NULL the supplicant device is available for use,
 *			else busy
 * @ctx_mutex:		held while accessing @ctx
 * @func:		supplicant function id to call
 * @ret:		call return value
 * @num_params:		number of elements in @param
 * @param:		parameters for @func
 * @req_posted:		if true, a request has been posted to the supplicant
 * @supp_next_send:	if true, next step is for supplicant to send response
 * @thrd_mutex:		held by the thread doing a request to supplicant
 * @supp_mutex:		held by supplicant while operating on this struct
 * @data_to_supp:	supplicant is waiting on this for next request
 * @data_from_supp:	requesting thread is waiting on this to get the result
 */
struct optee_supp {
	struct tee_context *ctx;
	/* Serializes access of ctx */
	struct mutex ctx_mutex;

	u32 func;
	u32 ret;
	size_t num_params;
	struct tee_param *param;

	bool req_posted;
	bool supp_next_send;
	/* Serializes access to this struct for requesting thread */
	struct mutex thrd_mutex;
	/* Serializes access to this struct for supplicant threads */
	struct mutex supp_mutex;
	struct completion data_to_supp;
	struct completion data_from_supp;
};

/**
 * struct optee - main service struct
 * @supp_teedev:	supplicant device
 * @teedev:		client device
 * @dev:		probed device
 * @invoke_fn:		function to issue smc or hvc
 * @call_queue:		queue of threads waiting to call @invoke_fn
 * @wait_queue:		queue of threads from secure world waiting for a
 *			secure world sync object
 * @supp:		supplicant synchronization struct for RPC to supplicant
 * @pool:		shared memory pool
 * @ioremaped_shm	virtual address of memory in shared memory pool
 */
struct optee {
	struct tee_device *supp_teedev;
	struct tee_device *teedev;
	struct device *dev;
	optee_invoke_fn *invoke_fn;
	struct optee_call_queue call_queue;
	struct optee_wait_queue wait_queue;
	struct optee_supp supp;
	struct tee_shm_pool *pool;
	void __iomem *ioremaped_shm;
};

struct optee_session {
	struct list_head list_node;
	u32 session_id;
};

struct optee_context_data {
	/* Serializes access to this struct */
	struct mutex mutex;
	struct list_head sess_list;
};

struct optee_rpc_param {
	u32	a0;
	u32	a1;
	u32	a2;
	u32	a3;
	u32	a4;
	u32	a5;
	u32	a6;
	u32	a7;
};

uint32_t optee_handle_rpc(struct tee_context *ctx, struct optee_rpc_param *param);

void optee_wait_queue_init(struct optee_wait_queue *wq);
void optee_wait_queue_exit(struct optee_wait_queue *wq);

u32 optee_supp_thrd_req(struct tee_context *ctx, u32 func, size_t num_params,
			struct tee_param *param);

int optee_supp_read(struct tee_context *ctx, void __user *buf, size_t len);
int optee_supp_write(struct tee_context *ctx, void __user *buf, size_t len);
void optee_supp_init(struct optee_supp *supp);
void optee_supp_uninit(struct optee_supp *supp);

int optee_supp_recv(struct tee_context *ctx, u32 *func, u32 *num_params,
		    struct tee_param *param);
int optee_supp_send(struct tee_context *ctx, u32 ret, u32 num_params,
		    struct tee_param *param);

u32 optee_do_call_with_arg(struct tee_context *ctx, phys_addr_t parg);
int optee_open_session(struct tee_context *ctx,
		       struct tee_ioctl_open_session_arg *arg,
		       struct tee_param *param);
int optee_close_session(struct tee_context *ctx, u32 session);
int optee_invoke_func(struct tee_context *ctx, struct tee_ioctl_invoke_arg *arg,
		      struct tee_param *param);
int optee_cancel_req(struct tee_context *ctx, u32 cancel_id, u32 session);

void optee_enable_shm_cache(struct optee *optee);
void optee_disable_shm_cache(struct optee *optee);

int optee_from_msg_param(struct tee_param *params, size_t num_params,
			 const struct optee_msg_param *msg_params);
int optee_to_msg_param(struct optee_msg_param *msg_params, size_t num_params,
		       const struct tee_param *params);
		       
		       
// copied from arch/arm/include/mm/core_mmu.h

/*
 * Memory area type:
 * MEM_AREA_NOTYPE:   Undefined type. Used as end of table.
 * MEM_AREA_TEE_RAM:  teecore execution RAM (secure, reserved to TEE, unused)
 * MEM_AREA_TEE_COHERENT: teecore coherent RAM (secure, reserved to TEE)
 * MEM_AREA_TA_RAM:   Secure RAM where teecore loads/exec TA instances.
 * MEM_AREA_NSEC_SHM: NonSecure shared RAM between NSec and TEE.
 * MEM_AREA_RAM_NSEC: NonSecure RAM storing data
 * MEM_AREA_RAM_SEC:  Secure RAM storing some secrets
 * MEM_AREA_IO_NSEC:  NonSecure HW mapped registers
 * MEM_AREA_IO_SEC:   Secure HW mapped registers
 * MEM_AREA_RES_VASPACE: Reserved virtual memory space
 * MEM_AREA_TA_VASPACE: TA va space, only used with phys_to_virt()
 * MEM_AREA_MAXTYPE:  lower invalid 'type' value
 */
enum teecore_memtypes {
	MEM_AREA_NOTYPE = 0,
	MEM_AREA_TEE_RAM,
	MEM_AREA_TEE_COHERENT,
	MEM_AREA_TA_RAM,
	MEM_AREA_NSEC_SHM,
	MEM_AREA_RAM_NSEC,
	MEM_AREA_RAM_SEC,
	MEM_AREA_IO_NSEC,
	MEM_AREA_IO_SEC,
	MEM_AREA_RES_VASPACE,
	MEM_AREA_TA_VASPACE,
	MEM_AREA_MAXTYPE
};

// list of memory areas which belong to the secure side
struct dfc_sec_mem_map {
	uint64_t pa_start;
	uint64_t pa_end;
	struct list_head list;
};

extern struct dfc_sec_mem_map *global_sec_mem_map;

/*
 * XXX: Custom handlers here
 */
int optee_open_blob_session(struct tee_context *ctx,
		       struct tee_ioctl_open_blob_session_arg *arg,
		       struct tee_param *param);

int optee_close_blob_session(struct tee_context *ctx, u32 session);

/*
 * Small helpers
 */

static inline void *reg_pair_to_ptr(u32 reg0, u32 reg1)
{
	return (void *)(unsigned long)(((u64)reg0 << 32) | reg1);
}

static inline void reg_pair_from_64(u32 *reg0, u32 *reg1, u64 val)
{
	*reg0 = val >> 32;
	*reg1 = val;
}

#endif /*OPTEE_PRIVATE_H*/
