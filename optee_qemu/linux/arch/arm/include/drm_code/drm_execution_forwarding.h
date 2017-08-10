#ifndef DRM_EXECUTION_FORWARDING_H
#define DRM_EXECUTION_FORWARDING_H

#include <linux/arm-smccc.h>

u32 optee_do_call_from_abort(unsigned long p0, unsigned long p1, unsigned long p2,
			     unsigned long p3, unsigned long p4, unsigned long p5,
			     unsigned long p6);

#define OPTEE_SMC_STD_CALL_VAL(func_num) \
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_STD_CALL, ARM_SMCCC_SMC_32, \
			   ARM_SMCCC_OWNER_TRUSTED_OS, (func_num))

#define OPTEE_SMC_FUNCID_RETURN_FROM_RPC	3
#define OPTEE_SMC_CALL_RETURN_FROM_RPC \
	OPTEE_SMC_STD_CALL_VAL(OPTEE_SMC_FUNCID_RETURN_FROM_RPC)


#endif
