#ifndef DFC_CFI_H
#define DFC_CFI_H
#include <tee_api_types.h>

#define MAX_DRM_SHADOW_STACK_SIZE 128
#define MAX_DRM_SHADOW_BYTES (MAX_DRM_SHADOW_STACK_SIZE * sizeof(uint64_t))

TEE_Result initialize_drm_shadow_stack(void *ep_ptr, uint64_t num_eps, uint64_t cfi_min, uint64_t cfi_max);

TEE_Result free_drm_shadow_stack(int curr_thr_id);

TEE_Result drm_push_cfi_secure_sp(uint64_t user_sp, uint64_t target_jmp);

TEE_Result drm_check_cfi_return_sp(uint64_t user_sp);

TEE_Result drm_check_return_sp(void);

#endif
