#include <dfc/dfc_cfi.h>
#include <kernel/thread.h>
#include <trace.h>

TEE_Result initialize_drm_shadow_stack(void *ep_ptr, uint64_t num_eps, uint64_t cfi_min, uint64_t cfi_max) {
    TEE_Result res = TEE_SUCCESS;
#ifndef NO_DRM_CFI
    struct thread_specific_data *tsd = thread_get_tsd();
    if(tsd->shadow_stack) {
        free(tsd->shadow_stack);
    }
    tsd->no_store_shadow_sp = false;
    tsd->shadow_stack = (uint64_t*)malloc(MAX_DRM_SHADOW_BYTES);
    tsd->possible_fn_eps = (uint64_t*)ep_ptr;
    tsd->eps_size = num_eps;
    tsd->cfi_min = cfi_min;
    tsd->cfi_max = cfi_max;
    tsd->curr_sh_id = MAX_DRM_SHADOW_STACK_SIZE;
    tsd->max_sh_stk_sz = MAX_DRM_SHADOW_STACK_SIZE;
#endif
    return res;
}

TEE_Result free_drm_shadow_stack(int curr_thr_id) {
    TEE_Result res = TEE_SUCCESS;
#ifndef NO_DRM_CFI
    struct thread_specific_data *tsd = thread_get_tsd_by_num(curr_thr_id);
    if(tsd->shadow_stack) {
        free(tsd->shadow_stack);
        tsd->shadow_stack = NULL;        
    }
    tsd->possible_fn_eps = NULL;
    tsd->curr_sh_id = tsd->max_sh_stk_sz = tsd->eps_size = 0;
#endif
    return res;

}

TEE_Result drm_push_cfi_secure_sp(uint64_t user_sp, uint64_t target_jmp __unused) {
    TEE_Result res = TEE_SUCCESS;
#ifndef NO_DRM_CFI
    struct thread_specific_data *tsd = thread_get_tsd();
    
    if(user_sp > tsd->cfi_min && user_sp <= tsd->cfi_max) {
        res = TEE_ERROR_SECURITY;
        // push the latest sp on to the shadow stack
        if(tsd->curr_sh_id > 0 && tsd->shadow_stack) {
            if(tsd->no_store_shadow_sp && tsd->curr_sh_id == tsd->max_sh_stk_sz && (target_jmp < tsd->cfi_min || target_jmp > tsd->cfi_max)) {
                // here we are returning to user mode for the last time.
#ifdef DFC_DEBUG
                DMSG("[*] DRM_CODE: No\n");
#endif
            } else {
                tsd->curr_sh_id--;
                tsd->shadow_stack[tsd->curr_sh_id] = user_sp;
#ifdef DFC_DEBUG
                DMSG("[*] DRM_CODE: Yes\n");
#endif
            }
            res = TEE_SUCCESS;
#ifdef DFC_DEBUG
            DMSG("[*] DRM_CODE: CURR Idx in push : 0x%llx at 0x%llx", tsd->curr_sh_id, user_sp);
#endif
        } else {
#ifdef DFC_DEBUG
            DMSG("[*] DRM_CODE: CURR Idx in else push : 0x%llx\n", tsd->curr_sh_id);
#endif
        }
    }
#endif
    return res;
}

TEE_Result drm_check_cfi_return_sp(uint64_t user_sp) {
    TEE_Result res = TEE_SUCCESS;
#ifndef NO_DRM_CFI
    struct thread_specific_data *tsd = thread_get_tsd();
    res = TEE_ERROR_SECURITY;
    
    tsd->no_store_shadow_sp = true;
    
    if(tsd->curr_sh_id < tsd->max_sh_stk_sz && tsd->shadow_stack) {
        uint64_t latest_sp = tsd->shadow_stack[tsd->curr_sh_id];
        // if we are returning to a recent location in user mode?
        if((user_sp - latest_sp) <= 2 || (latest_sp - user_sp) <= 2) {
            tsd->curr_sh_id++;
#ifdef DFC_DEBUG
            DMSG("SHADOW ENTRY\n");
            DMSG("[*] DRM_CODE: CURR Idx in pop : 0x%llx\n", tsd->curr_sh_id);
#endif
            res = TEE_SUCCESS;
        }
    } 
    
    if(res != TEE_SUCCESS) {
        // check we are returning to the beginning of a function?
        if(tsd->possible_fn_eps) {
            uint64_t idx = 0;
            for(idx=0; idx<tsd->eps_size; idx++) {
                if(tsd->possible_fn_eps[idx] == user_sp) {
                    res = TEE_SUCCESS;
                    tsd->no_store_shadow_sp = false;
#ifdef DFC_DEBUG
                    DMSG("FUNCTION ENTRY\n");
#endif
                    break;
                }
            }
         }
   }
#endif
    return res;
}
