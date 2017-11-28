#include <dfc/dfc_cfi.h>
#include <kernel/thread.h>
#include <arm.h>
#include <trace.h>

TEE_Result initialize_drm_shadow_stack(void *ep_ptr, uint64_t num_eps, uint64_t cfi_min, uint64_t cfi_max) {
    TEE_Result res = TEE_SUCCESS;
#ifndef NO_DRM_CFI
    struct thread_specific_data *tsd = thread_get_tsd();
    if(tsd->shadow_stack) {
        free(tsd->shadow_stack);
    }
    tsd->shadow_stack = (uint64_t*)malloc(MAX_DRM_SHADOW_BYTES);
    tsd->possible_fn_eps = (uint64_t*)ep_ptr;
    tsd->eps_size = num_eps;
    tsd->cfi_min = cfi_min;
    tsd->cfi_max = cfi_max;
    tsd->curr_sh_id = MAX_DRM_SHADOW_STACK_SIZE + 1;
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

TEE_Result drm_push_cfi_secure_sp(uint64_t user_sp, uint64_t usr_stk) {
    TEE_Result res = TEE_SUCCESS;
#ifndef NO_DRM_CFI
    struct thread_specific_data *tsd = thread_get_tsd();
    
    if(tsd->curr_sh_id < tsd->max_sh_stk_sz) {
        // are we returning to non-secure world?
        if(tsd->shadow_stack[tsd->curr_sh_id] == usr_stk) {
            tsd->curr_sh_id += 2;
            return res;
        }
        
        // We are not returning..but the stack 
        // has more items popped.
        if(tsd->shadow_stack[tsd->curr_sh_id] <= usr_stk) {
            DMSG("[!] DRM_Code: looks like stack seems to be have additional items popped\n");
            return TEE_ERROR_SECURITY;
        }
    }
    
    if(tsd->first_usr_sp == usr_stk) {
        // We are returning from the first function?
#ifdef DRM_DEBUG
        DMSG("[+] DRM_CODE: Returning from the initial function\n");
#endif
        return res;
    }
    
    // Okay, this is a call to non-secure side.
    if(tsd->curr_sh_id > 2) {
        tsd->curr_sh_id -= 2;
        tsd->shadow_stack[tsd->curr_sh_id] = usr_stk;
        tsd->shadow_stack[tsd->curr_sh_id - 1] = user_sp;
    } else {
        DMSG("[!] DRM_CODE: Shadow stack full, while pushing\n");
        return TEE_ERROR_SECURITY;
    }
#endif
    return res;
}

TEE_Result drm_check_cfi_return_sp(uint64_t user_sp, uint64_t usr_stk) {
    TEE_Result res = TEE_SUCCESS;
#ifndef NO_DRM_CFI
    uint64_t latest_stk = 0;
    uint64_t latest_sp = 0;
    struct thread_specific_data *tsd = thread_get_tsd();
    res = TEE_ERROR_SECURITY;
    
    
    if(tsd->curr_sh_id < tsd->max_sh_stk_sz) {
        latest_stk = tsd->shadow_stack[tsd->curr_sh_id];
        latest_sp = tsd->shadow_stack[tsd->curr_sh_id - 1];
        if(usr_stk >= latest_stk) {
            if(user_sp == latest_sp) {
                tsd->curr_sh_id += 2;
                res = TEE_SUCCESS;
            }
        }
    } 
    
    if(res != TEE_SUCCESS) {
        // check we are returning to the beginning of a function?
        if(tsd->possible_fn_eps) {
            uint64_t idx = 0;
            for(idx=0; idx<tsd->eps_size; idx++) {
                if(tsd->possible_fn_eps[idx] == user_sp) {
                    res = TEE_SUCCESS;
                    
                    if(tsd->curr_sh_id > 2) {
                        tsd->curr_sh_id -= 2;
                        tsd->shadow_stack[tsd->curr_sh_id] = usr_stk;
                        tsd->shadow_stack[tsd->curr_sh_id - 1] = user_sp;
                    } else {
                        DMSG("[!] DRM_CODE: Shadow stack full\n");
                        break;
                    }
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


__unused static int64_t get_dst_call_addr(uint64_t instr_addr) {
    int64_t dst_addr = 0;
#ifdef ARM32
    struct thread_specific_data *tsd = thread_get_tsd();
    if(tsd->cfi_min < instr_addr && tsd->cfi_max > instr_addr) {
        uint32_t final_addr = (uint32_t)instr_addr;
        uint32_t dst_cont = *(uint32_t*)(long)final_addr;
        uint32_t op_code = (dst_cont & 0x0e000000) >> 24;
        uint32_t link_bit = (dst_cont & 0x01000000) >> 24;
        bool subtr = false;
        uint32_t target_addr = (dst_cont & (0x00ffffff));
        
        uint32_t cond_flag = (dst_cont & 0xf0000000) >> 28;
        
        if(target_addr & 0x00800000) {
            target_addr = 0x3f000000 | target_addr;
            subtr = true;
        }
        target_addr = target_addr << 2;
        
        if(subtr) {
            target_addr -= 1;
            // negative relative offset
            target_addr = ~target_addr;
            target_addr = final_addr - target_addr + 8;
        } else {
            // positive relative offset.
            target_addr = final_addr + target_addr + 8;
        }
        
        if(op_code == 0xe) {
            
        } else {
            if(op_code == 0xa) {
                if(cond_flag == 0xf) {
                     target_addr += (link_bit << 1);
                }
                dst_addr = target_addr;
            } else {
                uint32_t blx_indirect = (dst_cont & 0x0ff000f0);
                if(blx_indirect == 0x01200030) {
                    // This is indirect call.
                    dst_addr = -1;
                } else {
                    //TODO: Try to kill the user thread.
                    DMSG("[!] DRM_CODE Trying to return to invalid instruction: 0x%x\n", dst_cont);
                    dst_addr = -2;
                }
            }
        }
    }
#endif
    return dst_addr;
}

static uint64_t get_target_ep_func(uint64_t tar_lr) {
    struct thread_specific_data *tsd = thread_get_tsd();
    uint64_t *ep_table = tsd->possible_fn_eps;
    uint64_t num_eps = tsd->eps_size, i = 0;
    uint64_t curr_max = 0;
    for(i=0; i < num_eps; i++) {
        if(ep_table[i] < tar_lr) {
            if(curr_max == 0) {
                curr_max = ep_table[i];
            } else {
                if(ep_table[i] > curr_max) {
                    curr_max = ep_table[i];
                }
            }
        }
    }
    return curr_max;
}

TEE_Result drm_check_return_sp(uint64_t target_return, uint64_t target_lr) {
    TEE_Result res = TEE_SUCCESS;
#ifndef NO_DRM_CFI
    int64_t taget_func_addr = get_dst_call_addr(target_return-4);
    if(taget_func_addr == -1 || taget_func_addr == 0) {
        // This means its fine.
    } else {
        uint64_t expected_func_addr = get_target_ep_func(target_lr);
        res = TEE_ERROR_SECURITY;
        if(expected_func_addr == (uint64_t)taget_func_addr) {
            res = TEE_SUCCESS;
        } else {
            DMSG("[!] CFI Bammed up, Expected: 0x%llx, Got: 0x%llx, at: 0x%llx\n", expected_func_addr, taget_func_addr, target_return);
        }
    }
#endif
    return res;
}
