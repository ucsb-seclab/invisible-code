#include "drm_interrupt_handler.h"
#include <drm_code/abort_helpers.h>

DRM_INT_RET_TYPE drm_handle_dabort(uint64_t far, uint64_t fsr, struct pt_regs *src_regs) {
     DRM_INT_RET_TYPE ret_val = ERROR_OCCURRED;     
     // first check if the address is already mapped?
     // if yes, just return.
     //TODO: finish this
     
     // if no, then we need to handle the data abort.
     drm_data_abort(far, fsr, src_regs);
     
     // if this is a data abort, we should return back to secure side.
     return ret_val;
}

DRM_INT_RET_TYPE drm_handle_pabort(uint64_t ifar, uint64_t ifsr, struct pt_regs *src_regs) {
    DRM_INT_RET_TYPE ret_val = ERROR_OCCURRED;
    // first check if the address is already mapped? 
    // if yes
    // check if the corresponding physical page is in non-secure side?
    // if yes that means execution jumped from secure side to non-secure side.
    // just return to continue execution.
    // TODO: finish this
    
    // handle the prefetch abort.
    drm_ptch_abort(ifar, ifsr, src_regs);
    
    // prefetch abort should always result in running in non-secure world.
    // for obvious reasons :)
        
    return ret_val;
}
