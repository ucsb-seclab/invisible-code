#include "drm_interrupt_handler.h"
#include "drm_utils.h"
#include <drm_code/abort_helpers.h>

DRM_INT_RET_TYPE drm_handle_dabort(uint64_t far, uint64_t fsr, struct pt_regs *src_regs) {
     DRM_INT_RET_TYPE ret_val = ERROR_OCCURRED;
     struct task_struct *target_proc = current;
     // first check if the address is already mapped?
     // if yes, just return.
     // we need this because, the page might be mapped by other core.
     if(is_address_mapped(target_proc, (unsigned long)far)) {
        pr_err(DFC_WARN_HDR "Address:0x%llx is already mapped for %d\n", __func__, far, target_proc->pid);
        // if this is a data abort, we should return back to secure side.
        ret_val = CONTINUE_S_EXECUTION;
     } else {
         // if no, then we need to handle the data abort.
         drm_data_abort(far, fsr, src_regs);
         ret_val = CONTINUE_S_EXECUTION;
         // Sanity check:
         // the address should be now mapped in the
         // task address space
         if(!is_address_mapped(target_proc, (unsigned long)far)) {
            pr_err(DFC_ERR_HDR "Failed to map address:0x%llx in the address space of process:%d\n", __func__, far, target_proc->pid);
            // should be return error here?
            // TODO: check if the current process is not killed.
            // This can happen when the process is trying to access some invalid address.
         } else {
            printk("[+] ALL OK: Address:0x%llx is now mapped in the address space of process:%d\n", far, target_proc->pid);
         }

     }
     return ret_val;
}

DRM_INT_RET_TYPE drm_handle_pabort(uint64_t ifar, uint64_t ifsr, struct pt_regs *src_regs) {
    DRM_INT_RET_TYPE ret_val = ERROR_OCCURRED;
    struct task_struct *target_proc = current;
    // first check if the address is already mapped?
    // if yes
    // check if the corresponding physical page is in non-secure side?
    // if yes that means execution jumped from secure side to non-secure side.
    struct page *dst_page = get_task_page(target_proc, (unsigned long)ifar);
    if(dst_page != NULL) {
        unsigned long page_phys;
        page_phys = (unsigned long)(page_to_phys(dst_page));
        if(!is_secure_mem(page_phys)) {
            // OK, the secure-side wants to jump to non-secure side.
            ret_val = CONTINUE_NS_EXECUTION;
            //TODO: change the registers
            // change PC and other user mode registers.
            // and return the execution.
        } else {
            // WHAT?? we got a prefetch abort
            // while trying to execute instruction that belons to secure memory?
            // BAD BAD.
            panic("%s, Invalid prefetch abort happened\n", __func__);
        }
    } else {
        // handle the prefetch abort.
        drm_prefetch_abort(ifar, ifsr, src_regs);
        ret_val = CONTINUE_NS_EXECUTION;
    }

    // prefetch abort should always result in running in non-secure world.
    // for obvious reasons :)

    return ret_val;
}
