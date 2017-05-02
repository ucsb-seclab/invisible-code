#ifndef DRM_INTERRUPT_HANDLER_H
#define DRM_INTERRUPT_HANDLER_H

#include <linux/sched.h>
#include "drm_interrupt_types.h"

/*
 * This funcion handles data abort for the current task, with provided src_regs.
 * 
 * @param far: Contents of fault address register, basically the va where this fault happened.
 * @param fsr: Contents of fault status register, which is used to determine the type fault and handler functions.
 *
 * @return DRM_INT_RET_TYPE depending on the result of the handling.
 *
 */
DRM_INT_RET_TYPE drm_handle_dabort(uint64_t far, uint64_t fsr, struct pt_regs *src_regs);


/*
 * This function handles prefetch abort for the current task, with provided src_regs.
 *
 * @param ifar: Contents of the fault address at which the prefetch abort happened.
 * @param ifsr: Contents of the fault status register, this is used in same way as data abort.
 *
 * @return DRM_INT_RET_TYPE depending on the result of the handling.
 * 
 */
DRM_INT_RET_TYPE drm_handle_pabort(uint64_t ifar, uint64_t ifsr, struct pt_regs *src_regs);

#endif
