#ifndef _ABORT_HELPERS_H
#define _ABORT_HELPERS_H
#include <linux/types.h>
struct pt_regs;
int drm_data_abort(uint64_t addr, uint64_t fsr, struct pt_regs *regs);

int drm_ptch_abort(uint64_t addr, uint64_t ifsr, struct pt_regs *regs);
#endif
