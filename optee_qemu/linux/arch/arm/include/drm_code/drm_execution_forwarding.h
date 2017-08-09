#ifndef DRM_EXECUTION_FORWARDING_H
#define DRM_EXECUTION_FORWARDING_H

u32 optee_do_call_from_abort(unsigned long p0, unsigned long p1, unsigned long p2,
			     unsigned long p3, unsigned long p4, unsigned long p5,
			     unsigned long p6, unsigned long p7, bool first_exec);

#endif
