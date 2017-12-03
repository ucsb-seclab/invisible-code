#ifndef DRM_EXECUTION_FORWARDING_H
#define DRM_EXECUTION_FORWARDING_H

u32 optee_do_call_from_abort(phys_addr_t shm_pa, phys_addr_t mm_pa, unsigned long num_of_entries);

#endif
