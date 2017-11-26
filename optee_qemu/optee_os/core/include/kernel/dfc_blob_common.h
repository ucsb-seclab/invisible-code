#ifndef DFC_BLOB_COMMON_H
#define DFC_BLOB_COMMON_H

#include <stdarg.h>
#include <tee_api_types.h>

struct blob_info {
	uint64_t va;
#ifndef NO_DRM_CFI
    uint64_t cfi_data_start;
#endif
	uint64_t pa;
	uint64_t size;
	uint64_t shm_ref;
};


// the data_map struct is used to pass around the
// data pages memory map reference
struct data_map {
	uint64_t pa;
	uint64_t numofentries;
	uint64_t shm_ref;
};

#endif
