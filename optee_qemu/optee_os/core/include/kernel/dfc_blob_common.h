#ifndef DFC_BLOB_COMMON_H
#define DFC_BLOB_COMMON_H

#include <stdarg.h>
#include <tee_api_types.h>

struct blob_info {
	uint64_t pa;
	uint64_t size;
	uint64_t shm_ref;
};

#endif
