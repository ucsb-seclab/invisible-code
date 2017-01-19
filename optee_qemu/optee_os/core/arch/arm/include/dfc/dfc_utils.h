#ifndef DFC_UTILS_H
#define DFC_UTILS_H
#include <dfc_common.h>

/**
 *  This function loads the provided blob into a malloced memory region.
 *  The pointer to malloced data and corresponding length are copied into 
 *  function arguments: out_blob_addr and out_blob_len.
 *
 *  @param mem_blob Pointer to the memory blob to load
 *  @param out_blob_addr[output] Pointer to the malloced memory.
 *  @param out_blob_len[output] Length of the memory area allocated.
 * 
 *  return TEE_SUCCESS or corresponding error code.
 */
TEE_Result load_blob_data(MEM_BLOB *mem_blob, void **out_blob_addr, LEN_TYPE *out_blob_len);

#endif
