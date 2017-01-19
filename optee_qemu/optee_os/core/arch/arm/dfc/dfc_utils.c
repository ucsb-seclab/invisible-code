#include <dfc/dfc_common.h>
#include <mm/core_memprot.h>

TEE_Result load_blob_data(MEM_BLOB *mem_blob, void **out_blob_addr, LEN_TYPE *out_blob_len) {
    void *curr_mem;
    void *allocated_mem;
    LEN_TYPE orig_blob_len;
    PHY_ADDR_TYPE orig_blob_addr;
    allocated_mem = NULL;
    curr_mem = NULL;
    
    // read the blob addr and blob len
    orig_blob_addr = mem_blob->blob_phy_addr;
    orig_blob_len = mem_blob->blob_len;
    
    // get the VA corresponding to the provided blob memory.
    curr_mem = phys_to_virt(orig_blob_addr, MEM_AREA_NSEC_SHM);
    
    if(!curr_mem) {
        res = TEE_ERROR_GENERIC;
		goto err_out;
    }
    
    // make sure that this is in non-secure memory.
    if (!tee_vbuf_is_non_sec(curr_mem, orig_blob_len)) {
		res = TEE_ERROR_SECURITY;
		goto err_out;
	}
	
	// allocate memory in the secure world.
	allocated_mem = malloc(orig_blob_len);
    if(!allocated_mem) {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto err_out;
    }
    
    // copy blob into secure world.
    memcpy(allocated_mem, curr_mem, orig_blob_len);
    
    // copy the pointer and size into provided arguments.
    *out_blob_addr = allocated_mem;
    *out_blob_len = orig_blob_len;
    
    return TEE_SUCCESS;
    
    err_out:
        // error occured.
        if(allocated_mem != NULL) {
            free(allocated_mem);
        }
    return res;
}
