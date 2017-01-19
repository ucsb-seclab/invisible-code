#include <stdlib.h>
#include <dfc/dfc_process.h>

DFC_GLOBAL_STATE dfc_glob_state = {
    .process_list = TAILQ_HEAD_INITIALIZER(dfc_process_st);
};

TEE_Result create_new_dfc_process(DFC_PROCESS **new_dfc_proc) {
    TEE_Result res;
    
    DFC_PROCESS *new_process = NULL;
    
    // allocate new proc structure.
    new_process = calloc(1, sizeof(DFC_PROCESS));
    if(!new_process) {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto error_calloc;
    }
    
    // initialize the mutex
    mutex_init(&(new_process->common_mutex));
    
    *new_dfc_proc = new_process;
    
    return TEE_SUCCESS;
    // error handling.
    error_calloc:
        if(new_process) {
            free(new_process);
        }
        
    return res;
}

TEE_Result add_va_pa_mappings(DFC_PROCESS *curr_process, MEM_BLOB *mem_map_target_bob) {
    
}
