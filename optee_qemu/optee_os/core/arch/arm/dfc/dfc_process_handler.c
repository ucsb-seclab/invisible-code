#include <stdlib.h>
#include <dfc/dfc_process.h>
#include <dfc/dfc_utils.h>
#include <mm/tee_mmu.h>
#include <mm/core_mmu.h>

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

TEE_Result add_va_pa_mappings(DFC_PROCESS *curr_process, MEM_BLOB *mem_map_target_blob) {
	TEE_Result res;
	void *mem_map_va = NULL;
	LEN_TYPE mem_map_len = 0;
	DFC_MEMORY_MAP *dfc_map_arr;
	LEN_TYPE curr_map_num = 0;

	// try to load the blob containing memory map.
	res = load_blob_data(mem_map_target_blob, &mem_map_va, &mem_map_len);	
	if(res) {
		goto clean_up;
	}

	// sanity
	assert(mem_map_len != 0);
	// make sure that we have discrete number of memory maps.
	if(mem_map_len % sizeof(DFC_MEMORY_MAP) != 0) {
		res = TEE_ERROR_GENERIC;
		goto clean_up;
	}

	dfc_map_arr = (DFC_MEMORY_MAP*)mem_map_va;
	//iterate thru each DFC map from 
	for(curr_map_num = 0; curr_map_num < (mem_map_len/sizeof(DFC_MEMORY_MAP)); curr_map_num++) {
		// add the mapping.
		res = add_memory_map(&(curr_process->mem_map_list), &(dfc_map_arr[curr_map_num]));
		if(res) {
			goto clean_up;
		}

	}
	return TEE_SUCCESS;
	clean_up:
		if(mem_map_va) {
			free(mem_map_va);
		}
	return res;
}
