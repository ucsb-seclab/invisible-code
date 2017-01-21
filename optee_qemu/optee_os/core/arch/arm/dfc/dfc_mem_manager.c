#include <dfc/dfc_common.h>
#include <dfc/dfc_mem_manager.h>
#include <kernel/thread.h>
#include <mm/core_mmu.h>
#include <mm/pgt_cache.h>

// This function traverses the provided src_list
// to find if there is existing node with the same va
// as the one provided (i.e to_check)
static struct dfc_memory_map_node_list* get_existing_map(struct dfc_memory_map_node_list *src_list, DFC_MEMORY_MAP *to_check) {                                                         
    struct dfc_memory_map_node_list *to_ret = NULL, *curr_node;
    if(to_check) {
        curr_node = src_list;
        while(curr_node) {
            if(curr_node->va == to_check->va) {
                to_ret = curr_node;
                break;
            }
            curr_node = curr_node->flink;
        }
    }   
    return to_ret;    
}


// set the current page table mapping for curr_proc
void set_dfc_process_map(DFC_PROCESS* curr_proc) {
    struct thread_specific_data *tsd = thread_get_tsd();
    struct dfc_memory_map_node_list *m_map_list;
    // Level 1 page table
    struct core_mmu_table_info dir_info;
    // list that contains all the l2 page tables needed
    // to store the mappings.
    struct pgt_cache *pgt_cache;
    
    // This is needed to clean up ttbr0 and ttbr1
    // check ARM MMU for details about ttbr0 and ttbr1
    core_mmu_set_user_map(NULL);
    
#ifdef CFG_SMALL_PAGE_USER_TA
    // first free all the page table that are assigned to this thread.
    pgt_free(&tsd->pgt_cache, tsd->ctx && is_user_ta_ctx(tsd->ctx));
#else
    // This means only 1MB pages are allowed and this decreases
    // the flexibility of out approach.
    assert(false);
#endif

#ifdef CFG_PAGED_USER_TA
    // We do not know, how to handle paging.
    // so if this option is enabled. we fault.
    assert(false);
#endif

    // get the base address of the level 1 page table.
    // this will be the address we store in ttbr0
    core_mmu_get_user_pgdir(&dir_info);
    // initialize all level 1 entries to 0
    memset(dir_info.table, 0, dir_info.num_entries * sizeof(uint32_t));
    // get the mem map list.
    m_map_list = curr_proc->mem_map_list;
    // allocate required number of x2 page tables for all the
    // va <-> pa mappings
    while(m_map_list) {
        //TODO: Can we do this? or pgt_cache has to be allocated only once?
        //pgt_alloc(pgt_cache, NULL, m_map_list->va, m_map_list->va + m_map_list->size - 1);
        m_map_list = m_map_list->flink;
    }
    
    //OK we allocated all the required page tables.
    
    // next we need to write corresponding VA and PA into the page table entries.
    
    // next write the physical address of dir_info into ttbr0
    // and then we are done.
    
}

TEE_Result add_memory_map(struct dfc_memory_map_node_list **node_list, DFC_MEMORY_MAP *to_add) {
    TEE_Result res;
    struct dfc_memory_map_node_list *dst_node = NULL;
    if(!to_add) {
        res = TEE_ERROR_GENERIC;
        goto error_out;
    }
    // check if there is existing va/pa mapping.
    if(*node_list) {    
        dst_node = get_existing_map(*node_list, to_add);
    } 
    
    // if there is no existing node?
    if(!dst_node) {
        // create a new node and add it to the head of the list    
        dst_node = calloc(1, sizeof(struct dfc_memory_map_node_list));
        if(!dst_node) {
            res = TEE_ERROR_OUT_OF_MEMORY;
            goto error_out;
        }
        dst_node->flink = *node_list;
        if(*node_list) {
            (*node_list)->blink = dst_node;
        }
        *node_list = dst_node;
    }
    // copy the new map into target node.
    dst_node->va = to_add->va;
    dst_node->pa = to_add->pa;
    dst_node->attr = to_add->attr;
    dst_node->size = to_add->size;
    return TEE_SUCCESS;   
    
    error_out:
        return res;
}
