#include <dfc/dfc_common.h>
#include <dfc/dfc_mem_manager.h>
#include <kernel/thread.h>
#include <mm/core_mmu.h>
#include <mm/pgt_cache.h>


static void set_dfc_map_to_pt(struct core_mmu_table_info *tbl_info,
		struct dfc_memory_map_node_list *curr_map)
{
	unsigned end;
	unsigned idx;
	paddr_t pa;

	/* va, len and pa should be block aligned */
	assert(!core_mmu_get_block_offset(tbl_info, region->va));
	assert(!core_mmu_get_block_offset(tbl_info, region->size));
	assert(!core_mmu_get_block_offset(tbl_info, region->pa));

	idx = core_mmu_va2idx(tbl_info, curr_map->va);
	end = core_mmu_va2idx(tbl_info, curr_map->va + curr_map->size);
	pa = curr_map->pa;

	while (idx < end) {
		core_mmu_set_entry(tbl_info, idx, pa, curr_map->attr);
		idx++;
		pa += 1 << tbl_info->shift;
	}
}


static void convert_dfc_map_to_pd(struct core_mmu_table_info *dir_info,
			struct dfc_memory_map_node_list *curr_map, struct pgt **pgt,
			struct core_mmu_table_info *pg_info)
{
    struct dfc_memory_map_node_list r = *curr_map;
	vaddr_t end = r.va + r.size;
	uint32_t pgt_attr = (r.attr & TEE_MATTR_SECURE) | TEE_MATTR_TABLE;

	while (r.va < end) {
		if (!pg_info->table ||
		     r.va >= (pg_info->va_base + CORE_MMU_PGDIR_SIZE)) {
			/*
			 * We're assigning a new translation table.
			 */
			unsigned int idx;

			assert(*pgt); /* We should have alloced enough */

			/* Virtual addresses must grow */
			assert(r.va > pg_info->va_base);

			idx = core_mmu_va2idx(dir_info, r.va);
			pg_info->table = (*pgt)->tbl;
			pg_info->va_base = core_mmu_idx2va(dir_info, idx);
#ifdef CFG_PAGED_USER_TA
			assert((*pgt)->vabase == pg_info->va_base);
#endif
			*pgt = SLIST_NEXT(*pgt, link);

			core_mmu_set_entry(dir_info, idx,
					   virt_to_phys(pg_info->table),
					   pgt_attr);
		}

		r.size = MIN(CORE_MMU_PGDIR_SIZE - (r.va - pg_info->va_base),
			     end - r.va);
		if (!(r.attr & TEE_MATTR_PAGED))
			set_dfc_map_to_pt(pg_info, &r);
		r.va += r.size;
		r.pa += r.size;
	}
}

// Convert the VA<->PA mapping into mmu_user_map i.e ttbr0
void set_dfc_process_map(DFC_PROCESS* curr_proc, struct core_mmu_user_map *map) {
    struct thread_specific_data *tsd = thread_get_tsd();
    struct dfc_memory_map_node_list *m_map_list;
    // Level 1 page table
    struct core_mmu_table_info dir_info;
    // Level 2 page table info
    struct core_mmu_table_info pg_info;
    // list that contains all the l2 page tables needed
    // to store the mappings.
    struct pgt_cache *pgt_cache;
    struct pgt *pgt;
    
#ifdef CFG_PAGED_USER_TA
    // We do not know, how to handle paging.
    // so if this option is enabled. we fault.
    assert(false);
#endif
    
    // This is needed to clean up ttbr0 and ttbr1
    // check ARM MMU for details about ttbr0 and ttbr1
    core_mmu_set_user_map(NULL);
    
#ifdef CFG_SMALL_PAGE_USER_TA
    // first free all the page table that are assigned to this thread.
    pgt_free(&tsd->pgt_cache, tsd->ctx && is_user_ta_ctx(tsd->ctx));
#else
    // This means only 1MB pages are allowed and this decreases
    // the flexibility of our approach.
    assert(false);
#endif

    // get the base address of the level 1 page table.
    // this will be the address we store in ttbr0
    core_mmu_get_user_pgdir(&dir_info);
    // initialize all level 1 entries to 0
    memset(dir_info.table, 0, dir_info.num_entries * sizeof(uint32_t));
    // get the mem map list.
    m_map_list = curr_proc->mem_map_list;
    // allocate required number of L2 page tables for all the
    // va <-> pa mappings
    while(m_map_list) {
        pgt_alloc(pgt_cache, NULL, m_map_list->va, m_map_list->va + m_map_list->size - 1);
        m_map_list = m_map_list->flink;
    }
    
    pgt = SLIST_FIRST(pgt_cache);    
    core_mmu_set_info_table(&pg_info, dir_info->level + 1, 0, NULL);
    
    //OK we allocated all the required page tables.
    
    // next we need to convert DFC process map into page table entries.
    m_map_list = curr_proc->mem_map_list;
    while(m_map_list) {
        convert_dfc_map_to_pd(&dir_info, m_map_list, &pgt, &pg_info);
        m_map_list = m_map_list->flink;
    }
    
    // next write the physical address of dir_info into ttbr0
    core_mmu_get_ttbr0(&map, &dir_info);
    // this is the identifier for TLB
	map->ctxid = curr_proc->s_pid & 0xff;    
	
	//if you enable below line, you will be writing into ttbr0?
	// TODO: check it.
	//core_mmu_set_user_map(map);
}


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
    // TODO: convert the attributes into OP-TEE compatible.
    dst_node->attr = to_add->attr;
    dst_node->size = to_add->size;
    return TEE_SUCCESS;   
    
    error_out:
        return res;
}
