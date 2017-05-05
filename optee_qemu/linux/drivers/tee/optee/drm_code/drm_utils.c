#include "drm_utils.h"
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/gfp.h>
#include <linux/mm.h>


// This funcion does the page table walk and gets the physical page corresponding
// to the provided address, if one exists.
static struct page *page_by_address(const struct mm_struct *const mm, const unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	struct page *page = NULL;

	pgd = pgd_offset(mm, address);
	if (!pgd || !pgd_present(*pgd))
		goto do_return;

	pud = pud_offset(pgd, address);
	if (!pud || !pud_present(*pud))
		goto do_return;

	pmd = pmd_offset(pud, address);
	if (!pmd || !pmd_present(*pmd))
		goto do_return;

	pte = pte_offset_kernel(pmd, address);
	if (!pte || !pte_present(*pte))
		goto do_return;

	page = pte_page(*pte);
do_return:
	return page;
}

/*
 * this function will return the pte entry for a given address
 * */
static pte_t *pte_by_address(const struct mm_struct *const mm, const unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, address);
	if (!pgd || !pgd_present(*pgd))
		goto do_return;

	pud = pud_offset(pgd, address);
	if (!pud || !pud_present(*pud))
		goto do_return;

	pmd = pmd_offset(pud, address);
	if (!pmd || !pmd_present(*pmd))
		goto do_return;

	pte = pte_offset_kernel(pmd, address);
	if (!pte_present(*pte))
		pte = NULL;

do_return:
	return pte;
}


struct page *get_task_page(struct task_struct *target_proc, const unsigned long addr)
{
	struct mm_struct *target_mm;
	struct page *curr_page = NULL;

	if(target_proc == NULL || addr == 0) {
		pr_err(DFC_ERR_HDR "Invalid arguments passed to the function\n", __func__);
		return NULL;
	}

	// get the mm_struct for the task
	target_mm = target_proc->mm;

	// we are accessing the page tables of the process.
	// set the semaphore
	down_read(&target_mm->mmap_sem);

	curr_page = page_by_address(target_mm, addr);
	// unset the semaphore
	up_read(&target_mm->mmap_sem);

	return curr_page;
}

// this function takes the pa range and adds it to
// the global list of dfc_mem_map
// it will also take the va of the secure blob
// and modify the memory mappings to set the corresponding
// set of pte with the secure world PA
int add_secure_mem(struct task_struct *target_proc,
		const unsigned long va,
		const unsigned long pa_start,
		const unsigned long size)
{

	unsigned long start_vma, end_vma;
	unsigned long current_pa;
	struct dfc_sec_mem_map *entry;
	struct mm_struct *target_mm;
	struct page *curr_page;
	pte_t *ptep = NULL;
	pte_t pte;
	pgprot_t protbits; // here we store the prot bits of the page

	// lock, make sure we are not trying
	// to add an entry to the global map list
	// at the same time as another thread
	mutex_lock(&global_sec_mem_map_mutex);

	entry = (struct dfc_sec_mem_map*)kzalloc(sizeof(struct dfc_sec_mem_map), GFP_KERNEL);

	if (entry == NULL){
		mutex_unlock(&global_sec_mem_map_mutex);
		return -ENOMEM;
	}

	target_mm = target_proc->mm;

	entry->pa_start = pa_start;
	entry->pa_end = pa_start+size;

	// add entry in tail
	list_add_tail(&(entry->list), &(global_sec_mem_map->list));

	mutex_unlock(&global_sec_mem_map_mutex);

	// now we need to do a pt walk, find the entries relative to the given va
	start_vma = va;
	end_vma = va+size;
	current_pa = pa_start;
	//set semaphore
	down_read(&target_mm->mmap_sem);
	while (start_vma < end_vma){
	
		ptep = pte_by_address(target_mm, start_vma);
		// get the pte and clear it from current mm
		pte = ptep_get_and_clear(target_mm, start_vma, ptep);
		// now let's get the page from the pte
		curr_page = pte_page(pte);
		protbits = pgprot_val(curr_page);
		__free_page(curr_page);		//let's be a nice guy, and free the page

		// now let's get the page for the given physical address
		curr_page = phys_to_page(pa_start);
		pte = mk_pte(curr_page, protbits);
		set_pte(pte);

		start_vma += PAGE_SIZE;
		current_pa += PAGE_SIZE; // increment also the pointer the physical address to point to next page
	}
	// unset semaphore
	up_read(&target_mm->mmap_sem);

	return 0;
}



bool is_secure_mem(unsigned long phy_addr)
{
	struct dfc_sec_mem_map *curr_map, *tmp_map;
	if(global_sec_mem_map != NULL) {
		list_for_each_entry_safe(curr_map, tmp_map, &(global_sec_mem_map->list), list) {
			// check if the phy_addr is within the range?
			if(curr_map->pa_start <= phy_addr && curr_map->pa_end > phy_addr) {
				return true;
			}
		}
	} else {
		pr_err(DFC_ERR_HDR "Secure memory map is NULL", __func__);
	}
	return false;
}

// this + is_secure_mem are to be used in the abort handler in order to check first
// if address is mapped and then if the S bit is (un)set
bool is_address_mapped(struct task_struct *target_proc, unsigned long addr_to_check)
{
	return get_task_page(target_proc, addr_to_check) != NULL;
}


int get_all_data_pages(
		struct task_struct *target_proc,
		struct dfc_mem_map **target_mm_blob,
		uint64_t *num_of_entries,
		struct dfc_local_map **local_map)
{
	int ret = -1;
	unsigned long start_vma, end_vma;
	unsigned long phy_start;
	// Total number of entries in the result_map.
	unsigned long num_entries = 0, curr_entry_num=0;
	struct dfc_mem_map *local_mm_blob;
	int vm_flags;
	// unsigned int uf_flags;
	struct dfc_local_map *result_map = NULL;
	struct dfc_local_map *curr_loc_map = NULL;
	struct vm_area_struct *curr_vma;
	struct page *curr_page;
	struct mm_struct *target_mm;

	if(target_proc == NULL || target_mm_blob == NULL || num_of_entries == NULL || local_map == NULL) {
		pr_err(DFC_ERR_HDR "Invalid arguments passed to the function\n", __func__);
		return ret;
	}
	// get the mm_struct for the task
	target_mm = target_proc->mm;
	// set the semaphore
	down_read(&target_mm->mmap_sem);
	curr_vma = target_mm->mmap;


	curr_loc_map = kzalloc(sizeof(*curr_loc_map), GFP_KERNEL);
	INIT_LIST_HEAD(&(curr_loc_map->list));
	result_map = curr_loc_map;

	while(curr_vma != NULL) {
		start_vma = curr_vma->vm_start;
		end_vma = curr_vma->vm_end;
		vm_flags = curr_vma->vm_flags;
		// print all non-executable pages
		printk("[+] %lx - %lx\n", start_vma, end_vma);
		if(!(vm_flags & VM_EXEC) && ((vm_flags & VM_READ) || (vm_flags & VM_WRITE))) {
			while(start_vma < end_vma) {
				curr_page = page_by_address(target_mm, start_vma);
				if(curr_page) {
					phy_start = (unsigned long)(page_to_phys(curr_page));
					if(phy_start != 0) {
						// allocata a new node
						curr_loc_map = kzalloc(sizeof(*curr_loc_map), GFP_KERNEL);
						// TODO: check for curr_loc_map to be NULL.
						// INIT_LIST_HEAD(&(curr_loc_map->list));
						// XXX: init_head should not be needed list_add
						// initializes prev and next elems of the list
						list_add_tail(&(curr_loc_map->list), &(result_map->list));

						curr_loc_map->va = start_vma;
						curr_loc_map->pa = phy_start;
						curr_loc_map->size = PAGE_SIZE;
						curr_loc_map->attr = vm_flags;
						//printk("adding entry>\n\tva:%llx\n\tpa:%llx\n\tsize:%llu\n\tattr:%llu\n",
						//	curr_loc_map->va, curr_loc_map->pa, curr_loc_map->size, curr_loc_map->attr);

						num_entries++;
						// flush the cache, to ensure that data is flushed into RAM.
						flush_cache_range(curr_vma, start_vma, start_vma + PAGE_SIZE);
						// This is to ensure that the page will not be mapped out by linux kernel.
						ret = get_user_pages(target_proc, target_proc->mm, start_vma, 1, (vm_flags & VM_WRITE) != 0, 0, &(curr_loc_map->target_page), NULL);
						if(ret <= 0) {
							pr_err(DFC_ERR_HDR "get_user_pages returned: %d\n", __func__, ret);
						}

						curr_loc_map->is_locked = true;

						//printk("  [+] %lx -> %lx\n", start_vma, phy_start);
					}
				} else {
					printk(" [-] %lx does not have page allocated\n", start_vma);
				}
				start_vma += PAGE_SIZE;
			}
		}
		curr_vma = curr_vma->vm_next;
	}

	// unset the semaphore
	up_read(&target_mm->mmap_sem);

	// OK, Now convert all entries in result_map to DFC_MEMORY_MAP
	printk("------------------------------------------------------------------------------------\n\n\n");
	if(num_entries > 0) {
		local_mm_blob = kzalloc(num_entries * sizeof(*local_mm_blob), GFP_KERNEL);
		curr_entry_num = 0;
		// iterate thru each entry
		list_for_each_entry(curr_loc_map, &(result_map->list), list) {
			local_mm_blob[curr_entry_num].va = curr_loc_map->va;
			local_mm_blob[curr_entry_num].pa = curr_loc_map->pa;
			local_mm_blob[curr_entry_num].size = curr_loc_map->size;
			local_mm_blob[curr_entry_num].attr = curr_loc_map->attr;
						printk("adding entry>\n\tva:%llx\n\tpa:%llx\n\tsize:%llu\n\tattr:%llu\n",
							curr_loc_map->va, curr_loc_map->pa, curr_loc_map->size, curr_loc_map->attr);
			curr_entry_num++;
		}
		if(num_entries != curr_entry_num) {
			pr_err(DFC_ERR_HDR "Number of entries added:%ld are not same as numer of entries fetched:%ld\n", __func__, num_entries, curr_entry_num);
		}
		// copy the result back to the caller.
		*target_mm_blob = local_mm_blob;
		*num_of_entries = num_entries;
		*local_map = result_map;
		ret = 0;
	} else {
		pr_err(DFC_ERR_HDR "No data pages found for the process pid:%d", __func__, target_proc->pid);
		ret = -2;
	}

	return ret;
}

void release_all_data_pages(struct dfc_local_map **local_map)
{
	struct dfc_local_map *curr_map, *tmp_map;
	if(local_map != NULL && *local_map != NULL) {
		list_for_each_entry_safe(curr_map, tmp_map, &((*local_map)->list), list) {
			// if this page was writable?
			// set the dirty bit, so that all the writes
			// by the secure world would be reflected.
			if((curr_map->attr & VM_WRITE) && curr_map->is_locked) {
				set_page_dirty_lock(curr_map->target_page);
			}

			// was this page locked by us?
			// if yes, release it
			if(curr_map->is_locked) {
				// Now release the page.
				page_cache_release(curr_map->target_page);
			 }
			 list_del(&(curr_map->list));

			 kfree(curr_map);
		}

		list_del(&((*local_map)->list));
		kfree(*local_map);
		*local_map = NULL;
		printk("[+] Super OK\n");
	} else {
		pr_err(DFC_ERR_HDR "Invalid pointer passed\n", __func__);
	}
}

void modify_task_regs(struct task_struct *target_proc, struct pt_regs *target_regs)
{
	if(target_regs != NULL && target_proc != NULL) {
		struct pt_regs *src_pt_regs = task_pt_regs(target_proc);
		// copy all the registers into task saved registers.
		memcpy(src_pt_regs, target_regs, sizeof(*target_regs));
	} else {
		pr_err(DFC_ERR_HDR "Invalid arguments, target_proc=%p, target_regs=%p\n", __func__, target_proc, target_regs);
	}
}
