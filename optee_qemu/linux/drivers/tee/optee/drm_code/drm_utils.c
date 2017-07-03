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
	pte_t *ptep;
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

	ptep = pte_offset_map(pmd, address);
	if (!ptep || !pte_present(*ptep))
		goto do_return;

	page = pte_page(*ptep);
	pte_unmap(ptep);

do_return:
	return page;
}

/*
 * this function will return the pte entry for a given address
 * */
static int free_page_by_address(struct mm_struct *mm, const unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep = NULL;
	pte_t pte;
	struct page *curr_page;

	int rc = -1;

	pgd = pgd_offset(mm, address);
	if (!pgd || !pgd_present(*pgd))
		goto do_return;

	pud = pud_offset(pgd, address);
	if (!pud || !pud_present(*pud))
		goto do_return;

	pmd = pmd_offset(pud, address);
	if (!pmd || !pmd_present(*pmd))
		goto do_return;

	ptep = pte_offset_map(pmd, address);
	if (!ptep ){
		goto do_return;
	}
	if( !pte_present(*ptep)){
		pte_unmap(ptep);
		goto do_return;
	}

	pte = ptep_get_and_clear(mm, address, ptep);
	pte_unmap(ptep);
	// now let's get the page from the pte
	curr_page = pte_page(pte);
	__free_page(curr_page);		//let's be a nice guy, and free the page
	rc = 0;
	
	// XXX: ADD CHECK // return result

do_return:
	return rc;
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

/* this function takes the pa range
 and the va of the secure blob and modify the
 memory mappings to set the corresponding
 set of pte with the secure world PA freeing
 the physical page */
int add_secure_mem(struct task_struct *target_proc,
		const unsigned long va,
		const unsigned long pa_start,
		const unsigned long size)
{

	unsigned long start_vma, end_vma;
	unsigned long current_pa, paddr;
	struct mm_struct *target_mm;
	struct page *curr_page;
	struct vm_area_struct *vma;
	int res = 0;
	pte_t *pte;
	spinlock_t *ptl;
	struct page *page;
	// lock, make sure we are not trying
	// to add an entry to the global map list
	// at the same time as another thread
	
	printk("trying to remap va %lx, pa %lx, size %lx [%lx]\n", va, pa_start, size, PAGE_SIZE);

	target_mm = target_proc->mm;

	/*mutex_lock(&global_sec_mem_map_mutex);

	entry = (struct dfc_sec_mem_map*)kzalloc(sizeof(struct dfc_sec_mem_map), GFP_KERNEL);

	if (entry == NULL){
		mutex_unlock(&global_sec_mem_map_mutex);
		res = -ENOMEM;
		goto out;
	}


	entry->pa_start = pa_start;
	entry->pa_end = pa_start+size;

	// add entry in tail
	list_add_tail(&(entry->list), &(global_sec_mem_map->list));

	mutex_unlock(&global_sec_mem_map_mutex);*/

	// now we need to do a pt walk, find the entries relative to the given va
	start_vma = va;
	end_vma = va+size;
	current_pa = pa_start;
	//set semaphore
	down_read(&target_mm->mmap_sem);
	while (start_vma < end_vma){
		vma = find_vma(target_mm, start_vma);
		res = free_page_by_address(target_mm, start_vma);
		if( res != 0){
			pr_err("error while freeing page at va %lx\n", start_vma);
			goto out;
		}

		// now let's get the page for the given physical address
		curr_page = phys_to_page(pa_start);
		printk("vma == %lx, page = %p, pa = %x\n", start_vma, curr_page, page_to_phys(curr_page));
		if (curr_page == NULL){
			pr_err("cannot get curr_page");
			res = -1;
			goto out;
		}

		pte = get_locked_pte(target_mm, start_vma, &ptl);
		set_pte_at(target_mm, start_vma, pte, mk_pte(curr_page, PAGE_READONLY));
		pte_unmap_unlock(pte, ptl);
		//res = vm_insert_page(vma, start_vma, curr_page);
		if (res != 0){
			pr_err("something went wrong inserting page! [%x]\n", res);
			goto out;
		}

		start_vma += PAGE_SIZE;
		current_pa += PAGE_SIZE; // increment also the pointer the physical address to point to next page
	}
	// unset semaphore
	up_read(&target_mm->mmap_sem);

	down_read(&target_mm->mmap_sem);

		page = page_by_address(target_proc->mm, va);
		paddr = page_to_phys(page);
		printk("\n\n[+] va %lx seems mapped to %lx\n\n", va, paddr);
	up_read(&target_mm->mmap_sem);
out:
	return res;
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
		uint64_t *num_of_entries,
		struct dfc_local_map **local_map)
{
	int ret = 0;
	unsigned long num_pages;
	unsigned long start_vma, end_vma;
	unsigned long phy_start;
	// Total number of entries in the result_map.
	unsigned long num_entries = 0;
	int vm_flags;
	// unsigned int uf_flags;
	struct dfc_local_map *result_map = NULL;
	struct dfc_local_map *curr_loc_map = NULL;
	struct vm_area_struct *curr_vma;
	struct page *curr_page;
	struct mm_struct *target_mm;

	if(target_proc == NULL || num_of_entries == NULL || local_map == NULL) {
		pr_err(DFC_ERR_HDR "Invalid arguments passed to the function\n", __func__);
		ret = -2;
		goto out;
	}
	// get the mm_struct for the task
	target_mm = target_proc->mm;
	// set the semaphore
	down_read(&target_mm->mmap_sem);
	curr_vma = target_mm->mmap;


	curr_loc_map = kzalloc(sizeof(*curr_loc_map), GFP_KERNEL);

	if (curr_loc_map == NULL){
		ret = -1;
		goto out;
	}
	//XXX TODO: better handling of curr_loc_map != NULL here and inside the loop!

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
						if (curr_loc_map == NULL){
							ret = -3;
							goto out;
						}
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
						num_pages = get_user_pages(target_proc, target_proc->mm, start_vma, 1,
										(vm_flags & VM_WRITE) != 0, 0, &(curr_loc_map->target_page), NULL);
						if(num_pages <= 0) {
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
	
	// store results back
	*local_map = result_map;
	*num_of_entries = num_entries-1;

out:
	if (ret < 0)
		panic(DFC_ERR_HDR "error while getting/locking user data pages (%d)", __func__, ret);

	return ret;
}


/* finalize_data_pages will take the list of data pages
 * and store it in the given dst (as an array) this is needed
 * to pass the pages to the secure world, where we will
 * "remap" them" */
int finalize_data_pages(
		unsigned long num_entries,
		struct dfc_mem_map *local_mm_blob,
		struct dfc_local_map *result_map)
{
	unsigned long curr_entry_num;
	int ret = 0;

	struct dfc_local_map *curr_loc_map = NULL;
	// Convert all entries in result_map to DFC_MEMORY_MAP
	if(num_entries > 0) {
		curr_entry_num = 0;
		// iterate thru each entry
		list_for_each_entry(curr_loc_map, &(result_map->list), list) {
			if(curr_loc_map){
				local_mm_blob[curr_entry_num].va = curr_loc_map->va;
				local_mm_blob[curr_entry_num].pa = curr_loc_map->pa;
				local_mm_blob[curr_entry_num].size = curr_loc_map->size;
				local_mm_blob[curr_entry_num].attr = curr_loc_map->attr;
						printk("%s: adding entry>\n\tva:%llx\n\tpa:%llx\n\tsize:%llu\n\tattr:%llx\n", __func__,
							curr_loc_map->va, curr_loc_map->pa, curr_loc_map->size, curr_loc_map->attr);
				curr_entry_num++;
			}
		}

		if(num_entries != curr_entry_num)
			pr_err(DFC_ERR_HDR "Number of entries added:%ld"
					"are not same as numer of entries fetched:%ld\n",
					__func__, num_entries, curr_entry_num);

		ret = 0;
	} else {
		pr_err(DFC_ERR_HDR "No data pages found for the process", __func__);
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

void copy_pt_to_abort_regs(struct thread_abort_regs *target_regs, struct pt_regs *src_regs)
{
    if(target_regs != NULL && src_regs != NULL) {
        target_regs->r0 = src_regs->ARM_r0;
        target_regs->r1 = src_regs->ARM_r1;
        target_regs->r2 = src_regs->ARM_r2;
        target_regs->r3 = src_regs->ARM_r3;
        target_regs->r4 = src_regs->ARM_r4;
        target_regs->r5 = src_regs->ARM_r5;
        target_regs->r6 = src_regs->ARM_r6;
        target_regs->r7 = src_regs->ARM_r7;
        target_regs->r8 = src_regs->ARM_r8;
        target_regs->r9 = src_regs->ARM_r9;
        target_regs->r10 = src_regs->ARM_r10;
        target_regs->r11 = src_regs->ARM_fp;
        target_regs->ip = src_regs->ARM_pc;
        target_regs->usr_sp = src_regs->ARM_sp;
        target_regs->usr_lr = src_regs->ARM_lr;
    }
}
