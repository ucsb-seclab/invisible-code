#include "drm_utils.h"
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/mempolicy.h>
#include <linux/mman.h>

#ifdef DEBUG_DFC
__maybe_unused static void print_abort_regs(struct thread_abort_regs *regs)
{
	printk("[-] dumping regs\n");
	printk("\t usr_sp = 0x%x", regs->usr_sp);
	printk("\t usr_lr = 0x%x", regs->usr_lr);
	printk("\t spsr= 0x%x", regs->spsr);
	printk("\t elr = 0x%x\n", regs->elr);
	printk("\t r0 = 0x%x", regs->r0);
	printk("\t r1 = 0x%x", regs->r1);
	printk("\t r2 = 0x%x", regs->r2);
	printk("\t r3 = 0x%x\n", regs->r3);
	printk("\t r4 = 0x%x", regs->r4);
	printk("\t r5 = 0x%x", regs->r5);
	printk("\t r6 = 0x%x", regs->r6);
	printk("\t r7 = 0x%x\n", regs->r7);
	printk("\t r8 = 0x%x", regs->r8);
	printk("\t r9 = 0x%x", regs->r9);
	printk("\t r10 = 0x%x\n", regs->r10);
	printk("\t r11 = 0x%x", regs->r11);
	printk("\t ip = 0x%x", regs->ip);
	printk("\t pad = 0x%x\n\n", regs->pad);
}
#endif

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
__maybe_unused static int free_page_by_address(struct mm_struct *mm, const unsigned long address)
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
	struct vm_area_struct *vma;
	int res = 0;
	struct page *page;
	// lock, make sure we are not trying
	// to add an entry to the global map list
	// at the same time as another thread
	
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
	
#ifdef DEBUG_DFC
	curr_page = page_by_address(target_mm, va);
	
	phy_start = (unsigned long)(page_to_phys(curr_page));
					
	printk("[+] %s: trying to remap mm=%p, va %lx, old pa %lx, new pa %lx, size %lx [%lx]\n", __func__, (void*)target_mm, va, phy_start, pa_start, size, PAGE_SIZE);
#endif
	
	up_read(&target_mm->mmap_sem);
	
	// first unmap, This ensures that the VMA gets splitted guy
	if(sys_munmap(start_vma, size)) {
		pr_err("[!] %s: Failed to unmap stuff\n", __func__);
		res = -1;
		goto out;
	}
	
	// now mmap will create new vma
	if(sys_mmap_pgoff(start_vma, size, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) != start_vma) {
		pr_err("[!] %s: Failed to mmap stuff\n", __func__);
		res = -1;
		goto out;
	}
	
	down_read(&target_mm->mmap_sem);
	
	vma = find_vma(target_mm, start_vma);
#ifdef DEBUG_DFC
	printk("[+] %s: VA=%lx, END=%lx, FLAGS=%lx\n", __func__, vma->vm_start, vma->vm_end, (unsigned long)vma->vm_page_prot);
#endif
	//printk("[+] %s: Trying to remap\n", __func__);
	res = remap_pfn_range(vma, start_vma, pa_start >> PAGE_SHIFT, size, vma->vm_page_prot);
	//res = vm_iomap_memory(vma, pa_start, size);
	if(res) {
		pr_err("[+] %s: remap_pfn_range failed\n", __func__);
		res = -1;
	}
	//io_remap_pfn_range(vma, start_vma, pa_start >> PAGE_SHIFT, size, PAGE_READONLY);
	// unset semaphore
	up_read(&target_mm->mmap_sem);

	down_read(&target_mm->mmap_sem);

		page = page_by_address(target_proc->mm, va);
		paddr = page_to_phys(page);
#ifdef DRM_DEBUG
		printk("\n\n[+] %s: va %lx seems mapped to %lx\n\n", __func__, va, paddr);
#endif
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
		unsigned long *num_of_entries,
		struct dfc_local_map **local_map)
{
	int ret = 0;
	unsigned long num_pages;
	void *start_vma, *end_vma;
	phys_addr_t phy_start;
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
#ifdef DRM_DEBUG
		printk("[+] %lx - %lx\n", start_vma, end_vma);
#endif
		if(!(vm_flags & VM_EXEC) && ((vm_flags & VM_READ) || (vm_flags & VM_WRITE))) {
			while(start_vma < end_vma) {
				curr_page = page_by_address(target_mm, start_vma);
				if(curr_page) {
					phy_start = (unsigned long)(page_to_phys(curr_page));
					if(phy_start != 0 && !(phy_start >= OPTEE_MIN && phy_start <= OPTEE_MAX)) {
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
					//printk(" [-] %lx does not have page allocated\n", start_vma);
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
	*num_of_entries = num_entries;

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
				#ifdef DRM_DEBUG
					printk("%s: adding entry>\n\tva:%llx\n\tpa:%llx\n\tsize:%llu\n\tattr:%llx\n", __func__,
							curr_loc_map->va, curr_loc_map->pa, curr_loc_map->size, curr_loc_map->attr);
				#endif
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

void copy_pt_to_abort_regs(struct thread_abort_regs *target_regs, struct pt_regs *src_regs, unsigned long addr)
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
        target_regs->ip = src_regs->ARM_ip;
        target_regs->usr_sp = src_regs->ARM_sp;
        target_regs->usr_lr = src_regs->ARM_lr;

		target_regs->elr = addr;

		if thumb_mode(src_regs)
			target_regs->spsr |= PSR_T_BIT;
		else
			target_regs->spsr &= ~PSR_T_BIT;

	}
	// XXX: add error print/panic if NULL
#ifdef DEBUG_DFC
	print_abort_regs(target_proc->dfc_regs);
#endif
}

void copy_abort_to_pt_regs(struct pt_regs *regs,struct thread_abort_regs *dfc_regs) {
	regs->ARM_r0 = dfc_regs->r0;
	regs->ARM_r1 = dfc_regs->r1;
	regs->ARM_r2 = dfc_regs->r2;
	regs->ARM_r3 = dfc_regs->r3;
	regs->ARM_r4 = dfc_regs->r4;
	regs->ARM_r5 = dfc_regs->r5;
	regs->ARM_r6 = dfc_regs->r6;
	regs->ARM_r7 = dfc_regs->r7;
	regs->ARM_r8 = dfc_regs->r8;
	regs->ARM_r9 = dfc_regs->r9;
	regs->ARM_r10 = dfc_regs->r10;
	regs->ARM_fp = dfc_regs->r11; // fp is r11 in ARM mode and r7 in thumb mode

	regs->ARM_ip = dfc_regs->ip;
	regs->ARM_sp = dfc_regs->usr_sp;
	regs->ARM_lr = dfc_regs->usr_lr;
	regs->ARM_pc = dfc_regs->elr;

	if (dfc_regs->spsr & PSR_T_BIT){
		regs->ARM_cpsr |= PSR_T_BIT;
	}else{
		regs->ARM_cpsr &= ~PSR_T_BIT;
	}

}
