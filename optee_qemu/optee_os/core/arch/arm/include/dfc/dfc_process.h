/***

**/
#ifndef DFC_PROCESS_H
#define DFC_PROCESS_H

#include <dfc/dfc_common.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <mm/core_mmu.h>
#include <kernel/mutex.h>
#include <kernel/vfp.h>
#include <types_ext.h>
#include <util.h>

typedef enum {
    SETUP,
    RUNNING,
    INTERRUPTED,
    KILLED
} DFC_PROCESS_STATE;



struct dfc_process_st {
    // pid for secure side
    S_PID_TYPE s_pid;
    // pid for non-secure side.
    NS_PID_TYPE ns_pid;
    THREAD_REGS regs;
    
    // process state
    DFC_PROCESS_STATE currState;
    
    // TODO: check following fields 
    // may or may not be needed
    vaddr_t stack_va_end;
    uint32_t flags;
    
    // mutex for critical sections.
    struct mutex common_mutex;
    
    #ifdef ARM64
	vaddr_t kern_sp;	/* Saved kernel SP for interrupts */
    #endif
    
    bool is_32bit;		/* true if 32-bit ta, false if 64-bit ta */
    
    
    // following fields needed for memory management.
    size_t stack_size;	/* size of stack */
	
	struct dfc_memory_map_node_list *mem_map_list;
	
#if defined(CFG_WITH_VFP)
	struct thread_user_vfp_state vfp;
#endif
};

typedef struct dfc_process_st DFC_PROCESS;

TAILQ_HEAD(dfc_process_list_head, dfc_process_st);

typedef struct {
    // list of all DFC_PROCESS.
    struct dfc_process_list_head process_list;
} DFC_GLOBAL_STATE;

extern DFC_GLOBAL_STATE dfc_glob_state;
#endif
