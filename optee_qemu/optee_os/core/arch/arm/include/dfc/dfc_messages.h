/*
 * Header that contains structure of all the messages shared between secure world and non-secure world
 * for DRM For Code.
 * 
 * Authors: Machiry
 */
 
#ifndef DFC_MESSAGES_H
#define DFC_MESSAGES_H

#ifdef ARM32
struct thread_abort_regs {
	uint32_t usr_sp;
	uint32_t usr_lr;
	uint32_t pad;
	uint32_t spsr;
	uint32_t elr;
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r4;
	uint32_t r5;
	uint32_t r6;
	uint32_t r7;
	uint32_t r8;
	uint32_t r9;
	uint32_t r10;
	uint32_t r11;
	uint32_t ip;
};
#endif /*ARM32*/

#ifdef ARM64
struct thread_abort_regs {
	uint64_t x0;	/* r0_usr */
	uint64_t x1;	/* r1_usr */
	uint64_t x2;	/* r2_usr */
	uint64_t x3;	/* r3_usr */
	uint64_t x4;	/* r4_usr */
	uint64_t x5;	/* r5_usr */
	uint64_t x6;	/* r6_usr */
	uint64_t x7;	/* r7_usr */
	uint64_t x8;	/* r8_usr */
	uint64_t x9;	/* r9_usr */
	uint64_t x10;	/* r10_usr */
	uint64_t x11;	/* r11_usr */
	uint64_t x12;	/* r12_usr */
	uint64_t x13;	/* r13/sp_usr */
	uint64_t x14;	/* r14/lr_usr */
	uint64_t x15;
	uint64_t x16;
	uint64_t x17;
	uint64_t x18;
	uint64_t x19;
	uint64_t x20;
	uint64_t x21;
	uint64_t x22;
	uint64_t x23;
	uint64_t x24;
	uint64_t x25;
	uint64_t x26;
	uint64_t x27;
	uint64_t x28;
	uint64_t x29;
	uint64_t x30;
	uint64_t elr;
	uint64_t spsr;
	uint64_t sp_el0;
};
#endif /*ARM64*/


// message types
typedef enum {
    // From NS: Decrypt the provided blob and start executing.
    DECRYPT_AND_EXECUTE = 1,
    // From NS: Add a mapping of VA to PA into the process memory map.
    ADD_VM_MAPPING,
    // From NS: Continue execution of the requested process.
    CONTINUE_EXECUTION,
    // From S: Ask for a free page to be added into the process memory map.
    // This is needed during setup phase.
    REQUEST_VM_MAPPING,
    // From S: an interrupt occured during execution of the process.
    // to be serviced by NS world.
    PROCESS_INTERRUPT,
    // from NS: a message from Non-secure world to stop
    // execution of the process.
    TERMINATE_PROCESS
} DFC_MESSAGE_TYPE;

typedef TOKEN_TYPE uint32_t
typedef PHY_ADDR_TYPE uint64_t
typedef VA_ADDR_TYPE uint64_t
typedef LEN_TYPE uint64_t
typedef MM_ATTR_TYPE uint64_t
typedef NS_PID_TYPE uint64_t
typedef S_PID_TYPE uint64_t
typedef struct thread_abort_regs THREAD_REGS

// basic structure of each memory map.
// TODO: change this to be meaningful.
typedef struct {
    VA_ADDR_TYPE va;
    PHY_ADDR_TYPE pa;
    MM_ATTR_TYPE attr;
} MEMORY_MAP_TYPE; 

// structure used for passing memory blobs.
// if contains phyiscal address of the blob and its length.
typedef struct {
    PHY_ADDR_TYPE blob_phy_addr;
    LEN_TYPE blob_len;
} MEM_BLOB;

// message structure for DECRYPT_AND_EXECUTE message.
typedef struct {
    // unique identifier 
    TOKEN_TYPE token;
    // process id used by the non-secure side.
    NS_PID_TYPE ns_pid;
    MEM_BLOB encrypted_blob;
    // blob containg base memory map to be used for the process.
    MEM_BLOB base_memory_map;
} DECRYPT_AND_EXECUTE_MSG;

// message structure for ADD_VM_MAPPING message.
typedef struct {
    // unique identifier 
    TOKEN_TYPE token;
    // pid of the process in secure world.
    S_PID_TYPE s_pid;
    // blob containing new memory maps that needed to be
    // added into the process address space.
    MEM_BLOB new_memory_map;
} ADD_VM_MAPPING_MSG;

typedef struct {
    // unique identifier 
    TOKEN_TYPE token;
    // pid in the non-secure world.
    NS_PID_TYPE ns_pid;
    // number of pages requested.
    LEN_TYPE num_pages;
} REQUEST_VM_MAPPING_MSG;

typedef struct {
    // unique identifier 
    TOKEN_TYPE token;
    // pid in the non-secure world.
    NS_PID_TYPE ns_pid;
    // registers of the process being interrupted.
    THREAD_REGS process_regs;    
} PROCESS_INTERRUPT_MSG;

// message structure for CONTINUE_EXECUTION message.
typedef struct {
    // this identifier should match
    // the identifier of previous
    // REQUEST_VM_MAPPING_MSG or PROCESS_INTERRUPT_MSG
    TOKEN_TYPE token;
    // pid of the process in secure world.
    S_PID_TYPE s_pid;
    // registers of the process being interrupted.
    THREAD_REGS process_regs;    
} CONTINUE_EXECUTION_MSG;

// message structure for TERMINATE_PROCESS message.
typedef struct {
    // unique identifier.
    TOKEN_TYPE token;
    // pid of the process in secure world.
    S_PID_TYPE s_pid;  
} TERMINATE_PROCESS;

#endif
