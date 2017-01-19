/*
 * Header that contains structure of all the messages shared between secure world and non-secure world
 * for DRM For Code.
 * 
 * Authors: Machiry
 */
 
#ifndef DFC_MESSAGES_H
#define DFC_MESSAGES_H

#include <dfc/dfc_common.h>


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
} TERMINATE_PROCESS_MSG;


// base msg exchanged between S and NS worlds.
typedef struct {
    // message type
    DFC_MESSAGE_TYPE msg_type;
    // actual message data in blob format.
    // the blob has to be interpreted as different
    // structures based on the msg_type.
    MEM_BLOB msg_data_blob;
} DFC_MSG;

#endif
