
#ifndef DFC_COMMON_H
#define DFC_COMMON_H

#include <tee_api_types.h>
#include <stdlib.h>

#ifdef ARM32
struct dpc_process_regs {
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
	uint32_t r12;
	uint32_t usr_sp;
	uint32_t usr_lr;
	uint32_t svc_spsr;
	uint32_t svc_sp;
	uint32_t svc_lr;
	uint32_t pc;
	uint32_t cpsr;
};
#endif /*ARM32*/

#ifdef ARM64
struct dpc_process_regs {
	uint64_t sp;
	uint64_t pc;
	uint64_t cpsr;
	uint64_t x[31];
};
#endif /*ARM64*/

typedef TOKEN_TYPE uint32_t
typedef PHY_ADDR_TYPE uint64_t
typedef VA_ADDR_TYPE uint64_t
typedef LEN_TYPE uint64_t
typedef MM_ATTR_TYPE uint64_t
typedef NS_PID_TYPE uint64_t
typedef S_PID_TYPE uint64_t
typedef struct dpc_process_regs THREAD_REGS

// basic structure of each memory map.
// TODO: change this to be meaningful.
struct dfc_mem_map {
    VA_ADDR_TYPE va;
    PHY_ADDR_TYPE pa;
    LEN_TYPE size;
    MM_ATTR_TYPE attr;
}; 

typedef struct dfc_mem_map DFC_MEMORY_MAP;

// structure used for passing memory blobs.
// if contains phyiscal address of the blob and its length.
typedef struct {
    PHY_ADDR_TYPE blob_phy_addr;
    LEN_TYPE blob_len;
} MEM_BLOB;

// list of memory map nodes of the process.
struct dfc_memory_map_node_list {
    VA_ADDR_TYPE va;
    PHY_ADDR_TYPE pa;
    MM_ATTR_TYPE attr;
    LEN_TYPE size;
    struct dfc_memory_map_node_list *flink;
    struct dfc_memory_map_node_list *blink;
};

#endif
