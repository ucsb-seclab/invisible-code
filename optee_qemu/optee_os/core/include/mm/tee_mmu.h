/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef TEE_MMU_H
#define TEE_MMU_H

#include <tee_api_types.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/tee_blob_manager.h>
#include <kernel/user_ta.h>
#include <kernel/user_blob.h>
#include <kernel/linux_mm_types.h>

/*-----------------------------------------------------------------------------
 * Allocate context resources like ASID and MMU table information
 *---------------------------------------------------------------------------*/
TEE_Result tee_mmu_init(struct user_ta_ctx *utc);
TEE_Result tee_mmu_blob_init(struct user_blob_ctx *utc);

void tee_mmu_blob_set_ctx(struct tee_blob_ctx *ctx);
uintptr_t tee_mmu_get_blob_load_addr(const struct tee_blob_ctx *const ctx);
void tee_mmu_blob_map_clear(struct user_blob_ctx *utc);

TEE_Result tee_mmu_map_blob_code(struct user_blob_ctx *ubc, paddr_t pa, uint32_t prot);
TEE_Result tee_mmu_blob_map_add_segment(struct user_blob_ctx *utc, paddr_t pa,
			vaddr_t va, size_t size, uint32_t prot, uint32_t idx);
uint32_t convert_prot_from_linux(uint32_t prot);

/*-----------------------------------------------------------------------------
 * tee_mmu_final - Release context resources like ASID
 *---------------------------------------------------------------------------*/
void tee_mmu_final(struct user_ta_ctx *utc);

/* Map stack of a user TA.  */
void tee_mmu_map_stack(struct user_ta_ctx *utc, paddr_t pa, size_t size,
			uint32_t prot);
/*
 * Map a code segment of a user TA, this function may be called multiple
 * times if there's several segments.
 */
TEE_Result tee_mmu_map_add_segment(struct user_ta_ctx *utc, paddr_t base_pa,
			size_t offs, size_t size, uint32_t prot);

void tee_mmu_map_clear(struct user_ta_ctx *utc);

/* Map parameters for a user TA */
TEE_Result tee_mmu_map_param(struct user_ta_ctx *utc,
			struct tee_ta_param *param);

/*
 * TA private memory is defined as TA image static segment (code, ro/rw static
 * data, heap, stack). The sole other virtual memory mapped to TA are memref
 * parameters. These later are considered outside TA private memory as it
 * might be accessed by the TA and its client(s).
 */
bool tee_mmu_is_vbuf_inside_ta_private(const struct user_ta_ctx *utc,
				       const void *va, size_t size);

bool tee_mmu_is_vbuf_intersect_ta_private(const struct user_ta_ctx *utc,
					  const void *va, size_t size);

/*-----------------------------------------------------------------------------
 * tee_mmu_user_va2pa - Translate virtual user address to physical address
 * given the user context.
 * Interface is deprecated, use virt_to_phys() instead.
 *---------------------------------------------------------------------------*/
TEE_Result tee_mmu_user_va2pa_helper(const struct user_ta_ctx *utc, void *ua,
				     paddr_t *pa);

/*-----------------------------------------------------------------------------
 * tee_mmu_user_va2pa - Translate physical address to virtual user address
 * given the user context.
 * Interface is deprecated, use phys_to_virt() instead.
 *---------------------------------------------------------------------------*/
TEE_Result tee_mmu_user_pa2va_helper(const struct user_ta_ctx *utc,
				     paddr_t pa, void **va);

/*-----------------------------------------------------------------------------
 * tee_mmu_check_access_rights -
 *---------------------------------------------------------------------------*/
TEE_Result tee_mmu_check_access_rights(const struct user_ta_ctx *utc,
				       uint32_t flags, uaddr_t uaddr,
				       size_t len);

/*-----------------------------------------------------------------------------
 * If ctx is NULL user mapping is removed and ASID set to 0
 *---------------------------------------------------------------------------*/
void tee_mmu_set_ctx(struct tee_ta_ctx *ctx);
struct tee_ta_ctx *tee_mmu_get_ctx(void);

/* Returns virtual address to which TA is loaded */
uintptr_t tee_mmu_get_load_addr(const struct tee_ta_ctx *const ctx);

/* init some allocation pools */
void teecore_init_ta_ram(void);
void teecore_init_pub_ram(void);

uint32_t tee_mmu_user_get_cache_attr(struct user_ta_ctx *utc, void *va);

TEE_Result tee_mmu_register_shm(paddr_t pa, size_t len, uint32_t attr);

#endif
