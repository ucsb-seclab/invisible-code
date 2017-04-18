#include <assert.h>
#include <compiler.h>
#include <keep.h>
#include <kernel/panic.h>
#include <kernel/tee_blob_manager.h>
#include <kernel/thread.c>
#include <kernel/user_blob.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mm.h>
#include <mm/core_mmu.h>





/*
 * loads the blob into memory
 */
static TEE_Result blob_load()
{
	return TEE_SUCCESS;
}
