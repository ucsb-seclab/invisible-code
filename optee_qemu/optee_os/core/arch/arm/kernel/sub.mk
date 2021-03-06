srcs-y += tee_ta_manager.c
srcs-y += tee_blob_manager.c
srcs-$(CFG_WITH_USER_TA) += user_ta.c
srcs-y += user_blob.c
srcs-y += static_ta.c
srcs-y += elf_load.c
srcs-y += tee_time.c

srcs-$(CFG_SECURE_TIME_SOURCE_CNTPCT) += tee_time_arm_cntpct.c
srcs-$(CFG_SECURE_TIME_SOURCE_REE) += tee_time_ree.c

srcs-$(CFG_ARM32_core) += proc_a32.S
srcs-$(CFG_ARM32_core) += spin_lock_a32.S
srcs-$(CFG_ARM64_core) += proc_a64.S
srcs-$(CFG_ARM64_core) += spin_lock_a64.S
srcs-$(CFG_TEE_CORE_DEBUG) += spin_lock_debug.c
srcs-$(CFG_ARM32_core) += ssvce_a32.S
srcs-$(CFG_ARM64_core) += ssvce_a64.S
srcs-$(CFG_ARM64_core) += cache_helpers_a64.S
srcs-$(CFG_PL310) += tz_ssvce_pl310_a32.S
srcs-$(CFG_PL310) += tee_l2cc_mutex.c

srcs-$(CFG_ARM32_core) += thread_a32.S
srcs-$(CFG_ARM64_core) += thread_a64.S
srcs-y += thread.c
srcs-y += abort.c
srcs-$(CFG_WITH_VFP) += vfp.c
ifeq ($(CFG_WITH_VFP),y)
srcs-$(CFG_ARM32_core) += vfp_a32.S
srcs-$(CFG_ARM64_core) += vfp_a64.S
endif
srcs-y += trace_ext.c
srcs-$(CFG_ARM32_core) += misc_a32.S
srcs-$(CFG_ARM64_core) += misc_a64.S
srcs-y += mutex.c
srcs-y += wait_queue.c
srcs-$(CFG_PM_STUBS) += pm_stubs.c

srcs-$(CFG_GENERIC_BOOT) += generic_boot.c
ifeq ($(CFG_GENERIC_BOOT),y)
srcs-$(CFG_ARM32_core) += generic_entry_a32.S
srcs-$(CFG_ARM64_core) += generic_entry_a64.S
endif

ifeq ($(CFG_CORE_UNWIND),y)
srcs-$(CFG_ARM32_core) += unwind_arm32.c
srcs-$(CFG_ARM64_core) += unwind_arm64.c
endif
