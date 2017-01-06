################################################################################
# Following variables defines how the NS_USER (Non Secure User - Client
# Application), NS_KERNEL (Non Secure Kernel), S_KERNEL (Secure Kernel) and
# S_USER (Secure User - TA) are compiled
################################################################################
override COMPILE_NS_USER   := 64
override COMPILE_NS_KERNEL := 64
override COMPILE_S_USER    := 64
override COMPILE_S_KERNEL  := 64

-include common.mk

################################################################################
# Paths to git projects and various binaries
################################################################################
ARM_TF_PATH			?= $(ROOT)/arm-trusted-firmware

EDK2_PATH			?= $(ROOT)/edk2
EDK2_BIN			?= $(EDK2_PATH)/QEMU_EFI.fd

QEMU_PATH			?= $(ROOT)/qemu

SOC_TERM_PATH			?= $(ROOT)/soc_term
STRACE_PATH			?= $(ROOT)/strace

DEBUG = 1

################################################################################
# Targets
################################################################################
all: arm-tf qemu soc-term linux strace update_rootfs
all-clean: arm-tf-clean busybox-clean linux-clean \
	optee-os-clean optee-client-clean qemu-clean \
	soc-term-clean check-clean strace-clean

-include toolchain.mk

################################################################################
# ARM Trusted Firmware
################################################################################
ARM_TF_EXPORTS ?= \
	CFLAGS="-O0 -gdwarf-2" \
	CROSS_COMPILE="$(CCACHE)$(AARCH64_CROSS_COMPILE)"

ARM_TF_FLAGS ?= \
	BL32=$(OPTEE_OS_BIN) \
	BL33=$(EDK2_BIN) \
	ARM_TSP_RAM_LOCATION=tdram \
	PLAT=qemu \
	DEBUG=0 \
	LOG_LEVEL=50 \
	ERROR_DEPRECATED=1 \
	BL32_RAM_LOCATION=tdram \
	SPD=opteed

arm-tf: optee-os edk2
	$(ARM_TF_EXPORTS) $(MAKE) -C $(ARM_TF_PATH) $(ARM_TF_FLAGS) all fip

arm-tf-clean:
	$(ARM_TF_EXPORTS) $(MAKE) -C $(ARM_TF_PATH) $(ARM_TF_FLAGS) clean

# FIXME: This is just too rough, we should build this just as we're doing for
#        FVP.
edk2: optee-os
ifeq ("$(wildcard $(EDK2_BIN))","")
	mkdir -p $(EDK2_PATH)
	wget -O $(EDK2_BIN) \
		http://snapshots.linaro.org/components/kernel/leg-virt-tianocore-edk2-upstream/716/QEMU-KERNEL-AARCH64/RELEASE_GCC49/QEMU_EFI.fd
endif
	mkdir -p $(ARM_TF_PATH)/build/qemu/release
	ln -sf $(OPTEE_OS_BIN) $(ARM_TF_PATH)/build/qemu/release/bl32.bin
	ln -sf $(EDK2_BIN) $(ARM_TF_PATH)/build/qemu/release/bl33.bin

################################################################################
# QEMU
################################################################################
qemu:
	cd $(QEMU_PATH); ./configure --target-list=aarch64-softmmu\
			$(QEMU_CONFIGURE_PARAMS_COMMON)
	$(MAKE) -C $(QEMU_PATH)

qemu-clean:
	$(MAKE) -C $(QEMU_PATH) distclean

################################################################################
# Busybox
################################################################################
BUSYBOX_COMMON_TARGET = fvp
BUSYBOX_CLEAN_COMMON_TARGET = fvp clean
BUSYBOX_COMMON_CCDIR = $(AARCH64_PATH)

busybox: busybox-common

busybox-clean: busybox-clean-common

busybox-cleaner: busybox-cleaner-common

################################################################################
# Linux kernel
################################################################################
LINUX_DEFCONFIG_COMMON_ARCH := arm64
LINUX_DEFCONFIG_COMMON_FILES := \
		$(LINUX_PATH)/arch/arm64/configs/defconfig \
		$(CURDIR)/kconfigs/qemu.conf

linux-defconfig: $(LINUX_PATH)/.config

LINUX_COMMON_FLAGS += ARCH=arm64

linux: linux-common

linux-defconfig-clean: linux-defconfig-clean-common

LINUX_CLEAN_COMMON_FLAGS += ARCH=arm64

linux-clean: linux-clean-common

LINUX_CLEANER_COMMON_FLAGS += ARCH=arm64

linux-cleaner: linux-cleaner-common

################################################################################
# OP-TEE
################################################################################
OPTEE_OS_COMMON_FLAGS += PLATFORM=vexpress-qemu_armv8a CFG_ARM64_core=y \
			 DEBUG=0 CFG_PM_DEBUG=0
optee-os: optee-os-common

OPTEE_OS_CLEAN_COMMON_FLAGS += PLATFORM=vexpress-qemu_armv8a
optee-os-clean: optee-os-clean-common

optee-client: optee-client-common

optee-client-clean: optee-client-clean-common

################################################################################
# Soc-term
################################################################################
soc-term:
	$(MAKE) -C $(SOC_TERM_PATH)

soc-term-clean:
	$(MAKE) -C $(SOC_TERM_PATH) clean

################################################################################
# xtest / optee_test
################################################################################
xtest: xtest-common

xtest-clean: xtest-clean-common

xtest-patch: xtest-patch-common

################################################################################
# hello_world
################################################################################
helloworld: helloworld-common

helloworld-clean: helloworld-clean-common

################################################################################
# strace
################################################################################
strace:
ifneq ("$(wildcard $(STRACE_PATH))","")
		cd $(STRACE_PATH) && \
		./bootstrap && \
		./configure --host=aarch64-linux-gnu CC=$(CROSS_COMPILE_NS_USER)gcc && \
		CC=$(CROSS_COMPILE_NS_USER)gcc $(MAKE)
endif

strace-clean:
ifneq ("$(wildcard $(STRACE_PATH))","")
		CC=$(CROSS_COMPILE_NS_USER)gcc \
			$(MAKE) -C $(STRACE_PATH) clean && \
		rm -f $(STRACE_PATH)/Makefile $(STRACE_PATH)/configure
endif

################################################################################
# Root FS
################################################################################
filelist-tee: filelist-tee-common
ifneq ("$(wildcard $(STRACE_PATH)/strace)","")
	@echo "file /bin/strace $(STRACE_PATH)/strace 755 0 0" >> $(GEN_ROOTFS_FILELIST)
endif

update_rootfs: update_rootfs-common

################################################################################
# Run targets
################################################################################
define run-help
	@echo "Run QEMU"
	@echo QEMU is now waiting to start the execution
	@echo Start execution with either a \'c\' followed by \<enter\> in the QEMU console or
	@echo attach a debugger and continue from there.
	@echo
	@echo To run xtest paste the following on the serial 0 prompt
	@echo tee-supplicant\&
	@echo sleep 0.1
	@echo xtest
	@echo
	@echo To run a single test case replace the xtest command with for instance
	@echo xtest 1004
endef

define launch-terminal
	@nc -z  127.0.0.1 $(1) || \
	xterm -title $(2) -e $(BASH) -c "$(SOC_TERM_PATH)/soc_term $(1)" &
endef

define wait-for-ports
       @while ! nc -z 127.0.0.1 $(1) || ! nc -z 127.0.0.1 $(2); do sleep 1; done
endef

.PHONY: run
# This target enforces updating root fs etc
run: all
	$(MAKE) run-only

.PHONY: run-only
run-only:
	$(call run-help)
	$(call launch-terminal,54320,"Normal World")
	$(call launch-terminal,54321,"Secure World")
	$(call wait-for-ports,54320,54321)
	cd $(ARM_TF_PATH)/build/qemu/release && \
	$(QEMU_PATH)/aarch64-softmmu/qemu-system-aarch64 \
		-nographic \
		-serial tcp:localhost:54320 -serial tcp:localhost:54321 \
		-machine virt,secure=on -cpu cortex-a57 -m 1057 -bios $(ARM_TF_PATH)/build/qemu/release/bl1.bin \
		-semihosting -d unimp \
		-initrd $(GEN_ROOTFS_PATH)/filesystem.cpio.gz \
		-kernel $(LINUX_PATH)/arch/arm64/boot/Image \
		-append 'console=ttyAMA0,38400 keep_bootcon root=/dev/vda2' \
		$(QEMU_EXTRA_ARGS)

ifneq ($(filter check,$(MAKECMDGOALS)),)
CHECK_DEPS := all
endif

ifneq ($(TIMEOUT),)
check-args := --timeout $(TIMEOUT)
endif

check: $(CHECK_DEPS)
	expect qemu-check.exp -- $(check-args) || \
		(if [ "$(DUMP_LOGS_ON_ERROR)" ]; then \
			echo "== $$PWD/serial0.log:"; \
			cat serial0.log; \
			echo "== end of $$PWD/serial0.log:"; \
			echo "== $$PWD/serial1.log:"; \
			cat serial1.log; \
			echo "== end of $$PWD/serial1.log:"; \
		fi; false)

check-only: check

check-clean:
	rm -f serial0.log serial1.log
