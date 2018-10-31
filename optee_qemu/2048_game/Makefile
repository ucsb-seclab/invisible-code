DRM = -Wall -I./include -fomit-frame-pointer

CC      = $(HOST_CROSS_COMPILE)gcc
LD      = $(HOST_CROSS_COMPILE)ld
AR      = $(HOST_CROSS_COMPILE)ar
NM      = $(HOST_CROSS_COMPILE)nm
OBJCOPY = $(HOST_CROSS_COMPILE)objcopy
OBJDUMP = $(HOST_CROSS_COMPILE)objdump
READELF = $(HOST_CROSS_COMPILE)readelf

CLANG = clang-4.0
OPT   = opt-4.0
LLDRM  = --target=armv7a --target=arm-linux-gnueabihf -ccc-gcc-name armv7a-linux-gnueabihf-gcc --gcc-toolchain=../toolchains/aarch32 --sysroot=../toolchains/aarch32/arm-linux-gnueabihf/libc


all:
	$(CLANG) -c -emit-llvm $(LLDRM) $(DRM) 2048.c -o 2048.plain.bc
	$(OPT) -load=../cfi_llvm_pass/build/IndirectCallCFIPass/libIndirectCallCFIPass.so -drmcfi -outputFuncs=all_sec_functions.txt 2048.plain.bc -sec_name=secure_code -o 2048.cfi.instr.bc
	$(CLANG) -c $(LLDRM) -Wall -fomit-frame-pointer 2048.cfi.instr.bc -o 2048.cfi.instr.o
	$(CC) $(DRM) 2048.cfi.instr.o -o 2048_instr
	python ../cfi_llvm_pass/elfinja/patch_secure_functions.py -f all_sec_functions.txt -i 2048_instr -o 2048


clean:
	rm -f 2048

