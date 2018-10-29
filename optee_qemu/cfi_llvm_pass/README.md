# Building with IW-CFI
______
## Pre-reqs
1. Install clang+llvm 3.8

## Building
```
cd optee_qemu/cfi_llvm_pass
./build.sh
```
## Instrumentation
### Compile the `C` file to llvm bitcode using clang
Example: `2048_game`
```
cd optee_qemu/2048_game
clang -c -emit-llvm --target=armv7a -Wall -I./include -fomit-frame-pointer 2048.c -o 2048.plain.bc
```

The output bitcode file is: `2048.plain.bc`
### Instrument the bitcode file
Example: `2048_game`
For this we need the original bitcode file i.e., `2048.plain.bc`
```
cd optee_qemu/cfi_llvm_pass/build/IndirectCallCFIPass
opt -load=./libIndirectCallCFIPass.so -drmcfi -outputFuncs=<output_secure_functions_list> <path_to_input_bc_file> -sec_name=<name_of_the_secure_funtion> -o <path_to_output_bitcode_file>
```
Actual command:
```
cd optee_qemu/cfi_llvm_pass/build/IndirectCallCFIPass
opt -load=./libIndirectCallCFIPass.so -drmcfi -outputFuncs=all_sec_functions.txt ../../../2048_game/2048.plain.bc -sec_name=secure_code -o 2048.cfi.instr.bc
```
* `2048.cfi.instr.bc`: The output instrumented bitcode file.
* `all_sec_functions.txt`: File that contains the list of all secure functions.


### Convert the instrumented bitcode to object file
Example: `2048_game`
```
cd optee_qemu/cfi_llvm_pass/build/IndirectCallCFIPass
clang -c --target=armv7a 2048.cfi.instr.bc -o 2048.cfi.instr.o
```
The target output object file is: `2048.cfi.instr.o`
### Convert the object file to executable
```
arm-linux-gnueabi-gcc <input_object_file> -o 2040.cfi.instr.out
```
Example:
```
cd optee_qemu/2048_game
arm-linux-gnueabi-gcc ../cfi_llvm_pass/build/IndirectCallCFIPass/2048.cfi.instr.o -o 2040.cfi.instr.out
```
### Patching the executable file to add addresses of secure functions
```
cd optee_qemu/cfi_llvm_pass/elfinja
python patch_secure_functions.py -f <path_to_secure_functions_txt> -i <input_executable_file> -o <patched_executable_file>
```
Example: `2048_game`
```
cd optee_qemu/cfi_llvm_pass/elfinja
python patch_secure_functions.py -f ../build/IndirectCallCFIPass/all_sec_functions.txt -i ../../2048_game/2048.cfi.instr.out -o ../../2048_game/2048.cfi.instr.final
```
