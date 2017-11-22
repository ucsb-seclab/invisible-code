#!/bin/bash
LLVM_DIR=$LLVM_ROOT/../cmake
mkdir build
echo "[*] Trying to Run Cmake"
cd build
cmake ..
echo "[*] Trying to make"
make -j8
