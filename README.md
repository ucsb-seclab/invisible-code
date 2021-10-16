Invisible Code (DRM for Code)
===================


This repo contains all the things for Invisible Code project.

[Project Doc](https://docs.google.com/document/d/1muIj2ufTWKrO_Vm9HNLUlxmCOS9xLNe7MTpeLj16X_I/edit?usp=sharing)
----------


OPTEE (for QEMU)
-------------

The folder [optee_qemu](https://github.com/ucsb-seclab/invisible-code/tree/debug_hang/optee_qemu) contains OPTEE-OS for QEMU. 
Refer [README](https://github.com/ucsb-seclab/invisible-code/blob/debug_hang/optee_qemu/optee_os/README.md) for documentation.

**Getting the toolchains (only once):**
This is a one time thing you run only once after getting all the source code.
```
cd optee_qemu/build
make toolchains
make all
```
**Building:**
```
cd optee_qemu/build
make all
```
**Running:**
```
cd optee_qemu/build
make all run
```

You will see 2-terminals (ttys), one each for non-secure and secure side. In the non-secure side, run xtest: 

```
xtest
```
