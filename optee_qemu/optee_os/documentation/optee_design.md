OP-TEE design
========================

# Contents

1.  [Introduction](#1-introduction)
2.  [Platform Initialization](#2-platform-initialization)
3.  [Secure Monitor Calls - SMC](#3-secure-monitor-calls---smc)
4.  [Thread handling](#4-thread-handling)
5.  [MMU](#5-mmu)
6.  [Stacks](#6-stacks)
7.  [Shared Memory](#7-shared-memory)
8.  [Pager](#8-pager)
9.  [Cryptographic abstraction layer](#9-cryptographic-abstraction-layer)
10. [libutee](#10-libutee)
11. [Trusted Applications](#11-trusted-applications)

# 1. Introduction
OP-TEE is a so called Trusted Execution Environment, in short a TEE, for ARM
based chips supporting TrustZone technology. OP-TEE consists of three
components.

+ [OP-TEE Client], which is the client API running in normal world user space.
+ [OP-TEE Linux Kernel driver], which is the driver that handles the
  communication between normal world user space and secure world.
+ [OP-TEE Trusted OS], which is the Trusted OS running in secure world.
  
OP-TEE was designed with scalability and portability in mind and as of now it
has been ported to quite a few different platforms, both ARMv7-A and ARMv8-A
from different vendors. For a full list, please see [Platforms Supported].

# 2. Platform initialization
TBD

# 3. Secure Monitor Calls - SMC
## 3.1 SMC handling
TBD

## 3.2 SMC Interface
The OP-TEE SMC interface is defined in two levels using [optee_smc.h] and
[optee_msg.h]. The former file defines SMC identifiers and what is passed in the
registers for each SMC. The latter file defines the OP-TEE Message protocol
which is not restricted to only SMC even if that currently is the only option
available.

## 3.3 Communication using SMC Interface
The main structure used for the SMC communication is defined in [struct
optee_msg_arg]. If we are looking into the source code, we could see that
communication mainly is achieved using `optee_msg_arg` and `thread_smc_args`,
where `optee_msg_arg` could be seen as the main structure. What will happen is
that the [OP-TEE Linux Kernel driver] will get the parameters either from
[OP-TEE Client] or directly from an internal service in the Linux kernel. The
TEE driver will populate the struct `optee_msg_arg` with the parameters plus
some additional bookkeeping information.  Parameters for the SMC are passed in
registers 1 to 7, register 0 holds the SMC id which among other things tells
whether it is a standard or a fast call.

# 4. Thread handling
The Trusted OS uses a couple of threads to be able to support running jobs in
parallel (not fully enabled!). There are handlers for different purposes. In
[thread.c] you will find a function called `thread_init_primary` which assigns
`init_handlers` (functions) that should be called when Trusted OS receives
standard or fast calls, FIQ and PSCI calls. There are default handlers for these
services, but the platform can decide if they want to implement their own
platform specific handlers instead.

## Synchronization
OP-TEE has three primitives for synchronization of threads and CPUs:
spin-lock, mutex, and condvar.

### Spin-lock
A spin-lock is represented as an `unsigned int`. This is the most primitive
lock. Interrupts should be disabled before attempting to take a spin-lock
and should remain disabled until the lock is released. A spin-lock is
initialized with `SPINLOCK_UNLOCK`.

| Function | Purpose |
|----------|---------|
| `cpu_spin_lock()` | Locks a spin-lock |
| `cpu_spin_trylock()` | Locks a spin-lock if unlocked and returns `0` else the spin-lock is unchanged and the function returns `!0`|
| `cpu_spin_unlock()` | Unlocks a spin-lock |

### Mutex
A mutex is represented by `struct mutex`. A mutex can be locked and
unlocked with interrupts enabled or disabled, but only from a normal
thread. A mutex can't be used in an interrupt handler, abort handler or
before a thread has been selected for the CPU. A mutex is initialized with
either `MUTEX_INITIALIZER` or `mutex_init()`.

| Function | Purpose |
|----------|---------|
|`mutex_lock()` | Locks a mutex. If the mutex is unlocked this is a fast operation, else the function issues an RPC to wait in normal world. |
| `mutex_unlock()` | Unlocks a mutex. If there's no waiters this is a fast operation, else the function issues an RPC to wake up a waiter in normal world. |
| `mutex_trylock()` | Locks a mutex if unlocked and returns `true` else the mutex is unchanged and the function returns `false`. |
| `mutex_destroy()` | Asserts that the mutex is unlocked and there's no waiters, after this the memory used by the mutex can be freed. |

When a mutex is locked it's owned by the thread calling `mutex_lock()` or
`mutex_trylock()`, the mutex may only be unlocked by the thread owning the
mutex. A thread should not exit to TA user space when holding a mutex.

### Condvar
A condvar is represented by `struct condvar`. A condvar is similar to a
pthread_condvar_t in the pthreads standard, only less advanced. Condition
variables are used to wait for some condition to be fulfilled and are
always used together a mutex. Once a condition variable has been used
together with a certain mutex, it must only be used with that mutex until
destroyed. A condvar is initialized with `CONDVAR_INITIALIZER` or
`condvar_init()`.

| Function | Purpose |
|----------|---------|
| `condvar_wait()` | Atomically unlocks the supplied mutex and waits in normal world via an RPC for the condition variable to be signaled, when the function returns the mutex is locked again. |
| `condvar_signal()` | Wakes up one waiter of the condition variable (waiting in `condvar_wait()`) |
| `condvar_broadcast()` | Wake up all waiters of the condition variable. |

The caller of `condvar_signal()` or `condvar_broadcast()` should hold the
mutex associated with the condition variable to guarantee that a waiter
doesn't miss the signal.

# 5. MMU
## Translation tables
OP-TEE uses several L1 translation tables, one large spanning 4 GiB and two
or more small tables spanning 32 MiB. The large translation table handles
kernel mode mapping and matches all addresses not covered by the small
translation tables. The small translation tables are assigned per thread
and covers the mapping of the virtual memory space for one TA context.

Memory space between small and large translation table is configured by
TTBRC. TTBR1 always points to the large translation table. TTBR0 points to
the a small translation table when user mapping is active and to the large
translation table when no user mapping is currently active.

The translation tables has certain alignment constraints, the alignment (of
the physical address) has to be the same as the size of the translation
table. The translation tables are statically allocated to avoid fragmentation of
memory due to the alignment constraints.

Each thread has one small L1 translation table of its own. Each TA context
has a compact representation of its L1 translation table. The compact
representation is used to initialize the thread specific L1 translation
table when the TA context is activated.

![Select xlation table](images/xlat_table.png "Select xlation table")

## Translation tables and switching to normal world
When switching to normal world either via an IRQ or RPC there's a chance
that secure world will resume execution on a different CPU. This means that
the new CPU need to be configured with the context of the currently active
TA. This is solved by always setting the TA context in the CPU when
resuming execution. Here's room for improvements since it's more likely
than not that it's the same CPU that resumes execution in secure world.

# 6. Stacks
Different stacks are used during different stages. The stacks are:
- Secure monitor stack (128 bytes), bound to the CPU. Only available if
  OP-TEE is compiled with a secure monitor always the case if the target is
  ARMv7-A but never for ARMv8-A.
- Temp stack (small ~1KB), bound to the CPU. Used when transitioning from
  one state to another. Interrupts are always disabled when using this
  stack, aborts are fatal when using the temp stack.
- Abort stack (medium ~2KB), bound to the CPU. Used when trapping a data
  or pre-fetch abort. Aborts from user space are never fatal the TA is only
  killed. Aborts from kernel mode are used by the pager to do the demand
  paging, if pager is disabled all kernel mode aborts are fatal.
- Thread stack (large ~8KB), not bound to the CPU instead used by the current
  thread/task. Interrupts are usually enabled when using this stack.

*Notes for ARMv7/AArch32:*

| Stack  | Comment |
|--------|---------|
| Temp   | Assigned to `SP_SVC` during entry/exit, always assigned to `SP_IRQ` and `SP_FIQ` |
| Abort  | Always assigned to `SP_ABT` |
| Thread | Assigned to `SP_SVC` while a thread is active |

*Notes for AArch64:*
There are only two stack pointers, `SP_EL1` and `SP_EL0`, available for OP-TEE
in AArch64. When an exception is received stack pointer is always `SP_EL1` which
is used temporarily while assigning an appropriate stack pointer for `SP_EL0`.
**`SP_EL1` is always assigned the value of `thread_core_local[cpu_id]`.** This
structure has some spare space for temporary storage of registers and also keeps
the relevant stack pointers. In general when we talk about assigning a stack
pointer to the CPU below we mean `SP_EL0`.

## Boot
During early boot the CPU is configured with the temp stack which is used until
OP-TEE exits to normal world the first time.

*Notes for AArch64:*
`SPSEL` is always `0` on entry/exit to have `SP_EL0` acting as stack pointer.

## Normal entry
Each time OP-TEE is entered from normal world the temp stack is used as the
initial stack. For fast calls this is the only stack used. For normal calls an
empty thread slot is selected and the CPU switches to that stack.

## Normal exit
Normal exit occurs when a thread has finished its task and the thread is freed.
When the main thread function, tee_entry_std(), returns interrupts are disabled
and the CPU switches to the temp stack instead. The thread is freed and OP-TEE
exits to normal world.

## RPC exit
RPC exit occurs when OP-TEE need some service from normal world. RPC can
currently only be performed with a thread is in running state. RPC is initiated
with a call to thread_rpc() which saves the state in a way that when the thread
is restored it will continue at the next instruction as if this function did a
normal return. CPU switches to use the temp stack before returning to normal
world.

## IRQ exit
IRQ exit occurs when OP-TEE receives an IRQ, which is always handled in normal
world. IRQ exit is similar to RPC exit but it's `thread_irq_handler()` and
`elx_irq()` (respectively for ARMv7-A/Aarch32 and for Aarch64) that saves the
thread state instead. The thread is resumed in the same way though.

*Notes for ARMv7/AArch32:*
SP_IRQ is initialized to temp stack instead of a separate stack.  Prior to
exiting to normal world CPU state is changed to SVC and temp stack is selected.

*Notes for AArch64:*
`SP_EL0` is assigned temp stack and is selected during IRQ processing. The
original `SP_EL0` is saved in the thread context to be restored when resuming.

## Resume entry
OP-TEE is entered using the temp stack in the same way as for normal entry. The
thread to resume is looked up and the state is restored to resume execution. The
procedure to resume from an RPC exit or an IRQ exit is exactly the same.

## Syscall
Syscalls are executed using the thread stack.

*Notes for ARMv7/AArch32*:
Nothing special `SP_SVC` is already set with thread stack.

*Notes for syscall AArch64*:

Early in the exception processing the original `SP_EL0` is saved in `struct
thread_svc_regs` in case the TA is executed in AArch64.

Current thread stack is assigned to `SP_EL0` which is then selected.

When returning `SP_EL0` is assigned what's in `struct thread_svc_regs`. This
allows `tee_svc_sys_return_helper()` having the syscall exception handler return
directly to `thread_unwind_user_mode()`.

# 7. Shared Memory
Shared Memory is a block of memory that is shared between the non-secure and the
secure world. It is used to transfer data between both worlds.

## Shared Memory Allocation
The shared memory is allocated by the Linux driver from a pool `struct
shm_pool`, the pool contains:
* The physical address of the start of the pool
* The size of the pool
* Whether or not the memory is cached
* List of chunk of memory allocated.

Note that:
- The shared memory pool is physically contiguous.
- The shared memory area is not secure as it is used by both non-secure and
  secure world.

### Shared Memory Configuration
It is the Linux kernel driver for OP-TEE that is responsible for initializing
the shared memory pool, given information provided by the Trusted OS. The Linux
driver issues a SMC call `OPTEE_SMC_GET_SHM_CONFIG` to retrieve the information
* Physical address of the start of the pool
* Size of the pool
* Whether or not the memory is cached

The shared memory pool configuration is platform specific. The memory mapping,
including the area `MEM_AREA_NSEC_SHM` (shared memory with non-secure world), is
retrieved by calling the platform-specific function `bootcfg_get_memory()`.
Please refer to this function and the area type `MEM_AREA_NSEC_SHM` to see the
configuration for the platform of interest. The Linux driver will then
initialize the shared memory pool accordingly.

### Shared Memory Chunk Allocation
It is the Linux kernel driver for OP-TEE that is responsible for allocating
chunks of shared memory. OP-TEE linux kernel driver relies on linux kernel
generic allocation support (`CONFIG_GENERIC_ALLOCATION`) to allocation/release
of shared memory physical chunks. OP-TEE linux kernel driver relies on linux
kernel dma-buf support (`CONFIG_DMA_SHARED_BUFFER`) to track shared memory
buffers references.

## Shared Memory Usage

### From the Client Application
The client application can ask for shared memory allocation using the
GlobalPlatform Client API function `TEEC_AllocateSharedMemory()`. The client
application can also provide shared memory through the GlobalPlatform Client API
function `TEEC_RegisterSharedMemory()`. In such a case, the provided memory must
be physically contiguous so that the Trusted OS, that does not handle
scatter-gather memory, is able to use the provided range of memory addresses.
Note that the reference count of a shared memory chunk is incremented when
shared memory is registered, and initialized to 1 on allocation.

### From the Linux Driver
Occasionally the Linux kernel driver needs to allocate shared memory for the
communication with secure world, for example when using buffers of type
TEEC_TempMemoryReference.

### From the Trusted OS
In case the Trusted OS needs information from the TEE supplicant (dynamic TA
loading, REE time request,...), shared memory must be allocated. Allocation
depends on the use case. The Trusted OS asks for the following shared memory
allocation:
- `optee_msg_arg` structure, used to pass the arguments to the non-secure world,
   where the allocation will be done by sending a `OPTEE_SMC_RPC_FUNC_ALLOC`
   message.
- In some cases, a payload might be needed for storing the result from TEE
  supplicant, for example when loading a Trusted Application. This type of
  allocation will be done by sending the message
  `OPTEE_MSG_RPC_CMD_SHM_ALLOC(OPTEE_MSG_RPC_SHM_TYPE_APPL,...)`, which then
  will return:
  - the physical address of the shared memory
  - a handle to the memory, that later on will be used later on when freeing
    this memory.

### From the TEE Supplicant
The TEE supplicant is also working with shared memory, used to exchange data
between normal and secure worlds. The TEE supplicant receives a memory address
from the Trusted OS, used to store the data. This is for example the case when a
Trusted Application is loaded. In this case, the TEE supplicant must register
the provided shared memory in the same way a client application would do,
involving the Linux driver.

# 8. Pager
OP-TEE currently requires ~256 KiB RAM for OP-TEE kernel memory. This is not a
problem if OP-TEE uses TrustZone protected DDR, but for security reasons OP-TEE
may need to use TrustZone protected SRAM instead. The amount of available SRAM
varies between platforms, from just a few KiB up to over 512 KiB. Platforms with
just a few KiB of SRAM can???t be expected to be able to run a complete TEE
solution in SRAM. But those with 128 to 256 KiB of SRAM can be expected to have
a capable TEE solution in SRAM. The pager provides a solution to this by demand
paging parts of OP-TEE using virtual memory.

## Secure memory
TrustZone protected SRAM is generally considered more secure than TrustZone
protected DRAM as there's usually more attack vectors on DRAM. The attack
vectors are hardware dependent and can be different for different platforms.

## Backing store
TrustZone protected DRAM or in some cases non-secure DRAM is used as backing
store. The data in the backing store is integrity protected with one hash
(SHA-256) per page (4KiB). Readonly pages aren't encrypted since the OP-TEE
binary itself is not encrypted.

## Partitioning of memory
The code that handles demand paging must always be available as it would
otherwise lead to deadlock. The virtual memory is partitioned as:

```
  Type      Sections
+--------------+-----------------+
|              | text            |
|              | rodata          |
|              | data            |
| unpaged      | bss             |
|              | heap1           |
|              | nozi            |
|              | heap2           |
+--------------+-----------------+
| init / paged | text_init       |
|              | rodata_init     |
+------------- +-----------------+
| paged        | text_pageable   |
|              | rodata_pageable |
+--------------+-----------------+
| demand alloc |                 |
|              |                 |
+--------------+-----------------+
```
Where "`nozi`" stands for "not zero initialized", this section contains entry
stacks (thread stack when TEE pager isn't enabled) and translation tables (TEE
pager cached translation table when the pager is enabled and LPAE MMU is used).

The "`init`" area is available when OP-TEE is initializing and contains
everything that is needed to initialize the pager. After the pager has been
initialized this area will be used for demand paged instead.

The "`demand alloc`" area is a special area where the pages are allocated and
removed from the pager on demand. Those pages are returned when OP-TEE doesn't
need them any longer. The thread stacks currently belongs this area. This means
that when a stack isn't used the physical pages can be used by the pager for
better performance.

The technique to gather code in the different area is based on compiling all
functions and data into separate sections. The unpaged text and rodata is then
gathered by linking all object files with `--gc-sections` to eliminate sections
that are outside the dependency graph of the entry functions for unpaged
functions. A script analyzes this ELF file and generates the bits of the final
link script. The process is repeated for init text and rodata.  What isn't
"unpaged" or "init" becomes "paged".

## Partitioning of the binary
The binary is partitioned into four parts as:
```
+----------+
| Header   |
+----------+
| Init     |
+----------+
| Hashes   |
+----------+
| Pageable |
+----------+
```
Header is defined as:
```c
#define OPTEE_MAGIC             0x4554504f
#define OPTEE_VERSION           1
#define OPTEE_ARCH_ARM32        0
#define OPTEE_ARCH_ARM64        1

struct optee_header {
        uint32_t magic;
        uint8_t version;
        uint8_t arch;
        uint16_t flags;
        uint32_t init_size;
        uint32_t init_load_addr_hi;
        uint32_t init_load_addr_lo;
        uint32_t init_mem_usage;
        uint32_t paged_size;
};
```

The header is only used by the loader of OP-TEE, not OP-TEE itself. To
initialize OP-TEE the loader loads the complete binary into memory and copies
what follows the header and the following `init_size` bytes to
`(init_load_addr_hi << 32 | init_load_addr_lo)`. `init_mem_usage` is used by the
loader to be able to check that there's enough physical memory available for
OP-TEE to be able to initialize at all. The loader supplies in `r0/x0` the
address of the first byte following what wasn't copied and jumps to the load
address to start OP-TEE.

## Initializing the pager
The pager is initialized as early as possible during boot in order to minimize
the "init" area. The global variable `tee_mm_vcore` describes the virtual memory
range that is covered by the level 2 translation table supplied to
`tee_pager_init()`.

### Assign pageable areas
A virtual memory range to be handled by the pager is registered with a call to
`tee_pager_add_core_area()`.

```c
bool tee_pager_add_area(tee_mm_entry_t *mm, uint32_t flags, const void *store,
			const void *hashes);
```

which takes a pointer to `tee_mm_entry_t` to tell the range, flags to tell how
memory should be mapped (readonly, execute etc), and pointers to backing store
and hashes of the pages.

### Assign physical pages
Physical SRAM pages are supplied by calling `tee_pager_add_pages()`

```c
void tee_pager_add_pages(tee_vaddr_t vaddr, size_t npages, bool unmap);
```

`tee_pager_add_pages()` takes the physical address stored in the entry mapping
the virtual address "vaddr" and "npages" entries after that and uses it to map
new pages when needed. The unmap parameter tells whether the pages should be
unmapped immediately since they doesn't contain initialized data or be kept
mapped until they need to be recycled. The pages in the "init" area are supplied
with `unmap == false` since those page have valid content and are in use.

## Invocation
The pager is invoked as part of the abort handler. A pool of physical pages are
used to map different virtual addresses. When a new virtual address needs to be
mapped a free physical page is mapped at the new address, if a free physical
page can't be found the oldest physical page is selected instead. When the page
is mapped new data is copied from backing store and the hash of the page is
verified. If it's OK the pager returns from the exception to resume the
execution.

# 9. Cryptographic abstraction layer
Cryptographic operations are implemented inside the TEE core by the
[LibTomCrypt] library. An abstraction layer allows for replacing the default
implementation, as explained in [crypto.md].

# 10. libutee
TBD

# 11. Trusted Applications
## Format
Trusted Applications consists of a signed ELF file.

The format a TA is:
```
<Signed header>
<ELF>
```

Where `<ELF>` is the content of a standard ELF file and `<Signed header>`
consists of:

| Type | Name | Comment |
|------|------|---------|
| `uint32_t` | magic | Holds the magic number `0x4f545348` |
| `uint32_t` | img_type | image type, values defined by enum shdr_img_type |
| `uint32_t` | img_size | image size in bytes |
| `uint32_t` | algo | algorithm, defined by public key algorithms `TEE_ALG_*` from TEE Internal API specification |
| `uint16_t` | hash_size | size of the signed hash |
| `uint16_t` | sig_size | size of the signature |
| `uint8_t[hash_size]` | hash | Hash of the fields above and the `<ELF>` above |
| `uint8_t[sig_size]` | signature | Signature of hash |

[crypto.md]: crypto.md
[LibTomCrypt]: https://github.com/libtom/libtomcrypt
[OP-TEE Client]: https://github.com/OP-TEE/optee_client
[OP-TEE Linux Kernel driver]: https://github.com/linaro-swg/linux
[OP-TEE Trusted OS]: https://github.com/OP-TEE/optee_os
[optee_smc.h]: ../core/arch/arm/include/sm/optee_smc.h
[optee_msg.h]: ../core/include/optee_msg.h
[Platforms Supported]: https://github.com/OP-TEE/optee_os#3-platforms-supported
[struct optee_msg_arg]: ../core/include/optee_msg.h
[thread.c]: ../core/arch/arm/kernel/thread.c
