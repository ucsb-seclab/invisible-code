This is an application used to test syscalls execution and evaluate the performances of the syscall proxying mechanism

Manual Build Instructions
-------------------------

1. Setup the OP-TEE software stack by following: https://github.com/OP-TEE/optee_os#5-repo-manifests

2. Define the toolchains and environment variables:

	```
	export TEEC_EXPORT=$PWD/../optee_client/out/export
	```

	If normal world user space is 64-bit:<BR>
	```
	export HOST_CROSS_COMPILE=$PWD/../toolchains/aarch64/bin/aarch64-linux-gnu-
	```

	If normal world user space is 32-bit:<BR>
	```
	export HOST_CROSS_COMPILE=$PWD/../toolchains/aarch32/bin/arm-linux-gnueabihf-
	```

	If secure world user space is 64-bit:<BR>
	```
	export TA_CROSS_COMPILE=$PWD/../toolchains/aarch64/bin/aarch64-linux-gnu-
	export TA_DEV_KIT_DIR=$PWD/../optee_os/out/arm/export-ta_arm64
	```

	If secure world user space is 32-bit:<BR>
	```
	export TA_CROSS_COMPILE=$PWD/../toolchains/aarch32/bin/arm-linux-gnueabihf-
	export TA_DEV_KIT_DIR=$PWD/../optee_os/out/arm/export-ta_arm32
	```

3. Build it!

        make

