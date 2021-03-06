#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif

#include <linux/tee.h>

// define our drm code section.
#define __drm_code	__attribute__((section("secure_code")))
#define __thumb	__attribute__((target("thumb")))
#define __arm	__attribute__((target("arm")))

typedef int (*secure_code_t)(void);

/*
 * We need the address of our secure_code section. Luckily there is no
 * need to scan the ELF header since the GNU linker will automatically
 * define symbols __start_NAME_OF_YOUR_SECTION and
 * __stop_NAME_OF_YOUR_SECTION (if NAME_OF_YOUR_SECTION is a valid C
 * identifier). So we can get the start address of our section and
 * computing the size of the section by subtracting this address from
 * the address of the end of the section.
*/
extern secure_code_t __start_secure_code;
extern secure_code_t __stop_secure_code;



void first_drm_func(void);


// define the variables used by the drm initialization code
int drm_fd = -1;
struct tee_ioctl_open_blob_session_arg curr_blob_sess = {0};

// declarations.
void drm_code_initialize (void) __attribute__((constructor));
void drm_code_destructor (void) __attribute__((destructor));
bool drm_toggle_dm_fwd (void);

void drm_code_initialize(void) {
    size_t n = 0;
    char devname[PATH_MAX];
    int ret;
    struct tee_ioctl_buf_data out_data;

    // open the device file.
    for (n = 0; n < 10; n++) {
		snprintf(devname, sizeof(devname), "/dev/tee%zu", n);
		drm_fd = open(devname, O_RDWR);
		if (drm_fd >= 0) {
		    break;
		}
	}
	// sanity
	if(drm_fd < 0) {
	    printf("%s : Unable to open device file, errorno=%d\n", __func__, errno);
	    return;
	}
	// initialize the starting address of the section.
	curr_blob_sess.blob_va = (unsigned long)&__start_secure_code;
	// initialize the size of the drm section.
	curr_blob_sess.blob_size = (unsigned long)&__stop_secure_code - (unsigned long)&__start_secure_code;
	
	out_data.buf_ptr = (__u64)&curr_blob_sess;
	out_data.buf_len = sizeof(curr_blob_sess);
	printf("%s : Trying to perform IOCTL with VA=%p and size=0xll%x\n", __func__, 
			(void*)curr_blob_sess.blob_va, curr_blob_sess.blob_size);
	// now do the open blob session.
	ret = ioctl(drm_fd, TEE_IOC_OPEN_BLOB_SESSION, &out_data);
	if(ret != 0) {
	    printf("%s : Unable to open a blob session, errorno=%d\n", __func__, errno);
	} else {
	    // OK, we sucessfully opened the session.
	    printf("%s : Sucessfully opened a blob session\n", __func__);
	}
	
}

bool drm_toggle_dm_fwd (void) {
	if (drm_fd < 0){
		printf("%s : cannot open tee driver fd\n", __func__);
		return false;
	}

	return ioctl(drm_fd, TEE_IOC_TOGGLE_DM_FWD);
}

// close the blob session and the device file.
void drm_code_destructor (void) {
    if(drm_fd >= 0) {
        struct tee_ioctl_close_session_arg curr_sess;
        int ret;
        curr_sess.session = curr_blob_sess.session;
        // close the session.
        ret = ioctl(drm_fd, TEE_IOC_CLOSE_BLOB_SESSION, &curr_sess);
        if(ret != 0) {
            printf("%s: Failure occurred while trying to close blob session, errorno=%d\n", __func__, errno);
        } else {
            printf("%s: Sucessfully closed DRM_BLOB_SESSION\n", __func__);
        }
        // close the file.
        close(drm_fd);
    }
}


__arm int arm_nw(){
	return 1;
}
__thumb int thumb_nw(){
	return 2;
}

// force page alignment of the drm_code section.
// TODO: force page alignment in linker script?
__drm_code __aligned(4096) void first_drm_func(void) {
    puts("Start of DRM Code Section\n");
}


__drm_code __arm int arm_sw(){
	return 3;
}

__drm_code __thumb int thumb_sw(){
	return 4;
}

__arm int arm_nw_call_arm_sw(){
	printf("[!!!] %s\n", __func__);
	return arm_sw();
}

__arm int arm_nw_call_thumb_sw(){
	printf("[!!!] %s\n", __func__);
	return thumb_sw();
}

__thumb int thumb_nw_call_thumb_sw(){
	printf("[!!!] %s\n", __func__);
	return thumb_sw();
}

__thumb int thumb_nw_call_arm_sw(){
	printf("[!!!] %s\n", __func__);
	return arm_sw();
}


__drm_code __arm int arm_sw_call_arm_nw(){
	printf("[!!!] %s\n", __func__);
	return arm_nw();
}

__drm_code __arm int arm_sw_call_thumb_nw(){
	printf("[!!!] %s\n", __func__);
	return thumb_nw();
}

__drm_code __thumb int thumb_sw_call_thumb_nw(){
	printf("[!!!] %s\n", __func__);
	return thumb_nw();
}

__drm_code __thumb int thumb_sw_call_arm_nw(){
	printf("[!!!] %s\n", __func__);
	return arm_nw();
}

void nw_to_sw_tests(){
	int res;
	res = thumb_nw_call_arm_sw();
	printf("[!!!] %s returned %d\n", "thumb_nw_call_arm_sw", res);
	res = arm_nw_call_arm_sw();
	printf("[!!!] %s returned %d\n", "arm_nw_call_arm_sw", res);
	res = arm_nw_call_thumb_sw();
	printf("[!!!] %s returned %d\n", "arm_nw_call_thumb_sw", res);
	res = thumb_nw_call_thumb_sw();
	printf("[!!!] %s returned %d\n", "thumb_nw_call_thumb_sw", res);

}

void sw_to_nw_tests(){
	int res;
	res = thumb_sw_call_arm_nw();
	printf("[!!!] %s returned %d\n", "thumb_sw_call_arm_nw", res);
	res = thumb_sw_call_thumb_nw();
	printf("[!!!] %s returned %d\n", "thumb_sw_call_thumb_nw", res);
	res = arm_sw_call_thumb_nw();
	printf("[!!!] %s returned %d\n", "arm_sw_call_thumb_nw", res);
	res = arm_sw_call_arm_nw();
	printf("[!!!] %s returned %d\n", "arm_sw_call_arm_nw", res);
}

__drm_code __arm int sw_syscall_test_arm()
{
	unsigned int ret_sys;
	// test getpgid
	asm volatile(
			"mov r0, #0\n"
			"mov r7, #132\n" // getpgid thumb
			"svc #0\n"
			"mov %[res], r0\n"
			:[res] "=r" (ret_sys)
			:
			:"r0", "r7");

	return ret_sys;
}

__drm_code __thumb int sw_syscall_test_thumb()
{
	unsigned int ret_sys;
	// test getpgid
	asm volatile(
			"mov r0, #0\n"
			"mov r7, #132\n" // getpgid thumb
			"svc #0\n"
			"mov %[res], r0\n"
			:[res] "=r" (ret_sys)
			:
			:"r0", "r7");

	return ret_sys;
}

const char *lol = "123\n\x00";
__drm_code __arm int sw_syscall_test_write()
{
	unsigned int ret_sys;
	// test getpgid
	asm volatile(
			"mov r0, #0\n"
			"mov r1, %[lol]\n"
			"mov r2, #5\n"
			"mov r7, #4\n" // getpgid thumb
			"svc #0\n"
			"mov %[res], r0\n"
			:[res] "=r" (ret_sys)
			:[lol] "r" (lol)
			:"r0","r1", "r7");

	return ret_sys;
}

void test_syscalls()
{
	int res_arm, res_thumb, w_res, expected;
	printf("%s, testing syscalls\n", __func__);
	
	w_res = sw_syscall_test_write();
	expected = getpgid(0);
	res_arm = sw_syscall_test_arm();
	res_thumb = sw_syscall_test_thumb();
	printf("[*] arm returned %x, thumb returned %x, expected %x\n", res_arm, res_thumb, expected);

	if ((res_arm == res_thumb) && (res_arm == expected)) {
		printf("[!] syscall test executed correctly!\n"
				"wrote %d chars\n", w_res);
	} else {
		printf("[!] syscall test failed\n");
	}
}

void test_forwarding()
{
	printf("%s, testing forwarding\n", __func__);
	nw_to_sw_tests();
	sw_to_nw_tests();
}

int main(int argc, char *argv[]) {

	printf("[*] %s dm set to %s\n", __func__, (drm_toggle_dm_fwd() == true) ? "true" : "false");

	test_syscalls();
	test_forwarding();

	printf("[*] %s dm set to %s\n", __func__, (drm_toggle_dm_fwd() == true) ? "true" : "false");

	test_syscalls();
	test_forwarding();

    printf("%s: Before invoking secure code\n", __func__);
    first_drm_func();
    printf("%s: Returning from secure code\n", __func__);
    return 0;
}
