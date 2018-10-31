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
#ifdef ENABLE_CFI
void cfi_data_start_guy();
#else
__drm_code
void cfi_data_start_guy(){
	printf("lol");
};
#endif
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
	ret = curr_blob_sess.blob_size / 4096;
	curr_blob_sess.blob_size =  (ret + 1) * 4096;
	curr_blob_sess.cfi_data_va = (unsigned long)&cfi_data_start_guy;
	out_data.buf_ptr = (__u64)&curr_blob_sess;
	out_data.buf_len = sizeof(curr_blob_sess);
	printf("%s : Trying to perform IOCTL with VA=%p, CFI=%p and size=0x%llx\n", __func__, 
			(void*)curr_blob_sess.blob_va, (void*)cfi_data_start_guy, curr_blob_sess.blob_size);
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
