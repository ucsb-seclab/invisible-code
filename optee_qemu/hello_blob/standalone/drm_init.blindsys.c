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
#include <sys/time.h>

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif

#include <linux/tee.h>


int main(int argc, char *argv[]) {

	int dm;
	size_t n = 0, j = 0;
    char devname[PATH_MAX];
    int ret;
    int drm_fd;
    struct timeval tv1,tv2;
    double overhead = 0;
    
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
	
	for(j=0;j<30;j++) {
	    gettimeofday(&tv1,NULL);
	    for(n=0; n<2000; n++) {
	        ret = ioctl(drm_fd, 0x12, NULL);
    	}
    	gettimeofday(&tv2,NULL);
    	overhead = ((1000000 * (tv2.tv_sec-tv1.tv_sec)) + (tv2.tv_usec - tv1.tv_usec));
    	printf("syscall overhead: %f usec\n", overhead/2000);
	}
	close(drm_fd);
    return 0;
}
