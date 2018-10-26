/*
 * lat_syscall.c - time simple system calls
 *
 * Copyright (c) 1996 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 */
char	*id = "$Id$\n";

#include "bench.h"
#define	FNAME "/usr/include/sys/types.h"

#include "drm_setup.c"

// define our drm code section.                                                                                                                                                           
#define __drm_code      __attribute__((section("secure_code")))

const char *lol = "123\n\x00";
#ifdef __drm_code
__drm_code __aligned(4096) void
#else
void
#endif
do_write()
{
	// test getpgid
	asm volatile(
			"mov r0, #1\n"
			"mov r1, %[lol]\n"
			"mov r2, #5\n"
			"mov r7, #4\n" // getpgid thumb
			"svc #0\n"
			::[lol] "r" (lol)
			:"r0","r1", "r2","r7", "memory");
}

#ifdef __drm_code
__drm_code __aligned(4096) void
#else
void
#endif
do_read(int fd)
{
	char	c;

	if (read(fd, &c, 1) != 1) {
		perror("/dev/zero");
		return;
	}
}

#ifdef __drm_code
__drm_code __aligned(4096) void
#else
void
#endif
do_stat(char *s)
{
	struct	stat sbuf;

	if (stat(s, &sbuf) == -1) {
		perror(s);
		return;
	}
}

#ifdef __drm_code
__drm_code __aligned(4096) void
#else
void
#endif
do_fstat(int fd)
{
	struct	stat sbuf;

	if (fstat(fd, &sbuf) == -1) {
		perror("fstat");
		return;
	}
}

#ifdef __drm_code
__drm_code __aligned(4096) void
#else
void
#endif
do_openclose(char *s)
{
	int	fd;

	fd = open(s, 0);
	if (fd == -1) {
		perror(s);
		return;
	}
	close(fd);
}


#ifdef __drm_code
__drm_code __aligned(4096) void
#else
void
#endif
do_getppid()
{
	/* asm volatile( */
/* 	"mov r0, #0\n" */
/* 	"mov r7, #0x84\n" // getpgid thumb */
/* 	"svc #0\n" */
/* 	:::"r0", "r7", "memory"); */
  /* int i= 0; */
  /* while(i<100) i++; */
  getppid();
}


int
main(int ac, char **av)
{
	int	fd;
	char	*file;

	if (ac < 2){
		printf("Usage: %s null|read|write|stat|open\n", av[0]);
		return(1);
	}
	file = av[2] ? av[2] : FNAME;

#ifdef __drm_code
//	drm_toggle_dm_fwd();
#endif

	BENCH(do_getppid(), 0);
	micro("Simple syscall", get_n());

	fd = open("/dev/zero", 0);
	if (fd == -1) {
		fprintf(stderr, "Read from /dev/zero: -1");
		return(1);
	}

	BENCH(do_read(fd), 0);
	micro("Simple read", get_n());
	close(fd);

	fd = open("/dev/null", 1);
	if (fd == -1) {
		fprintf(stderr, "Read from /dev/zero: -1");
		return(1);
	}
	BENCH(do_write(), 0);
	micro("Simple write", get_n());
	close(fd);

	BENCH(do_stat(file), 0);
	micro("Simple stat", get_n());

	fd = open(file, 0);
	BENCH(do_fstat(fd), 0);
	micro("Simple fstat", get_n());

	BENCH(do_openclose(file), 0);
	micro("Simple open/close", get_n());

	/*if (!strcmp("null", av[1])) {
		BENCH(do_getppid(), 0);
		micro("Simple syscall", get_n());
	} else if (!strcmp("write", av[1])) {
		fd = open("/dev/null", 1);
		BENCH(do_write(), 0);
		micro("Simple write", get_n());
		close(fd);
	} else if (!strcmp("read", av[1])) {
		fd = open("/dev/zero", 0);
		if (fd == -1) {
			fprintf(stderr, "Read from /dev/zero: -1");
			return(1);
		}
		BENCH(do_read(fd), 0);
		micro("Simple read", get_n());
		close(fd);
	} else if (!strcmp("stat", av[1])) {
		BENCH(do_stat(file), 0);
		micro("Simple stat", get_n());
	} else if (!strcmp("fstat", av[1])) {
		fd = open(file, 0);
		BENCH(do_fstat(fd), 0);
		micro("Simple fstat", get_n());
	} else if (!strcmp("open", av[1])) {
		BENCH(do_openclose(file), 0);
		micro("Simple open/close", get_n());
	} else {
	}*/
	return(0);
}
