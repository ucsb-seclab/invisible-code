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

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif

const char *lol = "123\n\x00";
__drm_code __aligned(4096) void
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


__drm_code void
do_read(int fd)
{
	char	c;

	if (read(fd, &c, 1) != 1) {
		perror("/dev/zero");
		return;
	}
}

__drm_code  void
do_stat(char *s)
{
	struct	stat sbuf;

	if (stat(s, &sbuf) == -1) {
		perror(s);
		return;
	}
}

__drm_code  void
do_fstat(int fd)
{
	struct	stat sbuf;

	if (fstat(fd, &sbuf) == -1) {
		perror("fstat");
		return;
	}
}

__drm_code  void
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

__drm_code void
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

__drm_code void cfi_back_edge_verification(void *target_addr) {
    asm volatile(
			"mov r0, %[reta]\n"
			"mov r1, lr\n"
			"mov r7, #121\n"
			"ror r7, r7, #24\n" 
			"svc #0\n"
			:
			:[reta] "r" (target_addr)
			:"r0", "r1", "r7");
}


__drm_code void cfi_data_start_guy(){
	printf("CFI_Data_Start\n");
}


__attribute__((section("dummy_sec"))) __aligned(4096) void dummyfunc(){
	printf("CFI_Data_Start\n");
}


int
main(int ac, char **av)
{
	int	fd;
	char	*file;

	if (ac < 2) goto usage;
	file = av[2] ? av[2] : FNAME;

	//drm_toggle_dm_fwd();

	if (!strcmp("null", av[1])) {
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
usage:		printf("Usage: %s null|read|write|stat|open\n", av[0]);
	}
	return(0);
}
