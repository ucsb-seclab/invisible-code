/*
 * lat_proc.c - process creation tests
 *
 * Usage: lat_proc
 *
 * TODO - linux clone, plan9 rfork, IRIX sproc().
 *
 * Copyright (c) 1994 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 * Support for this development by Sun Microsystems is gratefully acknowledged.
 */
char	*id = "$Id$\n";

#include "bench.h"

#ifdef STATIC
#define	PROG "/tmp/hello-s"
#else
#define	PROG "/tmp/hello"
#endif

void do_shell(void)
{
	int	pid;

	switch (pid = fork()) {
	    case -1:
		perror("fork");
		exit(1);

	    case 0:	/* child */
		close(1);
		execlp("/bin/sh", "sh", "-c", PROG, 0);
		exit(1);

	    default:
		while (wait(0) != pid)
			;
	}
}

void do_forkexec(void)
{
	int	pid;
	char	*nav[2];

	nav[0] = PROG;
	nav[1] = 0;
	switch (pid = fork()) {
	    case -1:
		perror("fork");
		exit(1);

	    case 0: 	/* child */
		close(1);
		execve(PROG, nav, 0);
		exit(1);

	    default:
		while (wait(0) != pid)
			;
	}
}
	
void do_fork(void)
{
	int	pid;

	switch (pid = fork()) {
	    case -1:
		perror("fork");
		exit(1);

	    case 0:	/* child */
		exit(1);

	    default:
		while (wait(0) != pid)
		    ;
	}
}
	
void do_procedure(int r)
{
	use_int(r);
}
	
int
main(int ac, char **av)
{
	if (ac < 2) goto usage;

	if (!strcmp("procedure", av[1])) {
		BENCH(do_procedure(ac), 0);
		micro("Procedure call", get_n());
	} else if (!strcmp("fork", av[1])) {
		BENCH(do_fork(), 0);
#ifdef STATIC
		micro("Static Process fork+exit", get_n());
#else
		micro("Process fork+exit", get_n());
#endif
	} else if (!strcmp("exec", av[1])) {
		BENCH(do_forkexec(), 0);
#ifdef STATIC
		micro("Static Process fork+execve", get_n());
#else
		micro("Process fork+execve", get_n());
#endif
	} else if (!strcmp("shell", av[1])) {
		BENCH(do_shell(), 0);
#ifdef STATIC
		micro("Static Process fork+/bin/sh -c", get_n());
#else
		micro("Process fork+/bin/sh -c", get_n());
#endif
	} else {
usage:		printf("Usage: %s fork|exec|shell\n", av[0]);
	}
	return(0);
}
