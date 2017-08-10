/*
 * lat_sig.c - signal handler test
 *
 * XXX - this benchmark requires the POSIX sigaction interface.  The reason
 * for that is that the signal handler stays installed with that interface.
 * The more portable signal() interface may or may not stay installed and
 * reinstalling it each time is expensive.
 *
 * XXX - should really do a two process version.
 *
 * Copyright (c) 1994 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 */
char	*id = "$Id$\n";

#include "bench.h"

#include "drm_setup.c"

// define our drm code section.                                                                                                                                                           
#define __drm_code      __attribute__((section("secure_code")))


int	caught, n;
double	adj;
void	handler() { }
void	prot() {
	if (++caught == n) {
		double	u;

		u = stop(0,0);
		u /= n;
		u -= adj;
		fprintf(stderr, "Protection fault: %.3f microseconds\n", u);
		exit(0);
	}
}

double
overhead(void)
{
	int	me = getpid();
	double	o;

	/*
	 * OS cost of sending a signal without actually sending one
	 */
	BENCH(kill(me, 0), 0);
	o = usecs_spent();
	o /= get_n();
	return (o);
}

void
install(void)
{
	struct	sigaction sa, old;

	sa.sa_handler = handler;
	sigemptyset(&sa.sa_mask);	
	sa.sa_flags = 0;
	sigaction(SIGUSR1, &sa, &old);
}
__drm_code __aligned(4096) void
do_install(void)
{
	double	u;

	/*
	 * Installation cost
	 */
	BENCH(install(), 0);
	u = usecs_spent();
	u /= get_n();
	fprintf(stderr,
	    "Signal handler installation: %.3f microseconds\n", u);
}

void
do_catch(int report)
{
	int	me = getpid();
	struct	sigaction sa, old;
	double	u;

	/*
	 * Cost of catching the signal less the cost of sending it
	 */
	sa.sa_handler = handler;
	sigemptyset(&sa.sa_mask);	
	sa.sa_flags = 0;
	sigaction(SIGUSR1, &sa, &old);
	BENCH(kill(me, SIGUSR1), 0);
	u = usecs_spent();
	u /= get_n();
	u -= overhead();
	adj = u;
	n = SHORT/u;
	if (report) {
		fprintf(stderr,
		    "Signal handler overhead: %.3f microseconds\n", u);
	}
}

void
do_prot(int ac, char **av)
{
	int	fd;
	struct	sigaction sa;
	char	*where;

	if (ac != 3) {
		fprintf(stderr, "usage: %s prot file\n", av[0]);          
		exit(1);
	}
	fd = open(av[2], 0);
	where = mmap(0, 4096, PROT_READ, MAP_SHARED, fd, 0);
	if ((int)where == -1) {
		perror("mmap");
		exit(1);
	}
	/*
	 * Catch protection faults.
	 * Assume that they will cost the same as a normal catch.
	 */
	do_catch(0);
	sa.sa_handler = prot;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGSEGV, &sa, 0);
	sigaction(SIGBUS, &sa, 0);
	start(0);
	*where = 1;
}


int
main(int ac, char **av)
{
	if (ac < 2) goto usage;

	if (!strcmp("install", av[1])) {
		do_install();
	} else if (!strcmp("catch", av[1])) {
		do_catch(1);
	} else if (!strcmp("prot", av[1])) {
		do_prot(ac, av);
	} else {
usage:		printf("Usage: %s install|catch|prot file\n", av[0]);
	}
	return(0);
}
