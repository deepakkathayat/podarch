/*
 * Copyright (c) 1997 The President and Fellows of Harvard College.
 * All rights reserved.
 * Copyright (c) 1997 Aaron B. Brown.
 * Copyright (c) 1994 Larry McVoy.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program, in the file COPYING in this distribution;
 *   if not, write to the Free Software Foundation, Inc., 675 Mass Ave,
 *   Cambridge, MA 02139, USA.
 *
 * This work is derived from, but can no longer be called, lmbench.
 * Results obtained from this benchmark may be published only under the
 * name "HBench-OS".
 *
 */

/*
 * lat_fslayer.c - time simple entry into the file system part of the system
 *                 (i.e. VFS overhead) by writing a byte to /dev/null.
 *
 *		   This was the old lmbench null syscall benchmark.
 *
 * Based on lmbench, file
 * 	$lmbenchId: lat_syscall.c,v 1.2 1995/09/24 01:32:37 lm Exp $
 *
 * $Id: lat_fslayer.c,v 1.4 1997/06/27 00:33:58 abrown Exp $
 */
char	*id = "$Id: lat_fslayer.c,v 1.4 1997/06/27 00:33:58 abrown Exp $\n";

#include "common.c"
#include "pod_header.h"

/* Worker function */
int do_syscall();

/*
 * Global variables: these are the parameters required by the worker routine.
 * We make them global to avoid portability problems with variable argument
 * lists and the gen_iterations function 
 */
int	fd;			/* file descriptor of /dev/null */

main(ac, av)
	int ac;
	char  **av;
{
	clk_t		totaltime;
	unsigned int	niter;

	/* print out RCS ID to stderr*/
	fprintf(stderr, "%s", id);

	/* Check command-line arguments */
	if (parse_counter_args(&ac, &av) || ac != 2) {
		fprintf(stderr, "Usage: %s%s iterations_persec\n", av[0],
			counter_argstring);
		exit(1);
	}
	
	/* parse command line parameters */
	niter = atoi(av[1]);
	fd = open("/dev/null", 1);
	if (fd == -1) {
		perror("open");
		exit(1);
	}

	/* initialize timing module (calculates timing overhead, etc) */
	init_timing();

#ifndef COLD_CACHE
	/* 
	 * Generate the appropriate number of iterations so the test takes
	 * at least one second. For efficiency, we are passed in the expected
	 * number of iterations, and we return it via the process error code.
	 * No attempt is made to verify the passed-in value; if it is 0, we
	 * we recalculate it.
	 */
	if (niter == 0) {
		niter = gen_iterations(&do_syscall, clock_multiplier);
		printf("%d\n",niter);
		return (0);
	}

	/*
	 * Take the real data and average to get a result
	 */
	do_syscall(1, &totaltime); /* prime caches */
#else
	niter = 1;
#endif
	do_syscall(niter, &totaltime);	/* get cached reread */

	output_latency(totaltime, niter);
	
	return (0);
}

int
do_syscall(num_iter, t)
	int num_iter;
	clk_t *t;
{
	register int i;
	char c;

	start();
	for (i = num_iter; i > 0; i--) {
		if (write(fd, &c, 1) != 1) {
			perror("/dev/null");
			exit(1);
		}
	}
	*t = stop(c);

	return (0);
}
