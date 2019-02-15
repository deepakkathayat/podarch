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
 */

/*
 * bw_mem_wr.c - measures write bandwidth delivered by memory system
 *
 * Note: this benchmark is directly comparable to the bw_mem_rd
 *       benchmark because both do a load/store and an add per word.
 *
 * Based on:
 *	$lmbenchId: bw_mem_wr.c,v 1.2 1995/03/11 02:19:39 lm Exp $
 *
 * $Id: bw_mem_wr.c,v 1.6 1997/06/27 00:33:58 abrown Exp $
 */

char	*id = "$Id: bw_mem_wr.c,v 1.6 1997/06/27 00:33:58 abrown Exp $\n";

#include "pod_header.h"
#include "common.c"

/*
 * Use unsigned int: supposedly the "optimal" transfer size for a given 
 * architecture.
 */
#ifndef TYPE
#define TYPE    unsigned int
#endif
#ifndef SIZE
#define	SIZE	sizeof(TYPE)
#endif

/* The worker function */
int 	do_memwrite(int num_iter, clk_t *time);

/*
 * Global variables: these are the parameters required by the worker routine.
 * We make them global to avoid portability problems with variable argument
 * lists and the gen_iterations function 
 */
unsigned int 	bytes;		/* the number of bytes to be written */

int
main(ac, av)
        char  **av;
{
	unsigned int	niter;
	clk_t		totaltime;
	unsigned int	xferred;

	/* print out RCS ID to stderr*/
	fprintf(stderr, "%s", id);

	/* Check command-line arguments */
	if (parse_counter_args(&ac, &av) || ac != 3) {
		fprintf(stderr, "Usage: %s%s iterations size\n", av[0],
			counter_argstring);
		exit(1);
	}
	
	/* parse command line parameters */
	niter = atoi(av[1]);
	bytes = parse_bytes(av[2]);
	
	/*
	 * The gory calculation on the next line computes the actual number of
	 * bytes tranferred by the unrolled loop.
	 */
	xferred = (200*SIZE)*((((bytes/SIZE)-200)+199)/200);
	if (xferred == 0) {
		fprintf(stderr, "error: buffer size too small: must be at "
			"least %d bytes.\n",201*SIZE);
		printf("<error>\n");
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
		niter = gen_iterations(&do_memwrite, clock_multiplier);
		printf("%d\n",niter);
		return (0);
	}

	/*
	 * Take the real data and average to get a result
	 */
	do_memwrite(1, &totaltime);	/* prime the cache with 1 iteration*/
#else
	niter = 1;
#endif
	do_memwrite(niter, &totaltime);	/* get cached write bandwidth */

	output_bandwidth(niter * xferred, totaltime);
	
	return (0);
}

/*
 * This function does all the work. It mallocs a buffer of size "bytes" and
 * then writes that buffer num_iter times, timing the entire operation.
 *
 * Returns 0 if the benchmark was successful, and -1 if there were too many
 * iterations.
 */
int
do_memwrite(num_iter, t)
	int num_iter;
	clk_t *t;
{
	/*
	 * 	Global parameters 
	 *
	 * unsigned int bytes;
	 */
	register TYPE *p;
	register unsigned long acc;
	register TYPE *end;
        int i;
        TYPE   *mem;

	/* Allocate the buffer to be used for writeing */
        mem = (TYPE *)malloc(bytes + 16384);

	if (!mem) {
		perror("malloc");
		exit(1);
	}
#ifndef COLD_CACHE
	bzero(mem, bytes);	/* Touch all of the pages */
#endif

#define	TWENTY	p[0]=1;p[1]=1;p[2]=1;p[3]=1;p[4]=1;p[5]=1;p[6]=1;p[7]=1;\
		p[8]=1;p[9]=1;p[10]=1;p[11]=1;p[12]=1;p[13]=1;p[14]=1;p[15]=1;\
		p[16]=1;p[17]=1;p[18]=1;p[19]=1;p+=20;
#define	HUNDRED	TWENTY TWENTY TWENTY TWENTY TWENTY

	acc = 0;

	end = mem + (bytes/SIZE) - 200;

	/* Start timing */
	start();

	/* Write num_iter times */
	for (i = num_iter; i > 0; i--) {
		for (p = mem; p < end; ) {
			HUNDRED
			HUNDRED
		}
	}

	*t = stop(acc);		/* stop timing and record result */

	free(mem);		/* free memory allocated */

	return (0);		/* success */
}
