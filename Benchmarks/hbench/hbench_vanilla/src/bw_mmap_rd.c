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
 * bw_mmap_rd.c - time reading & summing of a file using mmap
 *
 * Usage: bw_mmap_rd size file
 *
 * Without hardware counters, sizes less than 2m are not recommended.
 * Memory is read by summing it up so the numbers include the cost of
 * the adds.  If you use sizes large enough, you can compare to
 * bw_mem_rd and get the cost of TLB fills (very roughly).
 *
 * We don't do an internal iteration loop in this benchmark since mmap
 * read cannot be repeated (if we did, we'd lose the interesting timing
 * from the initial read).
 * The benchmark is structured in the iterative form for consistency, though.
 *
 * Based on:
 *	$lmbenchId: bw_mmap_rd.c,v 1.3 1995/10/26 01:03:42 lm Exp $
 *
 * $Id: bw_mmap_rd.c,v 1.8 1997/06/27 00:33:58 abrown Exp $
 */
char	*id = "$Id: bw_mmap_rd.c,v 1.8 1997/06/27 00:33:58 abrown Exp $\n";

#include "common.c"

#include <sys/mman.h>
#include <sys/stat.h>

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

#define	CHK(x)		if ((int)(x) == -1) { perror("x"); exit(1); }

/* 
 * The worker function. We don't really need it here; it is just to make 
 * the structure parallel the other tests.
 */
int 	do_mmapread();

/*
 * Global variables: these are the parameters required by the worker routine.
 * We make them global to avoid portability problems with variable argument
 * lists and the gen_iterations function 
 */

unsigned int 	bytes;		/* the number of bytes to be read */
int		fd;		/* file descriptor of open file */

main(ac, av)
	int ac;
	char **av;
{
	clk_t		totaltime;
	unsigned int 	xferred;
	struct stat 	sbuf;
	int		niter;

	/* print out RCS ID to stderr*/
	fprintf(stderr, "%s", id);

	/* Check command-line arguments */
	if (parse_counter_args(&ac, &av) || ac != 4) {
		fprintf(stderr, "Usage: %s%s ignored size file\n", 
			av[0], counter_argstring);
		exit(1);
	}
	
	/* parse command line parameters */
	niter = atoi(av[1]);
	bytes = parse_bytes(av[2]);
	CHK(fd = open(av[3], 0));
	CHK(fstat(fd, &sbuf));
	if (bytes > sbuf.st_size) {
		fprintf(stderr, "%s: is too small; %d bytes requested but only"
			" %d available\n", av[3], bytes, sbuf.st_size);
		exit(1);
	}

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

	/* Get the number of iterations */
	if (niter == 0) {
		/* We always do 1 iteration here */
		printf("1\n");
		return (0);
	}

	/*
	 * Take the real data
	 */
#ifndef COLD_CACHE
	do_mmapread(1, &totaltime);	/* prime the cache */
#endif
	do_mmapread(1, &totaltime);	/* get cached reread */

	output_bandwidth(xferred, totaltime);
	
	return (0);
}

/* 
 * This function does all the work. It reads "bytes" from "fd"
 * "num_iter" times via mmap and reports the total time in whatever
 * unit our clock is using.
 *
 * Note that num_iter > 1 is not useful in dealing with low-resolution 
 * timers, since each loop is timed individually.
 *
 * Returns 0 if the benchmark was successful, and -1 if there were too many
 * iterations.  */
int
do_mmapread(num_iter, t)
	int num_iter;
	clk_t *t;
{
	/*
	 * 	Global parameters 
	 *
	 * unsigned int bytes;
	 * int fd;
	 */
	register TYPE *p;
	register unsigned long sum;
	register TYPE *end;
	int i;
	TYPE *where;

	/* Try to map in the file */
#ifdef MAP_FILE
	CHK(where = (TYPE *)mmap(0, bytes, PROT_READ, MAP_FILE|MAP_SHARED, 
				 fd, 0));
#else
	CHK(where = (TYPE *)mmap(0, bytes, PROT_READ, MAP_SHARED, fd, 0));
#endif
	p = where;
	
#define	TWENTY	sum += p[0]+p[1]+p[2]+p[3]+p[4]+p[5]+p[6]+p[7]+p[8]+p[9]+ \
		p[10]+p[11]+p[12]+p[13]+p[14]+p[15]+p[16]+p[17]+p[18]+p[19]; \
		p += 20;
#define	HUNDRED	TWENTY TWENTY TWENTY TWENTY TWENTY

	sum = 0;	
	end = where + (bytes/SIZE) - 200;
	*t = 0;

	/* Do the read num_iter times, remapping the file each time around */
	for (i = num_iter; i > 0; i--) {
		munmap((char *)where, bytes);
#ifdef MAP_FILE
		CHK(where = (TYPE *)mmap(0, bytes, PROT_READ, 
					 MAP_FILE|MAP_SHARED, fd, 0));
#else
		CHK(where = (TYPE *)mmap(0, bytes, PROT_READ, MAP_SHARED, 
					 fd, 0));
#endif
		start();
		for (p = where; p < end; ) {
			HUNDRED
			HUNDRED
		}
		*t += stop(sum);
	}

	/* Remove our mapping */
	munmap((char *)where, bytes);

	return(0);
}
