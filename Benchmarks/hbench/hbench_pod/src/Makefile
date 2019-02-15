#
# Copyright (c) 1997 The President and Fellows of Harvard College.
# All rights reserved.
# Copyright (c) 1997 Aaron B. Brown.
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program, in the file COPYING in this distribution;
#   if not, write to the Free Software Foundation, Inc., 675 Mass Ave,
#   Cambridge, MA 02139, USA.
#
# Results obtained from this benchmark may be published only under the
# name "HBench-OS".
#
# $Id: Makefile,v 1.22 1997/06/27 14:50:12 abrown Exp $

# Make targets:
#
# hbench	[default] builds the benchmark suite for the current os/arch
# cyclecounter	build the suite with cyclecounter support
# eventcountersP5 build with Pentium event counter support
# eventcountersP6 build with Pentium Pro event counter support
# clean		removes binaries for the current platform
# cleanall	removes binaries for *all* platforms
# depend	build (REQUIRED!) dependecy rules
#
# Note that make clean actually removes the binaries (since they're
# never really "installed" anywhere).
#
# This is largely self configuring.  Most stuff is pretty portable.  You
# may have problems with the mhz program.  It needs a C compiler smart
# enough to use "register" when running in unoptimized mode.  gcc does
# this.  cc may not.  Look at the output of mhz and see if it is close
# (within a few percent).  If not, try a different compiler and send me
# mail with the info.
#
# Note that mhz will not work on an unpipelined, non-RISC CPU like the i386.
#
# OS config.  If your OS is not special-cased below, and the defaults don't
# work, then you'll need to add a case below setting up the appropriate 
# compiler and flags. If you do this, send me mail with the diffs to this
# makefile.
#
# If you don't have gcc, try make CC=cc and see if that works.

SHELL=/bin/sh

CC=gcc
PLATFORM=`$(SHELL) ../scripts/config.guess`
ARCH=`$(SHELL) ../scripts/config.guess | sed 's/-.*-.*$$//'`
OS=`$(SHELL) ../scripts/config.guess | sed 's/^.*-.*-//'`
OSROOT=`$(SHELL) ../scripts/config.guess | sed 's/^.*-.*-//' | sed 's/[0-9].*$$//'`

all:
	@$(MAKE) BINDIR=../bin/$(OS)-$(ARCH) $(OSROOT)

cyclecounter:
	@$(MAKE) COUNTERS=-DCYCLE_COUNTER BINDIR=../bin/$(OS)-$(ARCH)-c $(OSROOT)

eventcountersP5:
	@$(MAKE) COUNTERS=-DEVENT_COUNTERS=5 BINDIR=../bin/$(OS)-$(ARCH)-ec $(OSROOT)

eventcountersP6:
	@$(MAKE) COUNTERS=-DEVENT_COUNTERS=6 BINDIR=../bin/$(OS)-$(ARCH)-ec $(OSROOT)


TOOLCHAIN_DIR = ../../../../Toolchain
INCLUDE       = -I $(TOOLCHAIN_DIR)/

CFLAGS= -O $(SYS5) $(COUNTERS) $(INCLUDE)

COMPILE=$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS)


#####################################
##                                 ##
## PER-OS CONFIGURATION SECTION    ##
##                                 ##
## Make sure your operating system ##
## has a target here. Each target  ##
## should setup any needed flags,  ##
## then invoke the default target  ##
## (make binaries).                ##
##                                 ##
#####################################

# The following don't need special handling.
freebsd netbsd openbsd sunos linux:
	@$(MAKE) binaries

bsdi:
	@$(MAKE) LDLIBS="-lrpc" binaries

solaris:
	@$(MAKE) CC=cc LDLIBS="-lnsl -lsocket" SYS5=-DSYS5 binaries

# HPUX needs gcc; their C compiler screws up mhz.c.
hpux:
	@$(MAKE) CC="$(CC)" CFLAGS="$(CFLAGS) -Dvalloc=malloc -DNO_RUSAGE" binaries

# Really specific to the alpha, not osf.
osf:
	@$(MAKE) CC=cc binaries

irix:
	@$(MAKE) CC=cc CFLAGS="$(CFLAGS) -32" binaries

aix:
	@$(MAKE) CC=cc CFLAGS="$(CFLAGS) -Dvalloc=malloc" binaries


#########################################
##                                     ##
## END OF PER-OS CONFIGURATION SECTION ##
##                                     ##
## You should not need to change       ##
## anything below this box.            ##
##                                     ##
#########################################

setupdirs:
	@echo Building for $(OS)-$(ARCH) into $(BINDIR)
	@if [ ! -d $(BINDIR) ]; then mkdir -p $(BINDIR); fi

SRCS=	bench.h bw_bzero.c bw_file_rd.c bw_mem_cp.c bw_mem_rd.c bw_mem_wr.c \
	bw_mmap_rd.c bw_pipe.c bw_tcp.c common.c counter-common.c hello.c \
	lat_connect.c lat_ctx.c lat_ctx2.c lat_fs.c lat_fslayer.c \
	lat_mem_rd.c lat_mmap.c lat_pipe.c lat_proc.c lat_rpc.c \
	lat_sig.c lat_syscall.c lay_tcp.c lat_udp.c lib_tcp.c lib_udp.c \
	memsize.c mhz.c timing.c utils.c lmdd.c lat_pagefault.c

# PODARCH NOTE:
# -------------
# bw_tcp lat_connect lat_rpc lat_tcp lat_udp are removed the list
# They cannot be linked statically as internally they depend on libtirpc
# which creates a problem while static preparation
# https://sourceware.org/ml/libc-alpha/2011-07/msg00094.html


EXES=	$(BINDIR)/bw_bzero $(BINDIR)/bw_file_rd $(BINDIR)/bw_mem_cp \
	$(BINDIR)/bw_mem_rd $(BINDIR)/bw_mem_wr $(BINDIR)/bw_mmap_rd \
	$(BINDIR)/bw_pipe \
	$(BINDIR)/lat_ctx $(BINDIR)/lat_fs $(BINDIR)/lat_fslayer \
	$(BINDIR)/lat_mem_rd $(BINDIR)/lat_mmap $(BINDIR)/lat_pipe \
	$(BINDIR)/lat_proc $(BINDIR)/lat_sig \
	$(BINDIR)/lat_syscall \
	$(BINDIR)/lat_ctx2 \
	$(BINDIR)/memsize $(BINDIR)/hello $(BINDIR)/hello-s \
	$(BINDIR)/mhz $(BINDIR)/mhz-counter
#	$(BINDIR)/lmdd $(BINDIR)/lat_pagefault

binaries: setupdirs $(EXES)

clean:
	@echo rm -rf ../bin/$(OS)-$(ARCH)*
	@/bin/rm -rf ../bin/$(OS)-$(ARCH)*

cleanall:
	@echo rm -rf ../bin/[a-z]*
	@rm -rf ../bin/[a-z]*

depend:
	@../scripts/depend

###
### SPECIAL-CASE PROGRAMS
###
GLIBCDIR   = ../../../../eglibc-2.19/install/lib
STARTFILES = $(GLIBCDIR)/crt1.o $(GLIBCDIR)/crti.o `gcc --print-file-name=crtbegin.o`
ENDFILES   = `gcc --print-file-name=crtend.o` $(GLIBCDIR)/crtn.o
LIBGROUP   = -Wl,--start-group $(GLIBCDIR)/libc.a $(LDLIBS) -lgcc -lgcc_eh -Wl,--end-group
WRAP       = -Wl,--wrap=open,--wrap=fopen,--wrap=read,--wrap=nanosleep,--wrap=__access,--wrap=link,--wrap=unlink,--wrap=readlink,--wrap=__open,--wrap=__readlink,--wrap=uname,--wrap=write,--wrap=access,--wrap=getrusage,--wrap=chdir,--wrap=creat

POD_LDFLAGS = $(INCLUDE) -nostdlib -nostartfiles -static -T $(TOOLCHAIN_DIR)/page_aligner $(WRAP)

# Build static hello, if possible
$(BINDIR)/hello-s: hello.c
	@echo Generating statically-linked hello...
	@if [ `basename $(CC)` = gcc ]; \
	then $(COMPILE) -c -o $(BINDIR)/hello-s.o hello.c; \
		 $(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/hello-s  $(STARTFILES) $(BINDIR)/hello-s.o $(LIBGROUP) $(ENDFILES); \
	elif [ $(OSROOT) = solaris ]; \
	then $(CC) $(SYS5) -Bstatic -dn -o $(BINDIR)/hello-s hello.c $(LDLIBS); \
	elif [ $(OSROOT) = sunos ]; \
	then $(CC) -Bstatic -o $(BINDIR)/hello-s hello.c $(LDLIBS); \
	elif [ $(OSROOT) = osf ]; \
	then $(CC) -non_shared -o $(BINDIR)/hello-s hello.c $(LDLIBS); \
	elif [ $(OSROOT) = irix -a -d /usr/lib/nonshared ]; \
	then $(CC) -non_shared -o $(BINDIR)/hello-s hello.c $(LDLIBS); \
	fi
# Move this line above the "fi" (and backslash) to try a gcc-version of static
#	else $(COMPILE) -static -o $(BINDIR)/hello-s hello.c $(LDLIBS);


# Build dynamic hello
$(BINDIR)/hello: hello.c
	@echo Generating dynamically-linked hello...
	@if [ $(OSROOT) = bsdi ]; \
	then shlicc -O -o $(BINDIR)/hello hello.c $(LDLIBS); \
	else $(COMPILE) -c -o $(BINDIR)/hello.o hello.c; \
		 $(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/hello  $(STARTFILES) $(BINDIR)/hello.o $(LIBGROUP) $(ENDFILES); \
	fi

# No optimization for these.
$(BINDIR)/mhz: mhz.c common.c bench.h timing.c utils.c counter-common.c
	@echo Compiling mhz...
	@if [ $(OSROOT) = irix ]; \
	then cp mhz.irix $(BINDIR)/mhz; chmod +xw $(BINDIR)/mhz; \
	else $(CC) $(INCLUDE) $(SYS5) -c -o $(BINDIR)/mhz.o mhz.c; \
		 $(CC) $(SYS5) $(POD_LDFLAGS) -o $(BINDIR)/mhz  $(STARTFILES) $(BINDIR)/mhz.o $(LIBGROUP) $(ENDFILES); \
	fi

$(BINDIR)/mhz-counter: mhz.c common.c bench.h timing.c utils.c counter-common.c
	@if [ X$(COUNTERS)X != XX ]; \
	then $(CC) $(INCLUDE) $(COUNTERS) $(SYS5) -c -o $(BINDIR)/mhz-counter.o mhz.c; \
		 $(CC) $(COUNTERS) $(SYS5) $(POD_LDFLAGS) -o $(BINDIR)/mhz-counter  $(STARTFILES) $(BINDIR)/mhz-counter.o $(LIBGROUP) $(ENDFILES); \
	fi

$(BINDIR)/lat_ctx2: lat_ctx2.c
	@echo $(COMPILE) -c -o $(BINDIR)/lat_ctx2.o lat_ctx2.c $(LDLIBS)
	@if [ $(OSROOT) = irix ];\
	then	$(CC) $(SYS5) -32 -O1 -o $(BINDIR)/lat_ctx2 lat_ctx2.c;\
	else	$(COMPILE) -c -o $(BINDIR)/lat_ctx2.o lat_ctx2.c;\
			$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/lat_ctx2  $(STARTFILES) $(BINDIR)/lat_ctx2.o $(LIBGROUP) $(ENDFILES);\
	fi

# XXX not currently supported
#$(BINDIR)/lat_pagefault:  lat_pagefault.c timing.c bench.h
#	@if [ $(OSROOT) = linux -o $(OSROOT) = bsd ];\
#	then    cp /bin/true $(BINDIR)/lat_pagefault;\
#	else    $(COMPILE) -o $(BINDIR)/lat_pagefault lat_pagefault.c $(LDLIBS);\
#	fi

# Do not remove the next line, $(MAKE) depend needs it
# MAKEDEPEND follows
$(BINDIR)/bw_bzero:  bw_bzero.c common.c bench.h counter-common.c timing.c  utils.c
	$(COMPILE) -c -o $(BINDIR)/bw_bzero.o bw_bzero.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/bw_bzero $(STARTFILES) $(BINDIR)/bw_bzero.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/bw_file_rd:  bw_file_rd.c common.c bench.h counter-common.c timing.c  utils.c
	$(COMPILE) -c -o $(BINDIR)/bw_file_rd.o bw_file_rd.c 
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/bw_file_rd $(STARTFILES) $(BINDIR)/bw_file_rd.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/bw_mem_cp:  bw_mem_cp.c common.c bench.h counter-common.c timing.c  utils.c
	$(COMPILE) -c -o $(BINDIR)/bw_mem_cp.o bw_mem_cp.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/bw_mem_cp $(STARTFILES) $(BINDIR)/bw_mem_cp.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/bw_mem_rd:  bw_mem_rd.c common.c bench.h counter-common.c timing.c  utils.c
	$(COMPILE) -c -o $(BINDIR)/bw_mem_rd.o bw_mem_rd.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/bw_mem_rd $(STARTFILES) $(BINDIR)/bw_mem_rd.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/bw_mem_wr:  bw_mem_wr.c common.c bench.h counter-common.c timing.c  utils.c
	$(COMPILE) -c -o $(BINDIR)/bw_mem_wr.o bw_mem_wr.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/bw_mem_wr $(STARTFILES) $(BINDIR)/bw_mem_wr.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/bw_mmap_rd:  bw_mmap_rd.c common.c bench.h counter-common.c timing.c  utils.c
	$(COMPILE) -c -o $(BINDIR)/bw_mmap_rd.o bw_mmap_rd.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/bw_mmap_rd $(STARTFILES) $(BINDIR)/bw_mmap_rd.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/bw_pipe:  bw_pipe.c common.c bench.h counter-common.c timing.c  utils.c
	$(COMPILE) -c -o $(BINDIR)/bw_pipe.o bw_pipe.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/bw_pipe $(STARTFILES) $(BINDIR)/bw_pipe.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/bw_tcp:  bw_tcp.c common.c bench.h counter-common.c timing.c utils.c  lib_tcp.c
	$(COMPILE) -c -o $(BINDIR)/bw_tcp.o bw_tcp.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/bw_tcp $(STARTFILES) $(BINDIR)/bw_tcp.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/common:  common.c bench.h counter-common.c timing.c utils.c
	$(COMPILE) -c -o $(BINDIR)/common.o common.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/common $(STARTFILES) $(BINDIR)/common.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/counter-common:  counter-common.c
	$(COMPILE) -c -o $(BINDIR)/counter-common.o counter-common.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/counter-common $(STARTFILES) $(BINDIR)/counter-common.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/lat_connect:  lat_connect.c common.c bench.h counter-common.c  timing.c utils.c lib_tcp.c
	$(COMPILE) -c -o $(BINDIR)/lat_connect.o lat_connect.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/lat_connect $(STARTFILES) $(BINDIR)/lat_connect.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/lat_ctx:  lat_ctx.c common.c bench.h counter-common.c timing.c  utils.c
	$(COMPILE) -c -o $(BINDIR)/lat_ctx.o lat_ctx.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/lat_ctx $(STARTFILES) $(BINDIR)/lat_ctx.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/lat_fs:  lat_fs.c common.c bench.h counter-common.c timing.c utils.c
	$(COMPILE) -c -o $(BINDIR)/lat_fs.o lat_fs.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/lat_fs $(STARTFILES) $(BINDIR)/lat_fs.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/lat_fslayer:  lat_fslayer.c common.c bench.h counter-common.c  timing.c utils.c
	$(COMPILE) -c -o $(BINDIR)/lat_fslayer.o lat_fslayer.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/lat_fslayer $(STARTFILES) $(BINDIR)/lat_fslayer.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/lat_mem_rd:  lat_mem_rd.c common.c bench.h counter-common.c timing.c  utils.c
	$(COMPILE) -c -o $(BINDIR)/lat_mem_rd.o lat_mem_rd.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/lat_mem_rd $(STARTFILES) $(BINDIR)/lat_mem_rd.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/lat_mmap:  lat_mmap.c common.c bench.h counter-common.c timing.c  utils.c
	$(COMPILE) -c -o $(BINDIR)/lat_mmap.o lat_mmap.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/lat_mmap $(STARTFILES) $(BINDIR)/lat_mmap.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/lat_pipe:  lat_pipe.c common.c bench.h counter-common.c timing.c  utils.c
	$(COMPILE) -c -o $(BINDIR)/lat_pipe.o lat_pipe.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/lat_pipe $(STARTFILES) $(BINDIR)/lat_pipe.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/lat_proc:  lat_proc.c common.c bench.h counter-common.c timing.c  utils.c
	$(COMPILE) -c -o $(BINDIR)/lat_proc.o lat_proc.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/lat_proc $(STARTFILES) $(BINDIR)/lat_proc.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/lat_rpc:  lat_rpc.c common.c bench.h counter-common.c timing.c  utils.c
	$(COMPILE) -c -o $(BINDIR)/lat_rpc.o lat_rpc.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/lat_rpc $(STARTFILES) $(BINDIR)/lat_rpc.o $(LIBGROUP) $(ENDFILES)

# We add -mcmodel=large to the compiler to produce position independent code.
# This is needed while doing a deep-copy of handler functions during pordarch
# syscall marshalling.
$(BINDIR)/lat_sig:  lat_sig.c common.c bench.h counter-common.c timing.c  utils.c
	$(COMPILE) -mcmodel=large -c -o $(BINDIR)/lat_sig.o lat_sig.c
	$(COMPILE) $(POD_LDFLAGS) -mcmodel=large -o $(BINDIR)/lat_sig $(STARTFILES) $(BINDIR)/lat_sig.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/lat_syscall:  lat_syscall.c common.c bench.h counter-common.c  timing.c utils.c
	$(COMPILE) -c -o $(BINDIR)/lat_syscall.o lat_syscall.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/lat_syscall $(STARTFILES) $(BINDIR)/lat_syscall.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/lat_tcp:  lat_tcp.c common.c bench.h counter-common.c timing.c  utils.c lib_tcp.c
	$(COMPILE) -c -o $(BINDIR)/lat_tcp.o lat_tcp.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/lat_tcp $(STARTFILES) $(BINDIR)/lat_tcp.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/lat_udp:  lat_udp.c common.c bench.h counter-common.c timing.c  utils.c lib_udp.c
	$(COMPILE) -c -o $(BINDIR)/lat_udp.o lat_udp.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/lat_udp $(STARTFILES) $(BINDIR)/lat_udp.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/lib_tcp:  lib_tcp.c bench.h
	$(COMPILE) -c -o $(BINDIR)/lib_tcp.o lib_tcp.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/lib_tcp $(STARTFILES) $(BINDIR)/lib_tcp.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/lib_udp:  lib_udp.c bench.h
	$(COMPILE) -c -o $(BINDIR)/lib_udp.o lib_udp.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/lib_udp $(STARTFILES) $(BINDIR)/lib_udp.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/memsize:  memsize.c common.c bench.h counter-common.c timing.c  utils.c
	$(COMPILE) -c -o $(BINDIR)/memsize.o memsize.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/memsize $(STARTFILES) $(BINDIR)/memsize.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/timing:  timing.c bench.h
	$(COMPILE) -c -o $(BINDIR)/timing.o timing.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/timing $(STARTFILES) $(BINDIR)/timing.o $(LIBGROUP) $(ENDFILES)

$(BINDIR)/utils:  utils.c bench.h timing.c
	$(COMPILE) -c -o $(BINDIR)/utils.o utils.c
	$(COMPILE) $(POD_LDFLAGS) -o $(BINDIR)/utils $(STARTFILES) $(BINDIR)/utils.o $(LIBGROUP) $(ENDFILES)
