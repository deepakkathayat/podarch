#!/bin/bash
BIN=bin/linux-x86_64
STATIC_BINARIES=(bw_bzero bw_mem_cp bw_mem_rd bw_mem_wr hello hello-s lat_sig memsize mhz lat_mmap bw_file_rd lat_ctx2 lat_syscall lat_fs bw_mmap_rd lat_mem_rd lat_fslayer lat_ctx)
CC=gcc
TOOLCHAIN_DIR=../../../Toolchain

GLIBCDIR='../../../eglibc-2.19/install/lib'
STARTFILES="$GLIBCDIR/crt1.o  $GLIBCDIR/crti.o /usr/lib/gcc/x86_64-linux-gnu/4.8/crtbegin.o"
ENDFILES="/usr/lib/gcc/x86_64-linux-gnu/4.8/crtend.o $GLIBCDIR/crtn.o"
LIBGROUP=' -Wl,--start-group '$GLIBCDIR'/libc.a -I/usr/local/include -L/usr/local/lib -lgcrypt -lgpg-error -lgcc -lgcc_eh -Wl,--end-group'
WRAP='-Wl,--wrap=open,--wrap=fopen,--wrap=read,--wrap=nanosleep,--wrap=__access,--wrap=link,--wrap=unlink,--wrap=readlink,--wrap=__open,--wrap=__readlink,--wrap=uname,--wrap=write,--wrap=access,--wrap=getrusage,--wrap=chdir,--wrap=creat'
LDFLAGS=" -nostdlib -nostartfiles -static -T $TOOLCHAIN_DIR/page_aligner "$WRAP

make clobberall
make build

for var in ${STATIC_BINARIES[@]}
do
	$TOOLCHAIN_DIR/get_pod_int -i $BIN/$var -o some_$var -k $TOOLCHAIN_DIR/key -c $TOOLCHAIN_DIR/cpu > /dev/null	
	ld -r -b binary -o pod_intc.o podintc
	objcopy --rename-section .data=.intc,alloc,load,readonly,data,contents pod_intc.o pod_intc.o
	ld -r -b binary -o pod_intd.o podintd
	objcopy --rename-section .data=.intd,alloc,load,data,contents pod_intd.o pod_intd.o
    ld -r -b binary -o pod_intbss.o podintbss
    objcopy --rename-section .data=.intbss,alloc,load,data,contents pod_intbss.o pod_intbss.o
    ld -r -b binary -o pod_ints.o podints
    objcopy --rename-section .data=.ints,alloc,load,data,contents pod_ints.o pod_ints.o
    ld -r -b binary -o pod_intmmap.o podintmmap
    objcopy --rename-section .data=.intmmap,alloc,load,data,contents pod_intmmap.o pod_intmmap.o
    ld -r -b binary -o pod_intbrk.o podintbrk
    objcopy --rename-section .data=.intbrk,alloc,load,data,contents pod_intbrk.o pod_intbrk.o

	$CC $LDFLAGS -o $BIN/$var $STARTFILES $BIN/$var.o pod_intc.o pod_intd.o pod_intbss.o pod_ints.o pod_intmmap.o pod_intbrk.o $LIBGROUP $ENDFILES
	$TOOLCHAIN_DIR/makepod -i $BIN/$var -o $BIN/$var'_pod' -k $TOOLCHAIN_DIR/key -c $TOOLCHAIN_DIR/cpu > /dev/null

	rm -rf some_$var
done

rm -rf podint* pod_intc.o pod_intd.o pod_ints.o pod_intmmap.o pod_intbrk.o pod_intbss.o

