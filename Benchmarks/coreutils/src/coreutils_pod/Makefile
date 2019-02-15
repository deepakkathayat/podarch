TOP_DIR       = ../..
TOOLCHAIN_DIR = ../../../../Toolchain
LIBDIR        = $(TOP_DIR)/lib/libcoreutils.a $(TOP_DIR)/src/libver.a
INCLUDE       = -I $(TOP_DIR)/lib/ -I $(TOOLCHAIN_DIR)/

GLIBCDIR   = ../../../../eglibc-2.19/install/lib
STARTFILES = $(GLIBCDIR)/crt1.o $(GLIBCDIR)/crti.o `gcc --print-file-name=crtbegin.o`
ENDFILES   = `gcc --print-file-name=crtend.o` $(GLIBCDIR)/crtn.o
LIBGROUP   = -Wl,--start-group $(LIBDIR) $(GLIBCDIR)/libc.a -lgcc -lgcc_eh -Wl,--end-group
WRAP       = -Wl,--wrap=open,--wrap=fopen,--wrap=read,--wrap=nanosleep,--wrap=__access,--wrap=link,--wrap=unlink,--wrap=readlink,--wrap=__open,--wrap=__readlink,--wrap=uname,--wrap=write,--wrap=access,--wrap=getrusage,--wrap=chdir,--wrap=creat

LDFLAGS = $(INCLUDE) -nostdlib -nostartfiles -static -T $(TOOLCHAIN_DIR)/page_aligner $(WRAP)
CFLAGS  = -std=c99 -c
CC = gcc 

EXECUTABLES = base64 basename cat chcon chmod cksum comm csplit cut dircolors dirname du echo env expand  false fmt fold getlimits head hostid join link logname mkfifo mknod mktemp  nice nl nohup nproc od paste printenv printf ptx pwd readlink  runcon seq shred shuf sleep split stdbuf stty  sum sync tac tail tee  tr true truncate tsort tty uniq unlink uptime users wc yes


all : $(EXECUTABLES)

$(EXECUTABLES) :
	$(CC) $(INCLUDE) $(CFLAGS) -o $@.o $@.c
	$(CC) $(LDFLAGS) -o $@ $(STARTFILES) $@.o $(LIBGROUP) $(ENDFILES)

	$(CC) $(INCLUDE) $(CFLAGS) -o $@.o $@.c
	
	$(TOOLCHAIN_DIR)/get_pod_int -i $@ -o some_$@ -k $(TOOLCHAIN_DIR)/key -c $(TOOLCHAIN_DIR)/cpu > /dev/null
	ld -r -b binary -o pod_intc.o podintc
	objcopy --rename-section .data=.intc,alloc,load,readonly,data,contents pod_intc.o pod_intc.o
	ld -r -b binary -o pod_intd.o podintd
	objcopy --rename-section .data=.intd,alloc,load,data,contents pod_intd.o pod_intd.o
	ld -r -b binary -o pod_ints.o podints
	objcopy --rename-section .data=.ints,alloc,load,data,contents pod_ints.o pod_ints.o
	ld -r -b binary -o pod_intbss.o podintbss
	objcopy --rename-section .data=.intbss,alloc,load,data,contents pod_intbss.o pod_intbss.o
	ld -r -b binary -o pod_intbrk.o podintbrk
	objcopy --rename-section .data=.intbrk,alloc,load,data,contents pod_intbrk.o pod_intbrk.o
	ld -r -b binary -o pod_intmmap.o podintmmap
	objcopy --rename-section .data=.intmmap,alloc,load,data,contents pod_intmmap.o pod_intmmap.o

	$(CC) $(LDFLAGS) -o $@ $(STARTFILES) $@.o pod_intc.o pod_intd.o pod_ints.o pod_intbss.o pod_intbrk.o pod_intmmap.o $(LIBGROUP) $(ENDFILES)
	$(TOOLCHAIN_DIR)/makepod -i $@ -o $@_pod -k $(TOOLCHAIN_DIR)/key -c $(TOOLCHAIN_DIR)/cpu > /dev/null
	$(RM) *~ *.o some_*
	$(RM) podint*
clean :
	$(RM) *~  *.o $(EXECUTABLES) *_pod some_*  podint*

