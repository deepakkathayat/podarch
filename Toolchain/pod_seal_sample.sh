# Clean Ups
rm -f sample
rm -f pod_sample
rm -f some_sample
rm -f podintc
rm -f podintd
rm -f podints
rm -f podintbss
rm -f podintbrk
rm -f podintmmap
rm -f *.o

# Wrapper
GLIBCDIR='/home/vichu/PodArch-Private/eglibc-2.19/install/lib'
STARTFILES="$GLIBCDIR/crt1.o  $GLIBCDIR/crti.o /usr/lib/gcc/x86_64-linux-gnu/4.8/crtbegin.o"
ENDFILES="/usr/lib/gcc/x86_64-linux-gnu/4.8/crtend.o $GLIBCDIR/crtn.o"
LIBGROUP=' -Wl,--start-group '$GLIBCDIR'/libc.a -I/usr/local/include -L/usr/local/lib -lgcrypt -lgpg-error -lgcc -lgcc_eh -Wl,--end-group'
WRAP='-Wl,--wrap=open,--wrap=fopen,--wrap=read,--wrap=nanosleep,--wrap=__access,--wrap=link,--wrap=unlink,--wrap=readlink,--wrap=__open,--wrap=__readlink,--wrap=uname,--wrap=write,--wrap=access,--wrap=getrusage,--wrap=chdir,--wrap=creat'
LDFLAGS=' -nostdlib -nostartfiles -static -T page_aligner '$WRAP

# Pod Sealing
gcc -c -mcmodel=large -o sample.o sample.c
gcc $LDFLAGS -o sample $STARTFILES sample.o $LIBGROUP $ENDFILES

./get_pod_int -i sample -o some_sample -k key -c cpu > /tmp/get_pod_intc.out

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

gcc $LDFLAGS -o sample $STARTFILES sample.o pod_intc.o pod_intd.o pod_intbss.o pod_ints.o pod_intmmap.o pod_intbrk.o $LIBGROUP $ENDFILES

./makepod -i sample -o pod_sample -k key -c cpu > /tmp/makepod.out

# Mounting to Disk
sudo mount ~/working1/podarch/sid.ext2 /mnt/
sudo cp pod_sample /mnt/home/
sudo umount /mnt/

