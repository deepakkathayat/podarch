PodArch
=======

Welcome to project "PodArch". Please use the following steps
to compile the source codes in order to get started:

I/ LIBC
-------
The compilation steps are same as standard GNU C Library. The tree cannot be 
compiled in the source directory, hence use a separate build directory to put all 
the object files. Please provide an absolute path when using the --prefix option 
to install the libc. (NOTE: Otherwise it defaults to /usr/local/)

* cd LIBC_DIR 
* mkdir build 
* mkdir install 
* cd build  
* ../libc/configure --prefix=LIBC_DIR/install
* make
* make install

II/ QEMU
--------
PodArch is an extension to x86 architecture, hence create an x86 target machine.
Please use the '--enable-podarch' switch, otherwise it defaults to vanilla QEMU behavior.

PRE-REQUISITE PACKAGES

* libcurl4-gnutls-dev
* libsdl-console-dev

STEPS

* cd QEMU_DIR
* ./configure --target-list=x86_64-softmmu --enable-podarch
* make
* x86_64-softmmu/qemu-system-x86_64 -hda DISK_DIR -m 2G -kernel KERNEL_IMG  -append "root=/dev/sda"

III/ TOOLCHAIN
--------------
This basically has two important scripts:
get_pod_int.c - which puts placeholder sections for virtual descriptors
makepod.c - which actually converts the given binary to a pod-sealed one.

* cd TOOLCHAIN_DIR
* make all

IV/ KERNEL
----------
Please note that we will be using a loadable kernel module (LKM) which
can be attached easily (using 'insmod') to your kernel.
Update the KDIR location in Makefile to point to the kernel source tree
which we will be using with PodArch.

* cd KERNEL_LKM_DIR
* make

Sample Demo
===========

After all the codes are compiled successfully, we will see how to get a simple 'HELLO WORLD'
executed in PodArch. We will need a disk image in DISK_DIR to work with (Need one? click here).

* vim TOOLCHAIN_DIR/sample.c [Make sure we place "pod_header.h"]
* sh TOOLCHAIN_DIR/pod_seal_sample.h
* Load 'TOOLCHAIN_DIR/pod_sample' and 'KERNEL_DIR/pod_kret.ko' into DISK_DIR
* cd QEMU_DIR
* x86_64-softmmu/qemu-system-x86_64 -hda DISK_DIR -m 2G -kernel KERNEL_IMG  -append "root=/dev/sda"

After QEMU finishes booting the OS

* insmod pod_ket.ko
* ./pod_sample

This should execute the code in TOOLCHAIN_DIR/sample.c
