#!/usr/bin/env bash
#
# ./test_all_hbenchOS.sh [vanilla|podarch]
#
# An utility script to check all hbenchOS binaries
#
# Author: Viswesh Narayanan (visweshn92)

input_file1="../../dump1"
input_file2="../../dump2"

if [[ ( "$#" -ne 0 ) && ( "$1" = "vanilla" ) ]]; then

    ################ bw_bzero.c #######################

    ./bw_bzero 100 40960 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_bzero.c"
        exit $rc
    fi

    ################ bw_file_rd.c #######################

    ./bw_file_rd 10 409600 4096 $input_file2 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_file_rd.c"
        exit $rc
    fi

    ################ bw_mem_cp.c #######################

    ./bw_mem_cp 1000 40960 libc aligned > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_mem_cp.c libc aligned"
        exit $rc
    fi

    ./bw_mem_cp 1000 40960 libc unaligned > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_mem_cp.c libc unaligned"
        exit $rc
    fi

    ./bw_mem_cp 1000 40960 unrolled aligned > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_mem_cp.c unrolled aligned"
        exit $rc
    fi

    ./bw_mem_cp 1000 40960 unrolled unaligned > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_mem_cp.c unrolled unaligned"
        exit $rc
    fi

    ################ bw_mem_rd.c #######################

    ./bw_mem_rd 1000 40960 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_mem_rd.c"
        exit $rc
    fi

    ################ bw_mem_wr.c #######################

    ./bw_mem_wr 1000 40960 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_mem_wr.c"
        exit $rc
    fi

    ################ bw_mmap_rd.c #######################

    ./bw_mmap_rd 10 4096 $input_file2 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_mmap_rd.c"
        exit $rc
    fi

    ################ hello.c [N.B. This belongs to hbenchOS] #########

    ./hello > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 13 ]
    then
        echo "Failed: hello.c"
        exit $rc
    fi

    ################ hello-s.c #######################

    ./hello-s > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 13 ]
    then
        echo "Failed: hello-s.c"
        exit $rc
    fi

    ################ lat_ctx.c #######################
    # NOTE : Works only for nproc = 1 in PodArch
    ##################################################
    ./lat_ctx 10 1 1 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_ctx.c"
        exit $rc
    fi

    ################ lat_ctx2.c #######################
    # NOTE : Works only for nproc = 1 in PodArch
    ##################################################
    ./lat_ctx2 10 1 1 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_ctx2.c"
        exit $rc
    fi

    ################ lat_fslayer.c ####################

    ./lat_fslayer 1000 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_fslayer.c"
        exit $rc
    fi

    ################ lat_fs.c #########################

    ./lat_fs 10 create 40960 /tmp/ > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_fs.c create"
        exit $rc
    fi

    ./lat_fs 10 delforw 40960 /tmp/ > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_fs.c delforw"
        exit $rc
    fi


    ./lat_fs 10 delrev 40960 /tmp/ > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_fs.c delrev"
        exit $rc
    fi

    ./lat_fs 10 delrand 40960 /tmp/ > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_fs.c delrand"
        exit $rc
    fi

    ################ lat_mem_rd.c #######################

    ./lat_mem_rd 1 2 /tmp/ 4096 160 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_mem_rd.c"
        exit $rc
    fi

    ################ lat_mmap.c #######################

    ./lat_mmap 100 4096 $input_file2 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_mmap.c"
        exit $rc
    fi

    ################ lat_sig.c #######################

    ./lat_sig 100 install > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_sig.c install"
        exit $rc
    fi

    ./lat_sig 100 handle > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_sig.c handle"
        exit $rc
    fi

    ################ lat_syscall.c #######################

    ./lat_syscall 10 sigaction > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_syscall.c sigaction"
        exit $rc
    fi

    ./lat_syscall 10 gettimeofday > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_syscall.c gettimeofday"
        exit $rc
    fi

    ./lat_syscall 10 sbrk > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_syscall.c sbrk"
        exit $rc
    fi

    ./lat_syscall 10 getrusage > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_syscall.c getrusage"
        exit $rc
    fi

    ./lat_syscall 10 write > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_syscall.c write"
        exit $rc
    fi

    ./lat_syscall 10 getpid > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_syscall.c getpid"
        exit $rc
    fi

    ############### memsize.c ######################

    ./memsize 128 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: memsize.c"
        exit $rc
    fi

    ############### mhz.c ######################

    ./mhz > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: mhz.c"
        exit $rc
    fi

    echo "Vanilla - All Passed!"
fi

if [[ ( "$#" -ne 0 ) && ( "$1" = "podarch" ) ]]; then

    ################ bw_bzero.c #######################

    ./bw_bzero_pod 100 40960 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_bzero.c"
        exit $rc
    fi

    ################ bw_file_rd.c #######################

    ./bw_file_rd_pod 10 409600 4096 $input_file2 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_file_rd.c"
        exit $rc
    fi

    ################ bw_mem_cp.c #######################

    ./bw_mem_cp_pod 1000 40960 libc aligned > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_mem_cp.c libc aligned"
        exit $rc
    fi

    ./bw_mem_cp_pod 1000 40960 libc unaligned > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_mem_cp.c libc unaligned"
        exit $rc
    fi

    ./bw_mem_cp_pod 1000 40960 unrolled aligned > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_mem_cp.c unrolled aligned"
        exit $rc
    fi

    ./bw_mem_cp_pod 1000 40960 unrolled unaligned > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_mem_cp.c unrolled unaligned"
        exit $rc
    fi

    ################ bw_mem_rd.c #######################

    ./bw_mem_rd_pod 1000 40960 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_mem_rd.c"
        exit $rc
    fi

    ################ bw_mem_wr.c #######################

    ./bw_mem_wr_pod 1000 40960 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_mem_wr.c"
        exit $rc
    fi

    ################ bw_mmap_rd.c #######################

    ./bw_mmap_rd_pod 10 4096 $input_file2 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: bw_mmap_rd.c"
        exit $rc
    fi

    ################ hello.c [N.B. This belongs to hbenchOS] #########

    ./hello_pod > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 13 ]
    then
        echo "Failed: hello.c"
        exit $rc
    fi

    ################ hello-s.c #######################

    ./hello-s_pod > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 13 ]
    then
        echo "Failed: hello-s.c"
        exit $rc
    fi

    ################ lat_ctx.c #######################
    # NOTE : Works only for nproc = 1 in PodArch
    ##################################################
    ./lat_ctx_pod 10 1 1 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_ctx.c"
        exit $rc
    fi

    ################ lat_ctx2.c #######################
    # NOTE : Works only for nproc = 1 in PodArch
    ##################################################
    ./lat_ctx2_pod 10 1 1 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_ctx2.c"
        exit $rc
    fi

    ################ lat_fslayer.c ####################

    ./lat_fslayer_pod 1000 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_fslayer.c"
        exit $rc
    fi

    ################ lat_fs.c #########################

    ./lat_fs_pod 10 create 40960 /tmp/ > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_fs.c create"
        exit $rc
    fi

    ./lat_fs_pod 10 delforw 40960 /tmp/ > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_fs.c delforw"
        exit $rc
    fi


    ./lat_fs_pod 10 delrev 40960 /tmp/ > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_fs.c delrev"
        exit $rc
    fi

    ./lat_fs_pod 10 delrand 40960 /tmp/ > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_fs.c delrand"
        exit $rc
    fi

    ################ lat_mem_rd.c #######################

    ./lat_mem_rd_pod 1 2 /tmp/ 4096 160 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_mem_rd.c"
        exit $rc
    fi

    ################ lat_mmap.c #######################

    ./lat_mmap_pod 100 4096 $input_file2 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_mmap.c"
        exit $rc
    fi

    ################ lat_sig.c #######################

    ./lat_sig_pod 100 install > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_sig.c install"
        exit $rc
    fi

    ./lat_sig_pod 100 handle > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_sig.c handle"
        exit $rc
    fi

    ################ lat_syscall.c #######################

    ./lat_syscall_pod 10 sigaction > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_syscall.c sigaction"
        exit $rc
    fi

    ./lat_syscall_pod 10 gettimeofday > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_syscall.c gettimeofday"
        exit $rc
    fi

    ./lat_syscall_pod 10 sbrk > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_syscall.c sbrk"
        exit $rc
    fi

    ./lat_syscall_pod 10 getrusage > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_syscall.c getrusage"
        exit $rc
    fi

    ./lat_syscall_pod 10 write > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_syscall.c write"
        exit $rc
    fi

    ./lat_syscall_pod 10 getpid > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: lat_syscall.c getpid"
        exit $rc
    fi

    ############### memsize.c ######################

    ./memsize_pod 128 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: memsize.c"
        exit $rc
    fi

    ############### mhz.c ######################

    ./mhz_pod > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: mhz.c"
        exit $rc
    fi

    echo "PodArch - All Passed!"
fi

exit 0
