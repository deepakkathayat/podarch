#!/usr/bin/env bash
#
# ./test_all_coreutils.sh [vanilla|podarch]
#
# An utility script to check all coreutils binaries
# Please call this along with input test files
#
# Author: Viswesh Narayanan (visweshn92)

input_file1="../dump1"
input_file2="../dump2"
tsort_input="../dump3"

if [[ ( "$#" -ne 0 ) && ( "$1" = "vanilla" ) ]]; then

    vanilla_list="dircolors du env getlimits hostid logname mktemp nproc printenv pwd sync true tty uptime users"

    for bin in $vanilla_list
    do
        ./$bin > /tmp/1 2> /tmp/2
        rc=$? 
        if [ $rc != 0 ] 
        then 
            echo "Failed: $bin"
            exit $rc 
        fi
    done

    ./false > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 1 ]
    then
        echo "Failed: false"
        exit $rc
    fi

    ./seq 1 2 100 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: seq"
        exit $rc
    fi

    ./dirname a/b/c/d/e > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: dirname"
        exit $rc
    fi

    ./basename a/b/c/d/e > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: basename"
        exit $rc
    fi

    ./join --nocheck-order $input_file1 $input_file2 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: join"
        exit $rc
    fi

    ./comm $input_file1 $input_file2 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: comm"
        exit $rc
    fi

    ./chmod a+x $input_file2 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: chmod"
        exit $rc
    fi
    
    vanilla_list="head tail fmt expand cksum cat base64 nl od sum wc uniq"
    for bin in $vanilla_list
    do
        ./$bin $input_file1 > /tmp/1 2> /tmp/2
        rc=$? 
        if [ $rc != 0 ] 
        then 
            echo "Failed: $bin"
            exit $rc 
        fi
    done

    ./csplit $input_file1 13 62 101 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: csplit"
        exit $rc
    fi
    rm -f xx0*

    cp $input_file1 /tmp/input_cut
    ./cut -b 5 /tmp/input_cut > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: cut"
        exit $rc
    fi

    ./echo "Sample Input" > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: echo"
        exit $rc
    fi

    cp $input_file1 /tmp/input_fold
    ./fold --width=10 /tmp/input_fold > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: fold"
        exit $rc
    fi

    ./mkfifo pipe > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: mkfifo"
        exit $rc
    fi
    rm -f pipe

    ./printf "Sample Input" > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: printf"
        exit $rc
    fi

    ./ptx $input_file2 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: ptx"
        exit $rc
    fi

    ln -s $input_file1 /tmp/readlink_input
    ./readlink /tmp/readlink_input > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: readlink"
        exit $rc
    fi
    unlink /tmp/readlink_input

    cp $tsort_input /tmp/shred_input
   ./shred  /tmp/shred_input > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: shred"
        exit $rc
    fi

    ./shuf $input_file1 > /tmp/1 2> /tmp/2    
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: shuf"
        exit $rc
    fi

    ./sleep 5
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: sleep"
        exit $rc
    fi

    cp $input_file2 /tmp/split_input
    ./split -b 1000 /tmp/split_input > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: split"
        exit $rc
    fi
    rm -f x*

    ./tac $input_file1 $input_file2 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: tac"
        exit $rc
    fi

    cp $input_file1 /tmp/truncate_input
    ./truncate -s 4096 /tmp/truncate_input > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: truncate"
        exit $rc
    fi


    ./tsort $tsort_input > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: tsort"
        exit $rc
    fi

     cp $input_file1 /tmp/input_link
    ./link /tmp/input_link /tmp/link > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: link"
        exit $rc
    fi

    ./unlink /tmp/link > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: unlink"
        exit $rc
    fi

    ./tr 0 9 < $input_file1 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: tr"
        exit $rc
    fi

   ./stty -a > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: stty"
        exit $rc
    fi

    echo "Vanilla - All Passed!"
fi

if [[ ( "$#" -ne 0 ) && ( "$1" = "podarch" ) ]]; then

    pod_list="dircolors_pod du_pod env_pod getlimits_pod hostid_pod logname_pod mktemp_pod nproc_pod printenv_pod pwd_pod sync_pod true_pod tty_pod uptime_pod users_pod"

    for bin in $pod_list
    do
        ./$bin > /tmp/1 2> /tmp/2
        rc=$? 
        if [ $rc != 0 ] 
        then 
            echo "Failed: $bin"
            exit $rc 
        fi
    done

    ./false_pod > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 1 ]
    then
        echo "Failed: false_pod"
        exit $rc
    fi

    ./seq_pod 1 2 100 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: seq_pod"
        exit $rc
    fi

    ./dirname_pod a/b/c/d/e > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: dirname_pod"
        exit $rc
    fi

    ./basename_pod a/b/c/d/e > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: basename_pod"
        exit $rc
    fi

    ./join_pod --nocheck-order $input_file1 $input_file2 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: join_pod"
        exit $rc
    fi

    ./comm_pod $input_file1 $input_file2 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: comm_pod"
        exit $rc
    fi

    ./chmod_pod a+x $input_file2 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: chmod_pod"
        exit $rc
    fi

    pod_list="head_pod tail_pod fmt_pod expand_pod cksum_pod cat_pod base64_pod nl_pod od_pod sum_pod wc_pod uniq_pod"
    for bin in $pod_list
    do
        ./$bin $input_file1 > /tmp/1 2> /tmp/2
        rc=$? 
        if [ $rc != 0 ] 
        then 
            echo "Failed: $bin"
            exit $rc 
        fi
    done

    ./csplit_pod $input_file1 13 62 101 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: csplit_pod"
        exit $rc
    fi
    rm -f xx0*

    cp $input_file1 /tmp/input_cut
    ./cut_pod -b 5 /tmp/input_cut > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: cut_pod"
        exit $rc
    fi

    ./echo_pod "Sample Input" > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: echo_pod"
        exit $rc
    fi

    cp $input_file1 /tmp/input_fold
    ./fold_pod --width=10 /tmp/input_fold > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: fold_pod"
        exit $rc
    fi

    ./mkfifo_pod pipe > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: mkfifo_pod"
        exit $rc
    fi
    rm -f pipe

    ./printf_pod "Sample Input" > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: printf_pod"
        exit $rc
    fi

    ./ptx_pod $input_file2 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: ptx_pod"
        exit $rc
    fi

    ln -s $input_file1 /tmp/readlink_input
    ./readlink_pod /tmp/readlink_input > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: readlink_pod"
        exit $rc
    fi
    unlink /tmp/readlink_input

    cp $tsort_input /tmp/shred_input
   ./shred_pod  /tmp/shred_input > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: shred_pod"
        exit $rc
    fi

    ./shuf_pod $input_file1 > /tmp/1 2> /tmp/2    
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: shuf_pod"
        exit $rc
    fi

    ./sleep_pod 5
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: sleep_pod"
        exit $rc
    fi

    cp $input_file2 /tmp/split_input
    ./split_pod -b 1000 /tmp/split_input > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: split_pod"
        exit $rc
    fi
    rm -f x*

    ./tac_pod $input_file1 $input_file2 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: tac_pod"
        exit $rc
    fi

    cp $input_file1 /tmp/truncate_input
    ./truncate_pod -s 4096 /tmp/truncate_input > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: truncate_pod"
        exit $rc
    fi


    ./tsort_pod $tsort_input > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: tsort_pod"
        exit $rc
    fi

     cp $input_file1 /tmp/input_link
    ./link_pod /tmp/input_link /tmp/link > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: link_pod"
        exit $rc
    fi

    ./unlink_pod /tmp/link > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: unlink_pod"
        exit $rc
    fi

    ./tr_pod 0 9 < $input_file1 > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: tr_pod"
        exit $rc
    fi

   ./stty_pod -a > /tmp/1 2> /tmp/2
    rc=$?
    if [ $rc != 0 ]
    then
        echo "Failed: stty_pod"
        exit $rc
    fi

    echo "PodArch - All Passed!"
fi

exit 0
