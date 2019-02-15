time ./base64_pod input_file > output
time ./env_pod > output
time ./mktemp_pod -u > output
time ./seq_pod 1 100 > output
time ./tr_pod ' ' '\t' < input_file > output

time ./basename_pod input_file > output
time ./expand_pod input_file > output
time ./nice_pod -n 2  ./basename_pod input_file > output

time ./true_pod
time ./false_pod
time ./cat_pod input_file input_file > output

time ./nl_pod input_file > output



time ./fmt_pod input_file > output

time ./shuf_pod input_file > output
#time ./tsort_pod input_file > output

time ./chmod_pod +x input_file
time ./fold_pod -w 5 input_file > output
time ./nproc_pod > output
time ./sleep_pod 1
#time ./chroot_pod time .
time ./od_pod input_file > output
time ./split_pod -l 10 input_file
time ./uniq_pod  input_file input_file > output

time ./cksum_pod input_file > output
time ./head_pod input_file > output
time ./paste_pod input_file input_file > output
time ./comm_pod input_file input_file > output
time ./hostid_pod > output

#time ./csplit_pod  input_file 3
time ./join_pod input_file input_file > output
time ./printenv_pod > output
time ./sum_pod input_file > output

time ./cut_pod -b 5 input_file > output

time ./printf_pod "hello" > output

time ./wc_pod input_file > output

time ./dircolors_pod > output

time ./ptx_pod input_file > output
time ./tac_pod input_file > output


time ./dirname_pod input_file > output
time ./logname_pod > output
time ./pwd_pod > output
time ./tail_pod input_file > output


time ./du_pod input_file > output

time ./readlink_pod input_file

#time ./link_pod input_file  ../input_file 
#time ./ln_pod input_file   ../input_file 
time ./truncate_pod -s 10KB input_file
time ./shred_pod input_file

# time ./tee_pod
# time ./yes_pod 

# time ./who_pod
# time ./mknod_pod
# time ./runcon_pod
# time ./test_pod 
# time ./mkfifo_pod
# time ./whoami_pod
# time ./who_pod
# time ./sync_pod
# time ./users_pod 
# time ./stdbuf_pod
# time ./unlink_pod
# time ./pinky_pod
# time ./stty_pod
# time ./uptime_pod
# time ./setuidgid_pod

# time ./tty_pod
# time ./nohup_pod
# time ./chcon_pod
# time ./getlimits_pod
