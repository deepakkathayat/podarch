Frequently Asked Questions
==========================

- **I/ How to change the 'page_aligner' linker script ?**


The page_aligner script in TOOLCHAIN_DIR was prepared for Ubuntu 14.04 LTS
[kernel 3.13.0-55-generic and gcc 4.8.4]. The only modifications done were
adding page alignment properties to data, code, bss and integrity descriptors
segments [i.e. addition of .ALIGN(4096)]. If your versions change drastically
from the above, it is better to prepare a new page_aligner script to be used
for linking. To prepare a new one, simple run any script with GCC in verbose
mode and pull out the vanilla linker script and edit:

    gcc <my_script> -Wl,-verbose
    Add .ALIGN(4096) to respective sections



- **II/ How do I turn on the PodArch logging in QEMU ?**

This comes in very useful for debugging an issue wrt PodArch.
To enable the logging, please set the ENABLE_PODARCH_LOG flag in 
QEMU_DIR/include/exec/pod-common.h. If we wish to disable, please
unset the flag in the mentioned file and re-compile QEMU sources



 - **III/ How do I ensure all my system calls are marshalled correctly ?**

Please check once using 'strace' the system calls that are being used.
Most of them are already handled by us in LIBC_DIR. In case a syscall is
missed, most likely the code will result in SEGFAULT and the QEMU log 
(if enabled) will appear as below:

    > cat /tmp/qemu_log | tail -4
    [        seg_helper.c:  1091] Syscall 14 from 0x441480
    [        seg_helper.c:  1092] EDI: 1 ESI: 4c0d52e0 EDX: 0
    [  softmmu_template.h:   307] [1] Cloaking entry in IPACT: 0x7f589eab9000-> (0x4c0d5000, 1234567887654321)
    [        pod_helper.c:   466] do_page_encrypt(): 0x4c0d5000


This shows that marshalling is NOT proper as Syscall 14 is called
passing a stack address (i.e. ESI value). This causes the kernel to
use the encrypted contents in that address leading to SEGFAULT.

