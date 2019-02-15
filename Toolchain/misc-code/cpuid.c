 #include <stdio.h>
 
 int main(int argc, char **argv)
 {
        unsigned int eax, ebx, ecx, edx;
        printf("[%s]\n", argv[0]);
        __asm__ __volatile__ ("movl $1, %%eax\n\t"
                              "cpuid"
                              : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx));
        if (edx & (1 << 10)) {
                printf("cpuid: PodArch bit set\n");
        } else {
                printf("cpuid: PodArch bit not set\n");
        }
        return 0;
 }
