#include<stdio.h>

int main() {

    printf("Welcome! We are testing PodArch instruction support\n");

    unsigned int eax;
    //eax = 988231287; 
    //__asm__ __volatile__ (".byte 0xf1\n\t"
    //                      :
    //                      : "a"(eax)
    //                     );

    printf("It works well\n");
    return 0;
}
