/*
 * pod_header.h - Wrapper for system calls in PodArch
 * 
 * The idea is to hook *ALL* the libc calls (which internally
 * calls the system calls) and transfer the required contents
 * into public page. This is needed for two reasons:
 * 
 * - To allow benign working of OS as we need to start tracking
 *   the address mapping in I-PACT and decrypt the contents in user
 *   space (i.e. in ring 3).
 * 
 * - To protect the sensitive information stored in these addresses.
 *   from being accessed by malicious OS.
 *
 * USAGE:
 * ======
 * To wrap a new libc function <func>, add a __real_<func> declaration
 * and __wrap_<func> definition with right signatures. Also be sure to
 * add a corresponding GNU linker option -Wl,--wrap=<func> in our binary
 * toolchain to ensure system call marshalling during 'pod-sealing' step.
 *
 * NOTE:
 * =====
 * The below wrappers list may not be exhaustive. Please add wrappers
 * to libc functions as the need grows. 'ltrace' and 'strace' could be
 * useful to check what wrappers are needed.
 * The below link has the list of libc wrapper APIs
 * http://www.gnu.org/software/libc/manual/html_node/Function-Index.html
 * 
 *  Copyright (c) 2015 visweshn92
 */

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <signal.h>

/* This value should ideally be enough (i.e. almost 10 pages)
 * increase later if needed.
 */ 
#define PUB_SIZE 262144
#define POD_ENTER 6

static unsigned char __attribute__((section(".public_page"))) pub_area[PUB_SIZE] __attribute__((aligned(4096)));
static struct timespec __attribute__((section(".public_page"))) pub_req_time, pub_rem_time;

/* This function needs to be compiled without frame-pointer restore
   This is needed as CPU will jumping to _start while handling pod_enter
   Otherwise stack will be in an inconsistent state to begin __libc_start_main()
   with the correct argc and argv paramenters.
 */
void pod_enter() __attribute__((optimize("-fomit-frame-pointer")))  __attribute__((section(".public_code")));
void pod_enter()
{
  
   __asm__ __volatile__(".byte 0xf1"
                        :
                        : "a"(POD_ENTER));

}

void pod_exiter()
{
    exit(0);
}

/* This function basically registers the individual signal handlers
   needed while handling signals for PodArch. When these signals
   are called, we will finally do a pod_exit() to safely terminate.
*/
void pod_init() {
    signal(SIGINT, pod_exiter);
}

int __real___access(char *filename, int how);
int __wrap___access(char *filename, int how)
{
    int i;
    for (i = 0; filename[i] != '\0'; i++)
        pub_area[i] = filename[i];
    pub_area[i] = '\0';

    return __real___access((char*) pub_area, how);
}

int __real_access(char *filename, int how);
int __wrap_access(char *filename, int how)
{
    int i;
    for (i = 0; filename[i] != '\0'; i++)
        pub_area[i] = filename[i];
    pub_area[i] = '\0';

    return __real_access((char*) pub_area, how);
}

int __real_chdir(const char *path);
int __wrap_chdir(const char *path)
{
    int i;
    for (i = 0; path[i] != '\0'; i++)
        pub_area[i] = path[i];
    pub_area[i] = '\0';

    return __real_chdir((char*) pub_area);
}

int __real_creat(const char *path, int mode);
int __wrap_creat(const char *path, int mode)
{
    int i;
    for (i = 0; path[i] != '\0'; i++)
        pub_area[i] = path[i];
    pub_area[i] = '\0';

    return __real_creat((char*) pub_area, mode);
}

int __real_link (const char *oldname, const char *newname);
int __wrap_link (const char *oldname, const char *newname)
{
    int i,l;
    for (l = 0; oldname[l] != '\0'; l++)
        pub_area[l] = oldname[l];
    pub_area[l++] = '\0';

    for (i = 0; newname[i] != '\0'; i++)
        pub_area[l + i] = newname[i];
    pub_area[l + i] ='\0';

    return __real_link((char*)pub_area, (char*)(pub_area + l));
}

int __real_unlink (const char *name);
int __wrap_unlink (const char *name)
{
    int i;
    for (i = 0; name != NULL && name[i] != '\0'; i++)
        pub_area[i] = name[i];
    pub_area[i] ='\0';

    return __real_unlink(name ? (char*)pub_area : NULL);
}

int __real_uname (struct utsname *ut);
int __wrap_uname (struct utsname *ut)
{
    int ret;
    ret = __real_uname((struct utsname*) pub_area);
    memcpy(ut, pub_area, sizeof(struct utsname));
    return ret;
}

int __real_getrusage (int who, struct rusage *ru);
int __wrap_getrusage (int who, struct rusage *ru)
{
    int ret;
    ret = __real_getrusage(who, (struct rusage*) pub_area);
    memcpy(ru, pub_area, sizeof(struct rusage));
    return ret;
}

ssize_t __real_write(int fd, char *buf, size_t nbytes);
ssize_t __wrap_write(int fd, char *buf, size_t nbytes)
{
    size_t i;
    for(i = 0; i < nbytes; i++)
        pub_area[i] = buf[i];

    return __real_write(fd, (char*)pub_area, nbytes);
}

ssize_t __real_readlink (const char *filename, char *buffer, size_t size);
ssize_t __wrap_readlink (const char *filename, char *buffer, size_t size)
{
    int i;
    ssize_t ret;

    for (i = 0; filename[i] != '\0'; i++)
        pub_area[i] = filename[i];
    pub_area[i++] ='\0';

    ret = __real_readlink((char*) pub_area, (char*) (pub_area + i), size);
    memcpy(buffer, (char*) (pub_area + i), size);
    return ret;
}

ssize_t __real___readlink (const char *filename, char *buffer, size_t size);
ssize_t __wrap___readlink (const char *filename, char *buffer, size_t size)
{
    int i;
    ssize_t ret;

    for (i = 0; filename[i] != '\0'; i++)
        pub_area[i] = filename[i];
    pub_area[i++] ='\0';

    ret = __real___readlink((char*) pub_area, (char*) (pub_area + i), size);
    memcpy(buffer, (char*) (pub_area + i), size);
    return ret;
}

int __real_open(char *path, int oflags);
int __wrap_open(char *path, int oflags)
{
    int i;
    for(i = 0; path[i] != '\0'; i++)
        pub_area[i] = path[i];
    pub_area[i] = '\0';

    return __real_open((char*)pub_area, oflags);
}

int __real___open(char *path, int oflags);
int __wrap___open(char *path, int oflags)
{
    int i;
    for(i = 0; path[i] != '\0'; i++)
        pub_area[i] = path[i];
    pub_area[i] = '\0';

    return __real___open((char*)pub_area, oflags);
}

ssize_t __real_read(int fd, char *buf, size_t count);
ssize_t __wrap_read(int fd, char *buf, size_t count)
{
    ssize_t read_ret = __real_read(fd, (char*)pub_area, count);
    ssize_t i;
    for(i = 0; i < read_ret; i++)
        buf[i] = pub_area[i];

    return read_ret;
}

int __real_nanosleep(struct timespec *requested_time, struct timespec *remaining);
int __wrap_nanosleep(struct timespec *requested_time, struct timespec *remaining)
{
    int ret;
    memcpy(&pub_req_time, requested_time, sizeof(struct timespec));
    if (remaining != NULL)
        memcpy(&pub_rem_time, remaining, sizeof(struct timespec));
    
    ret = __real_nanosleep(&pub_req_time, remaining ? &pub_rem_time : NULL);

    memcpy(requested_time, &pub_req_time, sizeof(struct timespec));

    if (remaining != NULL)
        memcpy(remaining, &pub_rem_time, sizeof(struct timespec));
    return ret;
}


FILE* __real_fopen(char *filename, char *mode);
FILE* __wrap_fopen(char *filename, char *mode)
{
    int i, l;
    for (l = 0; filename[l] != '\0'; l++)
        pub_area[l] = filename[l];
    pub_area[l++] = '\0';

    for (i = 0; mode[i] != '\0'; i++)
        pub_area[l + i] = mode[i];
    pub_area[l + i] = '\0';

    return __real_fopen((char*)pub_area, (char*)(pub_area + l));
}
