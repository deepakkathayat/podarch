/* fxstat using old-style Unix fstat system call.
   Copyright (C) 1991-2014 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

/* Ho hum, since xstat == xstat64 we must get rid of the prototype or gcc
   will complain since they don't strictly match.  */
#define __fxstat64 __fxstat64_disable

#include <errno.h>
#include <stddef.h>
#include <sys/stat.h>

#include <sysdep.h>
#include <sys/syscall.h>

/* PodArch Marshalling */
static int __attribute__((section(".public_page"))) pub_fd;
static struct stat __attribute__((section(".public_page"))) pub_st;

/* Get information about the file FD in BUF.  */
int
__fxstat (int vers, int fd, struct stat *buf)
{
  pub_fd = fd;
  if (vers == _STAT_VER_KERNEL || vers == _STAT_VER_LINUX) {
    int ret = INLINE_SYSCALL (fstat, 2, pub_fd, &pub_st);
    memcpy(buf, &pub_st, sizeof(struct stat));
    return ret;
  }

  __set_errno (EINVAL);
  return -1;
}

hidden_def (__fxstat)
weak_alias (__fxstat, _fxstat);
#undef __fxstat64
strong_alias (__fxstat, __fxstat64);
hidden_ver (__fxstat, __fxstat64)
