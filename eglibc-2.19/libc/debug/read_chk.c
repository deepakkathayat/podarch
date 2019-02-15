/* Copyright (C) 2005-2014 Free Software Foundation, Inc.
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

#include <unistd.h>
#include <sys/param.h>
#ifdef HAVE_INLINED_SYSCALLS
# include <errno.h>
# include <sysdep.h>
#endif

#define PUB_SIZE 10 * 4096
static char __attribute__((section(".public_page"))) pub_area[PUB_SIZE];

ssize_t
__read_chk (int fd, void *buf, size_t nbytes, size_t buflen)
{
  if (nbytes > buflen)
    __chk_fail ();

 ssize_t ret;
#ifdef HAVE_INLINED_SYSCALLS
  ret = INLINE_SYSCALL (read, 3, fd, &pub_area, nbytes);
#else
  ret = __read (fd, &pub_area, nbytes);
#endif
  memcpy(buf, &pub_area, nbytes);
  return ret;
}
#undef pub_area
