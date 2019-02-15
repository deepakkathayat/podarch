/* Copyright (C) 2001-2014 Free Software Foundation, Inc.
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

#include <errno.h>
#include <sys/socket.h>
#include <sysdep-cancel.h>

#define PUB_SIZE 5 * 4096
static char __attribute__((section(".public_page"))) pub_area_send[PUB_SIZE];

/* Send N bytes of BUF to socket FD.  Returns the number sent or -1.  */
ssize_t
__libc_send (int fd, const void *buf, size_t n, int flags)
{
  memcpy(&pub_area_send, buf, n);

  if (SINGLE_THREAD_P)
    return INLINE_SYSCALL (sendto, 6, fd, pub_area_send, n, flags, NULL, (size_t) 0);

  int oldtype = LIBC_CANCEL_ASYNC ();

  ssize_t result = INLINE_SYSCALL (sendto, 6, fd, pub_area_send, n, flags, NULL,
				   (size_t) 0);

  LIBC_CANCEL_RESET (oldtype);

  return result;
}

weak_alias (__libc_send, __send)
libc_hidden_weak (__send)
weak_alias (__send, send)
#undef PUB_SIZE
