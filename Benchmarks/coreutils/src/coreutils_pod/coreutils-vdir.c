/* vdir -- wrapper to ls with the right ls_mode.
   Copyright (C) 2014 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* Written by Alex Deymo <deymo@chromium.org>.  */

#include <config.h>
#include "system.h"

#include "ls.h"
/* Ensure that the main for ls is declared even if the tool is not being built
   in this single-binary. */
int _single_binary_main_ls (int argc, char** argv) ATTRIBUTE_NORETURN;
int _single_binary_main_vdir (int argc, char** argv) ATTRIBUTE_NORETURN;

int _single_binary_main_vdir (int argc, char** argv)
{
  ls_mode = LS_LONG_FORMAT;
  _single_binary_main_ls (argc, argv);
}
