/*
 *  Declarations for filesytem-related utilities for cryptmount
 *  (C)Copyright 2005-2018, RW Penney
 */

/*
    This file is part of cryptmount

    cryptmount is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    cryptmount is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#ifndef _FSUTILS_H
#define _FSUTILS_H

/*! \addtogroup fsys_utils
 *  @{ */

struct tgtdefn;

int fs_check(const char *dev, const struct tgtdefn *tgt);
int fs_mount(const char *dev, const struct tgtdefn *tgt);
int fs_unmount(const struct tgtdefn *tgt);
int fs_swapon(const char *dev, const struct tgtdefn *tgt);
int fs_swapoff(const struct tgtdefn *tgt);
int is_mounted(const struct tgtdefn *tgt);
int is_readonlyfs(const char *path);
double fs_entropy(const char *dev, const size_t blklen);

/** @} */

#endif  /* _FSUTILS_H */

/*
 *  (C)Copyright 2005-2018, RW Penney
 */
