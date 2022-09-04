/*
 *  Declarations for loopback-device utilities for cryptmount
 *  (C)Copyright 2005-2021, RW Penney
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

#ifndef _LOOPUTILS_H
#define _LOOPUTILS_H

#include <stdlib.h>
#include <sys/types.h>

/*! \addtogroup loop_utils
 *  @{ */

int loop_findfree(char *buff, size_t buffsz);
int loop_setup(const char *dev, const char *file, int flags);
int loop_ident(unsigned maj, unsigned min, char *buff, size_t buffsz);
int loop_destroy(const char *dev);
int loop_dellist(unsigned devcnt, const dev_t *devids);

int blockify_file(const char *filename, int fmode, const char *prefdev,
                const char **devname, int *isloop);
int unblockify_file(const char **devname, int isloop);

/**  @} */

#endif  /* _LOOPUTILS_H */

/*
 *  (C)Copyright 2005-2021, RW Penney
 */
