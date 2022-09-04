/*
 *  Declarations for device-mapper utilities for cryptmount
 *  (C)Copyright 2005-2022, RW Penney
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

#ifndef _DMUTILS_H
#define _DMUTILS_H

#include "config.h"

#include <libdevmapper.h>

/*! \addtogroup dev_mapper
 *  @{ */


struct dm_task *devmap_prepare(int type, const char *devname);
int devmap_path(char **buff, const char *ident);
int devmap_create(const char *ident, uint64_t blk0, uint64_t blklen,
                const char *tgttype, const char *params);
int devmap_dependencies(const char *ident, unsigned *count, dev_t **devids);
int devmap_remove(const char *ident);

int is_configured(const char *ident, struct dm_info *dminfo);
int udev_settle();

/**  @} */

#endif  /* _DMUTILS_H */

/*
 *  (C)Copyright 2005-2022, RW Penney
 */
