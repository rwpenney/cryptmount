/*
 *  Declarations for config-table & mount-table utilities for cryptmount
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

#ifndef _TABLES_H
#define _TABLES_H

/*! \addtogroup cmtab_utils
 *  @{ */

extern const char *cm_status_filename;

struct tgtdefn;

/*!
 *  Record for persistent storage of target status.
 *
 *  This is used to populate entries in /run/cryptmount.status
 *  where each target that is either mounted or active as a swap device
 *  is listed together with the user-id of its owner.
 */
typedef struct tgtstat
{
    char *ident;            /*!< Unique identifying name of target */
    unsigned long uid;      /*!< User-ID responsible for mounting filesystem */

    struct tgtstat *nx;     /*!< Form into linked list */
} tgtstat_t;


void init_env_dictionary();
void clear_env_dictionary();
struct tgtdefn *alloc_tgtdefn(const struct tgtdefn *prototype);
const struct tgtdefn *get_tgtdefn(const struct tgtdefn *head,
                                const char *ident);
struct tgtdefn *clone_tgtdefn(const struct tgtdefn *orig);
void free_tgtdefn(struct tgtdefn *tgt);

struct tgtdefn *parse_config(const char *cfgname);
struct tgtdefn *parse_config_fd(int fd);
void free_config(struct tgtdefn **head);

tgtstat_t *alloc_tgtstatus(const struct tgtdefn *tgt);
tgtstat_t *get_tgtstatus(const struct tgtdefn *tgt);
tgtstat_t *get_all_tgtstatus();
int put_tgtstatus(const struct tgtdefn *tgt, const tgtstat_t *tstat);
void free_tgtstatus(tgtstat_t *tstat);
int is_cmstatus_intact();

/** @} */

#endif  /* _TABLES_H */

/*
 *  (C)Copyright 2005-2018, RW Penney
 */
