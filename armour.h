/*
 *  Declarations for encryption/security mechanisms for cryptmount
 *  (C)Copyright 2005-2025, RW Penney
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

#ifndef _ARMOUR_H
#define _ARMOUR_H

#include "cryptmount.h"

/*! \addtogroup keymgrs
 *  @{ */


struct keyinfo;
struct bound_tgtdefn;
struct cm_testinfo;
struct km_pw_context;
struct km_overrides;

/*! @brief Abstract interface to manager of filesystem access keys.
 *
 *  This structure consists of a set of function points,
 *  defining mechanisms through which filesystem keys
 *  can be read from, or written to, a secure key container.
 *  Different key-managers may use different approaches
 *  to key security, e.g. using libgcrypt for a stand-alone key,
 *  or LUKS for key storage within a filesystem header.
 */
typedef struct keymanager {
    const char *ident;

    unsigned initialized;

    /*! Initialize any underlying cryptographic libraries */
    int (*init_algs)(void);

    /*! Close-down any underlying cryptographic libraries */
    int (*free_algs)(void);

    /*! Attempt to attach to particular target,
        installing default fields in target-definition */
    int (*bind)(struct bound_tgtdefn *boundtgt, FILE *fp_key);

    /*! Get properties, e.g. whether a password is needed for access: */
    unsigned (*get_properties)(const struct bound_tgtdefn *boundtgt);

    /*! Extract encrypted key from file: */
    int (*get_key)(struct bound_tgtdefn *boundtgt,
                    const struct km_pw_context *pw_ctxt,
                    uint8_t **key, int *keylen, FILE *fp_key);

    /*! Write encrypted key into file: */
    int (*put_key)(struct bound_tgtdefn *boundtgt,
                    const struct km_pw_context *pw_ctxt,
                    const uint8_t *key, const int keylen, FILE *fp_key);

    /*! Linked-list scaffolding: */
    struct keymanager *next;

#ifdef TESTING
    void (*install_testctxt)(struct cm_testinfo *context);
    int (*run_tests)(void);
    unsigned test_flags;
#endif
} keymanager_t;

/*! Key-manager initialization status flags: */
enum {
    KM_INIT_ALGS =          0x001,
    KM_TESTED =             0x800
};

/*! Key-manager key-properties flags: */
enum {
    KM_PROP_HASPASSWD =     0x001,      /*!< Password needed to access key */
    KM_PROP_NEEDSKEYFILE =  0x002,      /*!< Key-file must be present */
    KM_PROP_FIXEDLOC =      0x004,      /*!< Key-file cannot be renamed */
    KM_PROP_FORMATTED =     0x008       /*!< Key-file has been formatted */
};


/*! Association of user-defined target-data & particular key-manager: */
typedef struct bound_tgtdefn
{
    tgtdefn_t *tgt;

    const keymanager_t *keymgr;
    void *km_data;

    /*! Block-device sector size, typically multiple of 512 <=4096, or 0 if unknown */
    unsigned sectorsize;
} bound_tgtdefn_t;


const char **get_keymgr_list(void);
int free_keymanagers(void);


bound_tgtdefn_t *bind_tgtdefn(const tgtdefn_t *tgt);
void free_boundtgt(bound_tgtdefn_t *boundtgt);


unsigned cm_get_keyproperties(const bound_tgtdefn_t *boundtgt);
int cm_get_key(bound_tgtdefn_t *boundtgt,
            const struct km_pw_context *pw_ctxt,
            uint8_t **key, int *keylen);
int cm_put_key(bound_tgtdefn_t *boundtgt,
            const struct km_pw_context *pw_ctxt,
            const uint8_t *key, const int keylen, FILE *fp_key);
size_t mk_key_string(const uint8_t *key, const size_t keylen,
            char *buff);

int sycheck_directory(const char *dirname);
int sycheck_cmtab(const char *cmtab);
int sycheck_target(const struct tgtdefn *ent);

int cm_mutex_lock(void);
int cm_mutex_unlock(void);


/**  @} */

#endif  /* _ARMOUR_H */

/*
 *  (C)Copyright 2005-2025, RW Penney
 */
