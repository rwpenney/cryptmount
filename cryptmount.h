/*
 *  General declarations for cryptmount
 *  (C)Copyright 2005-2023, RW Penney
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


#ifndef _CRYPTMOUNT_H
#define _CRYPTMOUNT_H

#include "config.h"

#include <sys/types.h>

#if HAVE_INTTYPES_H
#  include <inttypes.h>
#else
#  if HAVE_STDINT_H
#    include <stdint.h>
#  else
     typedef unsigned char          uint8_t;
     typedef long                   int32_t;
     typedef unsigned long          uint32_t;
     typedef long long              int64_t;
     typedef unsigned long long     uint64_t;
#  endif
#  define PRId64 "lld"
#  define SCNi64 "lli"
#endif

#ifdef HAVE_GETTEXT
#  include <libintl.h>
#  include <locale.h>
#  define _(String) gettext(String)
#  define gettext_noop(String) String
#  define N_(String) gettext_noop(String)
#else
#  define _(String) (String)
#  define N_(String) String
#  define textdomain(Domain) /* empty */
#  define bindtextdomain(Package, Directory) /* empty */
#endif

extern uid_t cm_initial_uid;

enum    /*! Exit-codes */
{
    EXIT_OK =       0,
    EXIT_BADOPT =   1,
    EXIT_BADTGT =   2,
    EXIT_BADEXEC =  3,
    EXIT_PRIV =     100,
    EXIT_INSECURE = 101
};


enum    /*! Error flags */
{
    ERR_NOERROR =       0,

    WRN_UNCONFIG,               /*!< Filesystem is already unmounted */
    WRN_NOPASSWD,
    WRN_LOWENTROPY,
    WRN_MOUNTED,                /*!< Filesystem is already mounted */

    ERR_threshold = 0x10,       /*!< Dividing-line between warnings & errors */

    ERR_NOTSUPPORTED,
    ERR_BADKEYFORMAT,
    ERR_BADALGORITHM,
    ERR_BADFILE,                /*!< Serious problem with accessing file */
    ERR_BADDECRYPT,             /*!< Failure to extract cipher key from file */
    ERR_BADENCRYPT,
    ERR_MEMSPACE,
    ERR_DMSETUP,
    ERR_BADDEVICE,
    ERR_BADIOCTL,
    ERR_BADSUID,
    ERR_BADPRIV,
    ERR_BADMOUNT,
    ERR_BADFSCK,
    ERR_BADSWAP,
    ERR_INSECURE,
    ERR_BADPASSWD,
    ERR_BADPARAM,
    ERR_BADMUTEX,
    ERR_ABORT
};


enum    /*! Target configuration switches */
{
    FLG_USER =          0x0001,
    FLG_FSCK =          0x0002,
    FLG_MKSWAP =        0x0004,
    FLG_TRIM =          0x0008,   /*!< trim/allow-discards on SSD writes */

    FLG_BOOT_MASK =     0xf000,
    FLG_BOOT_MOUNT =    0x1000,
    FLG_BOOT_SWAP =     0x2000,
    FLG_BOOT_PREP =     0x3000,

    FLG_DEFAULTS =  FLG_USER | FLG_FSCK
};


/*! @brief Information about the access key for an encrypted filesystem
 *
 *  Depending on the choice of key-manager, this will either describe
 *  a separate key-file, or a header within the encrypted fileystem itself.
 *
 *  \see keymanager_t, tgtdefn_t
 */
typedef struct keyinfo
{
    const char *format;     /*!< Type of key file, e.g. 'raw', 'libgcrypt' */
    char *filename;
    char *digestalg;
    char *cipheralg;
    long maxlen;            /*!< Maximum number of bytes to read from keyfile */
    unsigned retries;       /*!< Limit on password-entry attempts */
} keyinfo_t;


/*! @brief Description of an available encrypted filesystem or device.
 *
 *  This is typically extracted from a configuration file, containing
 *  details of its name, underlying device, encryption type etc.
 *  This structure can be used to form a linked-list of
 *  cryptmount filesystem-targets.
 *
 *  \see parse_config().
 */
typedef struct tgtdefn
{
    const char *ident;      /*!< Unique identifying name */
    unsigned flags;         /*!< Configuration switches */

    char *dev;              /*!< Device node or raw file */
    int64_t start, length;  /*!< Starting sector + num of sectors (or 0, -1) */
    char *dir;              /*!< Mount-point */
    char *fstype;           /*!< Filesystem type */
    char *mountoptions;     /*!< Options passed to 'mount' command */
    char *fsckoptions;      /*!< Options passed to 'fsck' command */
    char *loopdev;          /*!< Loopback device to wrap around raw file */
    char *supath;           /*!< PATH to setup for commands run as root */

    char *cipher;           /*!< Cipher used on filesystem */
    int64_t ivoffset;       /*!< Cipher initialization-vector offset */

    keyinfo_t key;          /*!< Location/format of key */

    struct tgtdefn *nx;     /*!< Form into linked list */
} tgtdefn_t;

#endif  /* _CRYPTMOUNT_H */

/*
 *  (C)Copyright 2005-2023, RW Penney
 */
