/*
 *  cryptmount - a utility for user-level mounting of encrypted filesystems
 *  (C)Copyright 2005-2024, RW Penney
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

#include "config.h"

#include <ctype.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef HAVE_SYSLOG
#  include <syslog.h>
#endif


#include "armour.h"
#include "cryptmount.h"
#include "delegates.h"
#include "dmutils.h"
#include "fsutils.h"
#include "looputils.h"
#include "tables.h"
#include "utils.h"
#if WITH_CSWAP
#  include <sys/swap.h>
#endif
#ifdef TESTING
#  include "cmtesting.h"
#endif


/** Record of getuid() output at start of process */
uid_t cm_initial_uid = ~0u;


/**
 *  An element within a linked-list of filesystem-targets,
 *  typically supplied from command-line.
 */
typedef struct targelt
{
    const tgtdefn_t *tgt;

    struct targelt *nx;
} targelt_t;


/** Identifiers of top-level operating mode, and configuration switches
 *
 *  The lower-order bits specify one of a sequence of mutuall-exclusive
 *  operating modes. The higher-order bits consist of a few control flags,
 *  some of which may be set implicitly according the the operating mode.
 */
typedef enum {
    M_UNSET, M_HELP,
    M_PREPARE, M_RELEASE,
    M_MOUNT, M_UNMOUNT,
    M_SWAPON, M_SWAPOFF,
    M_LIST, M_KEYMGRS, M_STATUS,
    M_PASSWORD, M_KEYGEN, M_KEYREU,
    M_SYSBOOT, M_SYSQUIT,
    M_SAFETYNET, M_VERSION,
    M_SELFTEST,

    M_MODE_MASK = 0x00ff,

    F_NEEDS_TGT =   0x0100, /*!< command requires a filesystem target */
    F_ALL_TARGETS = 0x0200, /*!< command will be applied to all known targets */
    F_NOWARN_ALL =  0x0400, /*!< suppress warnings with '--all' targets */
    F_VERIFY_PW =   0x0800  /*!< encryption password should be double-checked */
} cmmode_t;


static int64_t getblk512count(const char *device, int *blklen);
static int execute_list(cmmode_t mode, const tgtdefn_t *tgttable,
                const km_pw_context_t *pw_ctxt,
                const char *params, const targelt_t *eltlist);
static int do_list(const targelt_t *eltlist);
static int do_status(const targelt_t *eltlist);
static int do_keymgrlist();
static int do_sysboot_updown(int booting, const tgtdefn_t *tgttable,
                const km_pw_context_t *pw_ctxt);
static int do_devsetup(const km_pw_context_t *pw_ctxt,
                bound_tgtdefn_t *boundtgt, char **mntdev);
static int do_devshutdown(const bound_tgtdefn_t *boundtgt);
static int do_mount(const km_pw_context_t *pw_ctxt, bound_tgtdefn_t *boundtgt);
static int do_unmount(const bound_tgtdefn_t *boundtgt);
static int do_swapon(const km_pw_context_t *pw_ctxt, bound_tgtdefn_t *boundtgt);
static int do_swapoff(const bound_tgtdefn_t *boundtgt);
static int do_passwd(const km_pw_context_t *pw_ctxt, bound_tgtdefn_t *boundtgt);
static int do_keygen(const km_pw_context_t *pw_ctxt, bound_tgtdefn_t *boundtgt,
                const char *params, int reuse, const tgtdefn_t *tgttable);
static int do_safetynet();


static const char *USAGE_STRING = N_("\
usage: cryptmount [OPTION [target ...]]\n\
\n\
  available options are as follows:\n\
\n\
    -h | --help\n\
    -a | --all\n\
    -c | --change-password <target>\n\
    -k | --key-managers\n\
    -l | --list\n\
    -S | --status\n\
    -m | --mount <target>\n\
    -u | --unmount <target>\n\
    --generate-key <key-size> <target>\n\
    --reuse-key <src-target> <dst-target>\n\
    --prepare <target>\n\
    --release <target>\n\
    --config-fd <num>\n\
    --passwd-fd <num>\n\
    --swapon <target>\n\
    --swapoff <target>\n\
    --version\n\
\n\
  please report bugs to <cryptmount@rwpenney.uk>\n\
");


#ifdef TESTING

cm_testinfo_t test_context;
cm_testinfo_t *test_ctxtptr = &test_context;

int fs_test_blkgetsz()
    /** Check that 32bit & 64bit device size calculations agree */
{
#ifdef BLKGETSIZE64
    int fd, n_open, seclen;
    long len;
    uint64_t len64;
    const char **dev;
    const char *devices[] = {
        "/dev/hda", "/dev/hda1", "/dev/hda2", "/dev/hda3",
        "/dev/nvme0n1", "/dev/nvme0n2", "/dev/nvme1n1", "/dev/nvme1n2",
        "/dev/sda", "/dev/sda1", "/dev/sda2", "/dev/sda3",
        "/dev/sdb", "/dev/sdb1", "/dev/sdb2", "/dev/sdb3",
        "/dev/vda", "/dev/vda1", "/dev/xvda", "/dev/xvda1",
        "/dev/sr0", "/dev/sr1",
        NULL };
#endif

    CM_TEST_START("BLKGETSIZE ioctl calls");
#ifndef BLKGETSIZE64
    /* Assume that there is no ambiguity with BLKGETSIZE */
    CM_TEST_PASS();
#else
    dev = devices;
    n_open = 0;
    while (*dev != NULL) {
        fd = open(*dev, O_RDONLY);
        if (fd >= 0) {
            ++n_open;
            if (ioctl(fd, BLKSSZGET, &seclen) != 0
              || ioctl(fd, BLKGETSIZE, &len) != 0
              || ioctl(fd, BLKGETSIZE64, &len64) != 0) {
                CM_TEST_FAIL();
            }
            close(fd);
            if (len64 < (1<<31)) {
                CM_ASSERT_EQUAL(len64, ((int64_t)len * (int64_t)512));
            }
        }
#if 0
        if (fd >= 0) fprintf(stderr, "%s: %d  %ld  %lld\n", *dev, seclen, len * 512, len64);
#endif
        ++dev;
    }

    if (n_open > 0) {
        CM_TEST_OK();
    } else {
        CM_TEST_ABORT();
    }
#endif  /* BLKGETSIZE64 */
}

#endif  /* TESTING */


static int64_t getblk512count(const char *device, int *blklen)
    /** Find size of raw device in blocks of size 512-bytes */
{   int64_t count = -1;
    int fd;
#ifndef BLKGETSIZE64
    long len;
#endif

    *blklen = 512;
    fd = open(device, O_RDONLY);
    if (fd < 0) return (int64_t)-1;

#ifdef BLKGETSIZE64
    if (ioctl(fd, BLKGETSIZE64, &count) == 0
        && ioctl(fd, BLKSSZGET, blklen) == 0) {
        count /= (int64_t)512;
    } else {
        count = -1;
    }
#else
    if (ioctl(fd, BLKGETSIZE, &len) == 0) {
        /*  This directly gives the number of 512-byte blocks */
        count = (int64_t)len;
    }
#endif

    (void)close(fd);
    return count;
}


/*! @brief Print list of available filing-system targets to stdout
 *
 *  This provides the back-end functionality for
 *  the '--list' command-line option.
 */
static int do_list(const targelt_t *eltlist)
{   const targelt_t *elt;

    for (elt=eltlist; elt!=NULL; elt=elt->nx) {
        const tgtdefn_t *tgt = elt->tgt;

        /* TRANSLATORS: this string is marked as 'no-c-format' because
           some localizations may require the mount-point and filesystem type
           to be printed in a different order, but the untranslated string needs
           to remain an ordinary string that can be printed without gettext. */
        /* xgettext:no-c-format */
        printf(_("%-16s  [to mount on \"%s\" as \"%s\"]\n"),
                tgt->ident, tgt->dir, tgt->fstype);
    }

    return ERR_NOERROR;
}


/*! @brief Print mounting status of set of targets to stdout
 *
 *  This provides the back-end functionality for
 *  the '--status' command-line option.
 */
static int do_status(const targelt_t *eltlist)
{   const targelt_t *elt;
    tgtstat_t *tgtstats = NULL, *ts;

    tgtstats = get_all_tgtstatus();

    for (elt=eltlist; elt!=NULL; elt=elt->nx) {
        const tgtdefn_t *tgt = elt->tgt;

        for (ts=tgtstats; ts!=NULL; ts=ts->nx) {
          if (strcmp(ts->ident, tgt->ident) == 0) break;
        }

        printf("%-16s  %s\n",
               tgt->ident, (ts != NULL ? "mounted" : "not_mounted"));
    }

    free_tgtstatus(tgtstats);

    return ERR_NOERROR;
}


/*! @brief Print a list of all available key managers to stdout.
 *
 *  This provides the back-end functionality for
 *  the '--key-managers' command-line option.
 */
static int do_keymgrlist()
{   const char **keymgrs = get_keymgr_list();
    int i = 0;

    while (keymgrs[i] != NULL) {
        printf("%s", keymgrs[i]);

        ++i;
        if (keymgrs[i] != NULL) {
            printf(", ");
        } else {
            printf("\n");
        }
    }

    free((void*)keymgrs);
    return ERR_NOERROR;
}


/*! @brief Setup all devices which have a bootaction option specified
 *
 *  This provides the back-end functionality for
 *  the '--system-boot' and '--system-shutdown' command-line options.
 *
 *  \see do_mount(), do_swapon(), do_devsetup().
 */
static int do_sysboot_updown(int booting, const tgtdefn_t *tgttable,
                             const km_pw_context_t *pw_ctxt)
{   const tgtdefn_t *tgt;
    bound_tgtdefn_t *boundtgt = NULL;
    int eflag = ERR_NOERROR;

    for (tgt=tgttable; tgt!=NULL && eflag<ERR_threshold; tgt=tgt->nx) {
        const unsigned boot_mode = (tgt->flags & FLG_BOOT_MASK);

        if (boot_mode == 0) continue;
        boundtgt = bind_tgtdefn(tgt);
        if (boundtgt == NULL) continue;

        switch (boot_mode) {
            case FLG_BOOT_MOUNT:
                eflag = (booting ? do_mount(pw_ctxt, boundtgt)
                                 : do_unmount(boundtgt));
                break;
            case FLG_BOOT_SWAP:
                eflag = (booting ? do_swapon(pw_ctxt, boundtgt)
                                 : do_swapoff(boundtgt));
                break;
            case FLG_BOOT_PREP:
                eflag = (booting ? do_devsetup(pw_ctxt, boundtgt, NULL)
                                 : do_devshutdown(boundtgt));
                break;
            default:
                break;
        }

        free_boundtgt(boundtgt);
    }

    return eflag;
}


/*! @brief Setup all devices needed to access encrypted target
 *
 *  This will wrap any file-based targets within a loopback device,
 *  and then setup the device-mapper to provide encryption/decryption
 *  of the target block device after obtaining the access password
 *  from the user.
 *
 *  This provides the back-end functionality for
 *  the '--prepare' command-line option.
 *
 *  \see cm_get_key(), blockify_file(), devmap_create(), do_devshutdown().
 */
static int do_devsetup(const km_pw_context_t *pw_ctxt,
                       bound_tgtdefn_t *boundtgt, char **mntdev)
{   enum { BUFFMIN=1024 };
    uint8_t *key = NULL;
    int buffpos, blklen, readonly, isloop = 0, killloop = 0,
        keylen = 0, eflag = ERR_NOERROR;
    int64_t devlen = 0, fslen = 0;
    size_t dpsize;
    char *dmparams = NULL;
    const char *tgtdev = NULL;
    const tgtdefn_t *tgt = NULL;

    /* Get crypto-key for filing system: */
    eflag = cm_get_key(boundtgt, pw_ctxt, &key, &keylen);
    if (eflag != ERR_NOERROR) {
        fprintf(stderr, _("Failed to extract cipher key\n"));
        goto bail_out;
    }
    tgt = boundtgt->tgt;

    readonly = is_readonlyfs(tgt->dev);
    eflag = blockify_file(tgt->dev, (readonly ? O_RDONLY : O_RDWR),
                          tgt->loopdev, &tgtdev, &isloop);
    if (eflag != ERR_NOERROR) {
        fprintf(stderr, _("Cannot open device \"%s\" for target \"%s\"\n"),
                (tgt->dev != NULL ? tgt->dev : "(NULL)"), tgt->ident);
        goto bail_out;
    }

    /* Get size in blocks of target device: */
    devlen = getblk512count(tgtdev, &blklen);
    if (devlen < 0) {
        fprintf(stderr, _("Failed to get size of \"%s\"\n"), tgtdev);
        eflag = ERR_BADIOCTL;
        goto bail_out;
    }
    if (tgt->length < 0 || (tgt->start + tgt->length) > devlen) {
        fslen = devlen - tgt->start;
    } else {
        fslen = tgt->length;
    }
    if (tgt->start < 0 || fslen <= 0) {
        fprintf(stderr,_("Bad device-mapper start/length"));
        fprintf(stderr, " (%" PRId64 ",%" PRId64 ")\n",
                tgt->start, tgt->length);
        eflag = ERR_BADDEVICE;
        goto bail_out;
    }

    /* Setup device-mapper crypt table (CIPHER KEY IV_OFFSET DEV START): */
    dpsize = 2 * keylen + BUFFMIN;
    dmparams = (char*)sec_realloc(dmparams, dpsize);
    buffpos = snprintf(dmparams, dpsize, "%s ",
                        (tgt->cipher != NULL ?  tgt->cipher
                                             : CM_DEFAULT_CIPHER));
    buffpos += mk_key_string(key, (size_t)keylen, dmparams + buffpos);
    buffpos += snprintf(dmparams + buffpos, (dpsize - buffpos),
                          " %" PRId64 " %s %" PRId64,
                          tgt->ivoffset, tgtdev, tgt->start);
    if ((tgt->flags & FLG_TRIM) != 0) {
      buffpos += snprintf(dmparams + buffpos, (dpsize - buffpos),
                            " 1 allow_discards");
    }

    /* Setup device-mapper target: */
    eflag = devmap_create(tgt->ident,
            (uint64_t)0, (uint64_t)fslen, "crypt", dmparams);
    if (eflag != ERR_NOERROR) {
        fprintf(stderr,
            _("Device-mapper target-creation failed for \"%s\"\n"),
            tgt->ident);
        killloop = 1;
        goto bail_out;
    }
    if (mntdev != NULL) {
        devmap_path(mntdev, tgt->ident);
    }


  bail_out:

    if (killloop) unblockify_file(&tgtdev, isloop);   /* mounting failed? */
    if (tgtdev) free((void*)tgtdev);
    sec_free(dmparams);
    sec_free(key);

    return eflag;
}   /* do_devsetup() */


/*! @brief Remove all devices attached to encrypted target
 *
 *  This will close-down device-mapper and loopback devices
 *  configured by do_setup().
 *
 *  This provides the back-end functionality for
 *  the '--release' command-line option.
 *
 *  \see do_devsetup(), devmap_remove(), loop_dellist().
 */
int do_devshutdown(const bound_tgtdefn_t *boundtgt)
{   const tgtdefn_t *tgt = boundtgt->tgt;
    struct stat sbuff;
    unsigned devcnt=0;
    dev_t *devids=NULL;
    int eflag=ERR_NOERROR;

    /* Check if filing system has been configured at all: */
    if (!is_configured(tgt->ident, NULL)) {
        fprintf(stderr, _("Target \"%s\" does not appear to be configured\n"),
                        tgt->ident);
        eflag = WRN_UNCONFIG;
        goto bail_out;
    }

    /* Find any underlying (e.g. loopback) devices for device-mapper target: */
    udev_settle();
    (void)devmap_dependencies(tgt->ident, &devcnt, &devids);
#ifdef DEBUG
    fprintf(stderr, "Shutting down %s [%u dependencies]\n",
            tgt->ident, devcnt);
#endif

    if (stat(tgt->dev, &sbuff) != 0) {
        fprintf(stderr, _("Cannot stat \"%s\"\n"), tgt->dev);
        eflag = ERR_BADDEVICE;
        goto bail_out;
    }

    /* Remove demice-mapper target: */
    eflag = devmap_remove(tgt->ident);
    if (eflag != ERR_NOERROR) {
        fprintf(stderr, _("Failed to remove device-mapper target \"%s\"\n"),
            tgt->ident);
        goto bail_out;
    }
    udev_settle();

    /* Tidy-up any associated loopback devices: */
    if (S_ISREG(sbuff.st_mode) && devids != NULL) {
        (void)loop_dellist(devcnt, devids);
    }

  bail_out:

    if (devids != NULL) free((void*)devids);

    return eflag;
}


/*! @brief Mount an encrypted filesystem
 *
 *  This provides the back-end functionality for
 *  the '--mount' command-line option.
 *
 *  \see do_unmount(), do_devsetup(), fs_mount().
 */
static int do_mount(const km_pw_context_t *pw_ctxt, bound_tgtdefn_t *boundtgt)
{   const tgtdefn_t *tgt = NULL;
    int freedev = 0, eflag = ERR_NOERROR;
    char *mntdev = NULL;
    tgtstat_t *tstat;

    if (is_mounted(boundtgt->tgt)) {
        fprintf(stderr, _("Target \"%s\" is already mounted\n"),
                boundtgt->tgt->ident);
        eflag = WRN_MOUNTED;
        goto bail_out;
    }

    eflag = do_devsetup(pw_ctxt, boundtgt, &mntdev);
    if (eflag != ERR_NOERROR) goto bail_out;
    tgt = boundtgt->tgt;

#if WITH_FSCK
    if ((tgt->flags & FLG_FSCK) != 0) {
        const int fsck_flag = fs_check(mntdev, tgt);
        if (fsck_flag != ERR_NOERROR) {
            freedev = 1; eflag = fsck_flag;
            goto bail_out;
        }
    }
#endif

    if (fs_mount(mntdev, tgt) != ERR_NOERROR) {
        freedev = 1; eflag = ERR_BADMOUNT;
        goto bail_out;
    }

    tstat = alloc_tgtstatus(tgt);
    tstat->uid = (unsigned long)cm_initial_uid;
    put_tgtstatus(tgt, tstat);
    free_tgtstatus(tstat);

  bail_out:

    if (freedev) {
        /* Tidy-up debris if mount failed */
        udev_settle();
        do_devshutdown(boundtgt);
    }
    if (mntdev != NULL) free((void*)mntdev);

    return eflag;
}


/*! @brief Unmount an encrypted filesystem
 *
 *  This provides the back-end functionality for
 *  the '--unmount' command-line option.
 *
 *  \see do_mount(), do_devshutdown(), fs_unmount().
 */
static int do_unmount(const bound_tgtdefn_t *boundtgt)
{   const tgtdefn_t *tgt = boundtgt->tgt;
    int eflag=ERR_NOERROR;
    struct passwd *pwent;
    char *mntdev = NULL;
    tgtstat_t *tstat = NULL;

    /* Check if filing system has been configured at all: */
    if (!is_mounted(tgt) || (tstat = get_tgtstatus(tgt)) == NULL) {
        fprintf(stderr, _("Target \"%s\" does not appear to be mounted\n"),
                        tgt->ident);
        eflag = WRN_UNCONFIG;
        goto bail_out;
    }

    /* Check if filing system has been mounted & locked by another user: */
    if (getuid() != 0 && (uid_t)tstat->uid != cm_initial_uid) {
        pwent = getpwuid((uid_t)tstat->uid);
        if (pwent != NULL) {
            fprintf(stderr, _("Only \"%s\" can unmount \"%s\"\n"),
                pwent->pw_name, tgt->ident);
        } else {
            /*  TRANSLATORS: the following expands to include
                the *numerical* user-identity in place of '%lu',
                e.g. giving 'only user-16 can unmount "target"': */
            fprintf(stderr, _("Only user-%lu can unmount \"%s\"\n"),
                tstat->uid, tgt->ident);
        }
        eflag = ERR_BADPRIV;
        goto bail_out;
    }

    /* Unmount filing system: */
    if (fs_unmount(tgt) != ERR_NOERROR) {
        eflag = ERR_BADMOUNT;
        goto bail_out;
    }
    put_tgtstatus(tgt, NULL);

    /* Remove supporting device-mapper target etc */
    if (do_devshutdown(boundtgt) != ERR_NOERROR) {
        eflag = ERR_BADDEVICE;
    }


  bail_out:

    if (mntdev != NULL) free((void*)mntdev);
    if (tstat != NULL) free_tgtstatus(tstat);

    return eflag;
}


/*! @brief Setup an encrypted swap partition
 *
 *  This provides the back-end functionality for
 *  the '--swapon' command-line option.
 *
 *  \see do_swapoff(), do_devsetup(), fs_swapon().
 */
static int do_swapon(const km_pw_context_t *pw_ctxt, bound_tgtdefn_t *boundtgt)
{   const tgtdefn_t *tgt = NULL;
    int freedev = 0, eflag = ERR_NOERROR;
    char *mntdev = NULL;
    tgtstat_t *tstat = NULL;

#if WITH_CSWAP

    if (is_configured(boundtgt->tgt->ident, NULL)) {
        fprintf(stderr, _("Target \"%s\" is already configured\n"),
                        boundtgt->tgt->ident);
        eflag = WRN_MOUNTED;
        goto bail_out;
    }

    eflag = do_devsetup(pw_ctxt, boundtgt, &mntdev);
    if (eflag != ERR_NOERROR) goto bail_out;
    tgt = boundtgt->tgt;

    if (fs_swapon(mntdev, tgt) != ERR_NOERROR) {
        freedev = 1;
        eflag = ERR_BADSWAP;
        goto bail_out;
    }

    tstat = alloc_tgtstatus(tgt);
    tstat->uid = (unsigned long)cm_initial_uid;
    put_tgtstatus(tgt, tstat);
    free_tgtstatus(tstat);

#else   /* !WITH_CSWAP */

    fprintf(stderr, _("Crypto-swap is not supported by this installation of cryptmount\n"));
    eflag = ERR_BADSWAP;

#endif

  bail_out:

    if (freedev) {
        /* Tidy-up debris if swapon failed */
        udev_settle();
        do_devshutdown(boundtgt);
    }

    if (mntdev != NULL) free((void*)mntdev);

    return eflag;
}


/*! @brief Close down an encrypted swap partition
 *
 *  This provides the back-end functionality for
 *  the '--swapoff' command-line option.
 *
 *  \see do_swapon(), do_devshutdown(), fs_swapoff().
 */
static int do_swapoff(const bound_tgtdefn_t *boundtgt)
{   const tgtdefn_t *tgt = boundtgt->tgt;
    int eflag=ERR_NOERROR;
    char *mntdev=NULL;
    tgtstat_t *tstat;

#if WITH_CSWAP

    /* Check if device has been configured at all: */
    if ((tstat = get_tgtstatus(tgt)) == NULL) {
        fprintf(stderr, _("Target \"%s\" does not appear to be configured\n"),
                        tgt->ident);
        eflag = WRN_UNCONFIG;
        goto bail_out;
    }

    /* Remove swap-partition: */
    if (fs_swapoff(tgt) != ERR_NOERROR) {
        eflag = ERR_BADSWAP;
        goto bail_out;
    }
    put_tgtstatus(tgt, NULL);

    /* Remove supporting device-mapper target etc */
    if (do_devshutdown(boundtgt) != ERR_NOERROR) {
        eflag = ERR_BADDEVICE;
    }

#else   /* !WITH_CSWAP */

    fprintf(stderr, _("Crypto-swap is not supported by this installation of cryptmount\n"));
    eflag = ERR_BADSWAP;

#endif

  bail_out:

    if (mntdev != NULL) free((void*)mntdev);

    return eflag;
}


/*! @brief Change access password on particular target
 *
 *  This provides the back-end functionality for
 *  the '--change-password' command-line option.
 *
 *  \see cm_get_key(), cm_put_key().
 */
static int do_passwd(const km_pw_context_t *pw_ctxt, bound_tgtdefn_t *boundtgt)
{   tgtdefn_t *tgt = boundtgt->tgt;
    uint8_t *key = NULL;
    unsigned keyprops;
    int keylen = 0, eflag = ERR_NOERROR;
    char *newfname = NULL, *oldfname = NULL;
    struct stat sbuff;
    size_t sz;
    FILE *fp = NULL;

    keyprops = cm_get_keyproperties(boundtgt);
    if ((keyprops & KM_PROP_HASPASSWD) == 0) {
        fprintf(stderr, _("Key-file for \"%s\" isn't password-protected\n"),
                tgt->ident);
        eflag = WRN_NOPASSWD;
        goto bail_out;
    }

    /* Attempt to read current key: */
    eflag = cm_get_key(boundtgt, pw_ctxt, &key, &keylen);
    if (eflag != ERR_NOERROR) goto bail_out;

    /* Setup location to re-encrypt key: */
    if (tgt->key.filename != NULL) {
        const char *outfname=NULL;
        if ((keyprops & KM_PROP_FIXEDLOC) == 0) {
            sz = strlen(tgt->key.filename) + 16;
            oldfname = (char*)malloc(2 * sz);
            newfname = oldfname + sz;
            snprintf(oldfname, sz, "%s-old", tgt->key.filename);
            snprintf(newfname, sz, "%s-new", tgt->key.filename);
            fp = fopen(newfname, "wb");
            outfname = newfname;
        } else {
            fp = fopen(tgt->key.filename, "r+b");
            outfname = tgt->key.filename;
        }
        if (fp == NULL) {
            fprintf(stderr, _("Cannot open \"%s\" for writing\n"), outfname);
            eflag = ERR_BADFILE;
            goto bail_out;
        }
    }
    eflag = cm_put_key(boundtgt, pw_ctxt, key, keylen, fp);
    if (fclose(fp) != 0) eflag = ERR_BADFILE;
    if (eflag != ERR_NOERROR) goto bail_out;

    /* Replace old key-container with new key-container: */
    if (oldfname != NULL && newfname != NULL) {
        if (stat(tgt->key.filename, &sbuff) != 0
          || rename(tgt->key.filename, oldfname) != 0
          || chown(oldfname, 0, 0) != 0
          || chmod(oldfname, S_IRUSR | S_IWUSR) != 0) {
            fprintf(stderr, _("Retiring old key (%s -> %s) failed\n"),
                    tgt->key.filename, oldfname);
            goto bail_out;
        }

        if (rename(newfname, tgt->key.filename) != 0
          || chown(tgt->key.filename, sbuff.st_uid, sbuff.st_gid) != 0
          || chmod(tgt->key.filename, sbuff.st_mode) != 0) {
            fprintf(stderr, _("Installing new key (%s -> %s) failed\n"),
                    newfname, tgt->key.filename);
            goto bail_out;
        }

        newfname = NULL;

        fprintf(stderr, _("Backup of previous key is in \"%s\"\n"), oldfname);
    }

  bail_out:

    if (newfname != NULL) {
        unlink(newfname);
    }
    if (oldfname != NULL) free((void*)oldfname);

    return eflag;
}


/*! @brief Create new filesystem crypto-key
 *
 *  This provides the back-end functionality for
 *  the '--generate-key' command-line option.
 *
 *  \see cm_generate_key(), cm_put_key().
 */
static int do_keygen(const km_pw_context_t *pw_ctxt, bound_tgtdefn_t *boundtgt,
                    const char *params, int reuse, const tgtdefn_t *tgttable)
{   uint8_t *key = NULL;
    unsigned keyprops;
    int keylen = 0, fileexists = 0, eflag = ERR_NOERROR;
    char *newfname = NULL;
    tgtdefn_t *tgt = boundtgt->tgt;
    const tgtdefn_t *parent = NULL;
    bound_tgtdefn_t *boundparent = NULL;
    size_t sz;
    struct stat sbuff;
    FILE *fp = NULL;
    const unsigned mask_fmtfxd = KM_PROP_FIXEDLOC | KM_PROP_FORMATTED;

    if (params != NULL) {
        if (reuse) {
            parent = get_tgtdefn(tgttable, params);
            boundparent = bind_tgtdefn(parent);
            if (parent == NULL || boundparent == NULL) {
                fprintf(stderr, _("Target name \"%s\" is not recognized\n"),
                        params);
                eflag = ERR_BADPARAM;
            }
        } else {
            if (sscanf(params, "%i", &keylen) != 1 || keylen < 1) {
                fprintf(stderr, _("Bad key-length parameter"));
                eflag = ERR_BADPARAM;
            }
        }
    }
    if (params == NULL || eflag != ERR_NOERROR) goto bail_out;

    /* Check if keyfile already exists: */
    keyprops = cm_get_keyproperties(boundtgt);
    fileexists = (tgt->key.filename != NULL
                    && stat(tgt->key.filename, &sbuff) == 0);
    if (fileexists && (keyprops & mask_fmtfxd) != KM_PROP_FIXEDLOC) {
        fprintf(stderr,_("Key-file \"%s\" already exists for target \"%s\"\n"),
            tgt->key.filename, tgt->ident);
        eflag = ERR_BADFILE;
        goto bail_out;
    }

    /* Assemble new key material: */
    if (reuse) {
        eflag = cm_get_key(boundparent, pw_ctxt, &key, &keylen);
    } else {
        fprintf(stderr, _("Generating random key; please be patient...\n"));
        key = (uint8_t*)sec_realloc(NULL, (size_t)keylen);
        eflag = cm_generate_key(key, (size_t)keylen);
        if (eflag != ERR_NOERROR) {
            fprintf(stderr, _("Failed to generate new key\n"));
            goto bail_out;
        }
    }

    /* Setup location for new key: */
    if (tgt->key.filename != NULL) {
        const char *outfname=NULL;
        if ((keyprops & KM_PROP_FIXEDLOC) == 0) {
            sz = strlen(tgt->key.filename) + 16;
            newfname = (char*)malloc(sz);
            snprintf(newfname, sz, "%s-new", tgt->key.filename);
            fp = fopen(newfname, "wb");
            outfname = newfname;
        } else {
            fp = fopen(tgt->key.filename, (fileexists ? "r+b" : "wb"));
            outfname = tgt->key.filename;
        }
        if (fp == NULL) {
            fprintf(stderr, _("Cannot open \"%s\" for writing\n"), outfname);
            eflag = ERR_BADFILE;
            goto bail_out;
        }
    }
    eflag = cm_put_key(boundtgt, pw_ctxt, key, keylen, fp);
    if (fp != NULL && fclose(fp) != 0) eflag = ERR_BADFILE;
    if (eflag != ERR_NOERROR) goto bail_out;

    /* Move new key file into prefered location: */
    if (newfname != NULL) {
        if (rename(newfname, tgt->key.filename) != 0
          || chown(tgt->key.filename, 0, 0) != 0
          || chmod(tgt->key.filename, S_IRUSR | S_IWUSR) != 0) {
            fprintf(stderr, _("Installation of new keyfile \"%s\" failed"),
                    tgt->key.filename);
            eflag = ERR_BADFILE;
        }
        free((void*)newfname);
        newfname = NULL;
    }

  bail_out:

    if (newfname != NULL) {
        unlink(newfname);
        free((void*)newfname);
    }
    if (key != NULL) sec_free((void*)key);
    if (boundparent != NULL) free_boundtgt(boundparent);

    return eflag;
}


/*! @brief Attempt to unmount/shutdown all targets currently mounted.
 *
 *  This will identify all filesystems listed in cryptmount's own
 *  mounting table (typically /run/cryptmount.status), and try
 *  to unmount, or de-configure, any targets that seem still to be in use.
 *
 *  This will generally only be useful during a system shutdown,
 *  to provide a safety mechanism for filesystems that have
 *  not been unmounted normally. Accordingly, this routine
 *  is more aggressive in its approach than do_unmount(), do_swapoff(), etc.
 *
 *  This provides the back-end functionality for
 *  the '--safetynet' command-line option.
 */
static int do_safetynet()
{   tgtstat_t *all_tsts=NULL, *tst;
    char *devname=NULL;
    const char *old_ident=NULL;
    tgtdefn_t *tgt=NULL;
    dev_t *devids=NULL;
    unsigned devcnt=0;
    int mflag;
    struct {
        unsigned targets, unmounted, unswapped, undeviced, unlooped; }
        counts = {
            0, 0, 0, 0, 0 };

    /*  This routine is ugly, but may be the best we can do to prevent
     *  damage to filesystems that should have been properly removed
     *  by other mechanisms (e.g. --unmount, --swapoff) */

    tgt = alloc_tgtdefn(NULL);
    old_ident = tgt->ident;

    /* Get list of all targets in status-file: */
    udev_settle();
    all_tsts = get_all_tgtstatus();

    for (tst=all_tsts; tst!=NULL; tst=tst->nx) {
        ++counts.targets;
        devmap_path(&devname, tst->ident);
        tgt->ident = tst->ident;

#ifdef DLGT_UMOUNT
        /* Attempt to unmount filesystem: */
        switch (fork()) {
            case -1:
                break;
            case 0:
                execl(DLGT_UMOUNT, "umount", devname, NULL);
                break;
            default:
                (void)wait(&mflag);
                break;
        }
        if (mflag == 0) ++counts.unmounted;
#endif  /* DLGT_UMOUNT */
#if WITH_CSWAP
        /* Attempt to remove swap partition: */
        if (swapoff(devname) == 0) ++counts.unswapped;
#endif  /* WITH_CSWAP */

        /* Remove device-mapper device: */
        (void)devmap_dependencies(tst->ident, &devcnt, &devids);
        if (devmap_remove(tst->ident) == ERR_NOERROR) ++counts.undeviced;
        udev_settle();

        /* Free any associated loopback devices: */
        if (devcnt > 0 && loop_dellist(devcnt, devids) == 0) ++counts.unlooped;
        if (devids != NULL) {
            free((void*)devids);
            devids = NULL;
        }

        /* Remove entry in status-file, having done our best to clean-up: */
        (void)put_tgtstatus(tgt, NULL);

        if (devname != NULL) {
            free((void*)devname);
            devname = NULL;
        }
    }

    free_tgtstatus(all_tsts);

    if (!is_cmstatus_intact()) {
      char *statpath = NULL;
      (void)cm_path(&statpath, CM_SYSRUN_PFX, cm_status_filename);
      if (statpath != NULL) {
        fprintf(stderr, "%s has been corrupted - removing\n", statpath);
        unlink(statpath);
        free(statpath);
      }
    }

    tgt->ident = old_ident;
    free_tgtdefn(tgt);

    if (counts.targets != 0) {
        fprintf(stderr, "Safety-net caught %u targets:\n"
                "\t%u unmounted, %u swaps removed\n"
                "\t%u devices removed, %u loopbacks freed\n",
                counts.targets,
                counts.unmounted, counts.unswapped,
                counts.undeviced, counts.unlooped);
    }

    return (counts.targets != counts.undeviced);
}


static void check_priv_opt(const char *opt)
    /** Check if ordinary user is allowed to perform privileged actions */
{
    if (getuid() != 0) {
        fprintf(stderr, _("Only root can use option \"%s\"\n"), opt);
        exit(EXIT_PRIV);
    }

    /* Remove effect of any setuid flags, reverting to real user-id: */
    if (seteuid(getuid()) != 0) exit(EXIT_PRIV);
}


static int check_priv_tgt(const tgtdefn_t *tgt)
    /** Check if ordinary user is allowed to perform privileged actions */
{
    if ((tgt->flags & FLG_USER) == 0 && cm_initial_uid != 0) {
        fprintf(stderr, _("Only root can configure \"%s\"\n"), tgt->ident);
        return ERR_BADPRIV;
    }

    return ERR_NOERROR;
}


/*! @brief Apply top-level mode-dependent operation to list of targets
 *
 *  This will mount/unmount/swapon/swapoff the give set of encrypted
 *  filesystems, according to an application-level choice of operating mode.
 *
 *  \see do_mount(), do_swapon(), do_list(), do_safetynet(), parse_options().
 */
static int execute_list(cmmode_t mode, const tgtdefn_t *tgttable,
                const km_pw_context_t *pw_ctxt,
                const char *params, const targelt_t *eltlist)
{   const targelt_t *elt = NULL;
    bound_tgtdefn_t *boundtgt = NULL;
    int ignore_eltlist = 1, prio = 0, eflag = ERR_NOERROR;
    struct passwd *pwent = NULL;
    const char *username = NULL, *syslogmsg = NULL;

    pwent = getpwuid(cm_initial_uid);
    username = (pwent != NULL ? pwent->pw_name : "UNKNOWN");

#if defined(HAVE_SYSLOG) && !defined(TESTING)
    openlog(PACKAGE, LOG_PID, LOG_AUTHPRIV);
#endif

    /* Execute special-cases of user-selected task: */
    switch ((mode & M_MODE_MASK)) {
        case M_VERSION:
            fprintf(stderr, "%s-%s\n", PACKAGE_NAME, PACKAGE_VERSION);
            break;
        case M_KEYMGRS:
            do_keymgrlist();
            break;
        case M_LIST:
            do_list(eltlist);
            break;
        case M_STATUS:
            do_status(eltlist);
            break;
        case M_SYSBOOT:
            do_sysboot_updown(1, tgttable, pw_ctxt);
            break;
        case M_SYSQUIT:
            do_sysboot_updown(0, tgttable, pw_ctxt);
            break;
        case M_SAFETYNET:
            do_safetynet();
            break;
        default:
            ignore_eltlist = 0;
            break;
    }
    if (ignore_eltlist) eltlist = NULL;

    /* Apply user-selected operation to list of targets (if present): */
    for (elt=eltlist; elt!=NULL && eflag<ERR_threshold; elt=elt->nx) {
        boundtgt = bind_tgtdefn(elt->tgt);
        if (boundtgt == NULL) {
            fprintf(stderr, _("Cannot find key-manager to match target \"%s\"\n"), elt->tgt->ident);
            eflag = ERR_BADKEYFORMAT;
            break;
        }
        syslogmsg = NULL;
        prio = LOG_AUTHPRIV | LOG_NOTICE;

        switch ((mode & M_MODE_MASK)) {
            case M_PREPARE:
                syslogmsg = "prepare of \"%s\" by %s %s";
                eflag = do_devsetup(pw_ctxt, boundtgt, NULL);
                break;
            case M_RELEASE:
                syslogmsg = "release of \"%s\" by %s %s";
                prio = LOG_AUTHPRIV | LOG_NOTICE;
                eflag = do_devshutdown(boundtgt);
                if (eflag == WRN_UNCONFIG) syslogmsg = NULL;
                break;
            case M_MOUNT:
                if ((eflag = check_priv_tgt(boundtgt->tgt)) != ERR_NOERROR) break;
                syslogmsg = "mount of \"%s\" by %s %s";
                eflag = do_mount(pw_ctxt, boundtgt);
                if (eflag == WRN_MOUNTED) syslogmsg = NULL;
                break;
            case M_UNMOUNT:
                if ((eflag = check_priv_tgt(boundtgt->tgt)) != ERR_NOERROR) break;
                syslogmsg = "unmount of \"%s\" by %s %s";
                eflag = do_unmount(boundtgt);
                if (eflag == WRN_UNCONFIG) syslogmsg = NULL;
                break;
            case M_SWAPON:
                syslogmsg = "swapon \"%s\" by %s %s";
                eflag = do_swapon(pw_ctxt, boundtgt);
                if (eflag == WRN_MOUNTED) syslogmsg = NULL;
                break;
            case M_SWAPOFF:
                syslogmsg = "swapoff \"%s\" by %s %s";
                eflag = do_swapoff(boundtgt);
                if (eflag == WRN_UNCONFIG) syslogmsg = NULL;
                break;
            case M_PASSWORD:
                if ((eflag = check_priv_tgt(boundtgt->tgt)) != ERR_NOERROR) break;
                syslogmsg = "changing password for \"%s\" by %s %s";
                eflag = do_passwd(pw_ctxt, boundtgt);
                break;
            case M_KEYGEN:
                if ((eflag = check_priv_tgt(boundtgt->tgt)) != ERR_NOERROR) break;
                syslogmsg = "key generation for \"%s\" by %s %s";
                eflag = do_keygen(pw_ctxt, boundtgt, params, 0, NULL);
                break;
            case M_KEYREU:
                if ((eflag = check_priv_tgt(boundtgt->tgt)) != ERR_NOERROR) break;
                syslogmsg = "key generation for \"%s\" by %s %s";
                eflag = do_keygen(pw_ctxt, boundtgt, params, 1, tgttable);
                break;
            default:
                break;
        }

        /* Suppress benign warning messages when '--all' option is selected: */
        if (eflag != 0 && eflag < ERR_threshold
                && (mode & F_ALL_TARGETS) && (mode & F_NOWARN_ALL)) {
            eflag = 0;
        }

#ifndef TESTING
#  ifdef HAVE_SYSLOG
        if (syslogmsg != NULL) {
            syslog(prio, syslogmsg, elt->tgt->ident, username,
                (eflag == ERR_NOERROR ? "succeeded" : "failed"));
        }
#  endif
#else   /* TESTING */
        /* Avoid compiler warnings about unused variables: */
        eflag += 0 * (prio + (username == NULL) + (syslogmsg == NULL));
#endif

        free_boundtgt(boundtgt);
    }

#ifdef HAVE_SYSLOG
    closelog();
#endif

    return eflag;
}


static cmmode_t get_defaultmode(int argc, char *argv[])
    /** Translate program-name into default action (or just assume M_MOUNT) */
{   cmmode_t mode = M_MOUNT;

#ifdef WITH_ARGV0
    struct modename {
        cmmode_t mode;
        const char *name; } modetable[] = {
            { M_MOUNT,      "cryptmount" },
            { M_UNMOUNT,    "cryptumount" },
            { M_UNMOUNT,    "cryptunmount" },
#if WITH_CSWAP
            { M_SWAPON,     "cryptswapon" },
            { M_SWAPOFF,    "cryptswapoff", },
#endif
            { M_PREPARE,    "cryptprepare" },
            { M_RELEASE,    "cryptrelease" },
            { M_MOUNT, NULL } },
        *mp;
    const char *base;

    if (argc >= 1) {
        base = strrchr(argv[0], '/');
        if (base != NULL) ++base; else base = argv[0];

        for (mp=modetable; mp->name!=NULL; ++mp) {
            if (strcmp(base, mp->name) == 0) {
                mode = mp->mode;
                break;
            }
        }
    }

#endif

    return mode;
}


/**
 *  Parse command-line options to identify a top-level processing mode,
 *  and extract configuration parameters such as key-length,
 *  password source etc.
 *  This routine will also ensure that 'privileged' options are
 *  only accessible to the super-user.
 */
cmmode_t parse_options(int argc, char *argv[],
                       const char **mode_params,
                       int *passwd_fd, int *config_fd,
                       km_pw_context_t *pw_ctxt)
{   cmmode_t bare_mode = M_UNSET, mode_flags = 0;
    enum {
        ALL_USERS =     0x01,
        NEEDS_ARG =     0x02,
        SET_MODE =      0x04,
        SET_FLAGS =     0x08,
        NEEDS_TGT =     0x10
    };
    const char *passwd_fd_str = NULL, *config_fd_str = NULL;
    struct cm_option {
        char shortopt;
        const char *longopt;
        unsigned flags;
        const char **argument;
        cmmode_t newmode;
        unsigned newflags;
    };
    struct cm_option opt_table[] = {
        { 'a', "all",               ALL_USERS | SET_FLAGS,
                                    NULL, M_UNSET, F_ALL_TARGETS },
        { 'c', "change-password",   ALL_USERS | SET_MODE | SET_FLAGS,
                                    NULL, M_PASSWORD, F_NEEDS_TGT },
        { 'f', "config-fd",         NEEDS_ARG,
                                    &config_fd_str, M_UNSET, 0 },
        { 'g', "generate-key",      NEEDS_ARG | SET_MODE | SET_FLAGS,
                                    mode_params, M_KEYGEN, F_NEEDS_TGT },
        { 'h', "help",              ALL_USERS | SET_MODE,
                                    NULL, M_HELP, 0 },
        { 'k', "key-managers",      ALL_USERS | SET_MODE,
                                    NULL, M_KEYMGRS, 0 },
        { 'l', "list",              ALL_USERS | SET_MODE,
                                    NULL, M_LIST, 0 },
        { 'm', "mount",             ALL_USERS | SET_MODE | SET_FLAGS,
                                    NULL, M_MOUNT, F_NEEDS_TGT|F_NOWARN_ALL },
        { 'w', "passwd-fd",         ALL_USERS | NEEDS_ARG,
                                    &passwd_fd_str, M_UNSET, 0 },
        { 'p', "prepare",           SET_MODE | SET_FLAGS,
                                    NULL, M_PREPARE, F_NEEDS_TGT|F_NOWARN_ALL },
        { 'r', "release",           SET_MODE | SET_FLAGS,
                                    NULL, M_RELEASE, F_NEEDS_TGT|F_NOWARN_ALL },
        { 'e', "reuse-key",         NEEDS_ARG | SET_MODE | SET_FLAGS,
                                    mode_params, M_KEYREU, F_NEEDS_TGT },
        { 'n', "safetynet",         SET_MODE,
                                    NULL, M_SAFETYNET, 0 },
        { 'S', "status",            ALL_USERS | SET_MODE | SET_FLAGS,
                                    NULL, M_STATUS },
        { 's', "swapon",            SET_MODE | SET_FLAGS,
                                    NULL, M_SWAPON, F_NEEDS_TGT|F_NOWARN_ALL },
        { 'x', "swapoff",           SET_MODE | SET_FLAGS,
                                    NULL, M_SWAPOFF, F_NEEDS_TGT|F_NOWARN_ALL },
        { 'B', "system-boot",       SET_MODE,
                                    NULL, M_SYSBOOT, 0 },
        { 'Q', "system-shutdown",   SET_MODE,
                                    NULL, M_SYSQUIT, 0 },
        { 'u', "unmount",           ALL_USERS | SET_MODE | SET_FLAGS,
                                    NULL, M_UNMOUNT, F_NEEDS_TGT|F_NOWARN_ALL },
        { 'y', "verify-password",   ALL_USERS | SET_FLAGS,
                                    NULL, M_UNSET, F_VERIFY_PW },  /* FIXME - not implemented? */
        { 'v', "version",           ALL_USERS | SET_MODE,
                                    NULL, M_VERSION, 0 },
#ifdef TESTING
        { 'D', "config-dir",        ALL_USERS | NEEDS_ARG,
                                    &test_context.argconfigdir, M_UNSET, 0 },
        { 'W', "password",          ALL_USERS | NEEDS_ARG,
                                    &pw_ctxt->argpasswd[0], M_UNSET, 0 },
        { 'N', "newpassword",       ALL_USERS | NEEDS_ARG,
                                    &pw_ctxt->argpasswd[1], M_UNSET, 0 },
        { 'T', "self-test",         ALL_USERS | SET_MODE,
                                    NULL, M_SELFTEST, 0 },
#endif
        { '?', NULL, 0, NULL, M_UNSET, 0 } };
    const size_t n_options = (sizeof(opt_table) / sizeof(opt_table[0]) - 1);
    char *shortopts, *spos;
    int idx = 0, optchar = '\0';
    size_t i;

    shortopts = (char*)malloc(n_options * 2 + 1);
    spos = shortopts;
    for (i=0; i<n_options; ++i) {
        *spos = opt_table[i].shortopt;
        if ((opt_table[i].flags & NEEDS_ARG)) {
            *++spos = ':';
        }
        ++spos;
    }
    *spos = '\0';

#ifdef _GNU_SOURCE
    struct option *longopts;

    longopts = (struct option*)calloc(n_options + 1, sizeof(struct option));
    for (i=0; i<n_options; ++i) {
        longopts[i].name =      opt_table[i].longopt;
        longopts[i].has_arg =   ((opt_table[i].flags & NEEDS_ARG)
                                    ? required_argument : no_argument);
        longopts[i].flag =      NULL;
        longopts[i].val =       (int)opt_table[i].shortopt;
    }
#endif  /* _GNU_SOURCE */

    for (;;) {
        struct cm_option *selected;
#ifdef _GNU_SOURCE
        optchar = getopt_long(argc, argv, shortopts, longopts, &idx);
#else
        optchar = getopt(argc, argv, shortopts);
#endif
        if (optchar < 0 || optchar == '?') break;
        idx = 0;
        while (opt_table[idx].shortopt != optchar
                && opt_table[idx].longopt != NULL) ++idx;
        if (opt_table[idx].longopt == NULL) {
            optchar = '?';
            break;
        }
        selected = opt_table + idx;

        if (!(selected->flags & ALL_USERS)) {
            check_priv_opt(selected->longopt);
        }

        if ((selected->flags & NEEDS_ARG)) {
            *selected->argument = optarg;
        }

        if ((selected->flags & SET_MODE)) {
            if (bare_mode == M_UNSET) {
                bare_mode = selected->newmode;
            } else {
                fprintf(stderr, _("Multiple operating modes not supported\n"));
                exit(1);
            }
        }

        if ((selected->flags & SET_FLAGS)) {
            mode_flags |= selected->newflags;
        }
    }

    if (optchar == '?') {
        fprintf(stderr, "%s", _(USAGE_STRING));
        exit(EXIT_BADOPT);
    }

    if (bare_mode == M_UNSET) bare_mode = get_defaultmode(argc, argv);
    if (config_fd_str != NULL) sscanf(config_fd_str, "%d", config_fd);
    if (passwd_fd_str != NULL) sscanf(passwd_fd_str, "%d", passwd_fd);

#ifdef _GNU_SOURCE
    free((void*)longopts);
#endif
    free((void*)shortopts);

    return (bare_mode | mode_flags);
}


int main(int argc, char *argv[])
{   cmmode_t mode = M_UNSET;
    const char *mode_params = NULL;
    char *cmtab = NULL;
    int config_fd = -1, passwd_fd = -1, eflag = ERR_NOERROR;
    tgtdefn_t *tgttable=NULL;
    km_pw_context_t pw_ctxt;
    const tgtdefn_t *tgt = NULL;
    targelt_t *eltlist = NULL, **eltptr = &eltlist;

#ifdef HAVE_GETTEXT
    /* setup internationalization of message-strings via gettext(): */
    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);
#endif

    cm_initial_uid = getuid();
    init_env_dictionary();

#ifdef TESTING
    fprintf(stderr, "WARNING!!! cryptmount has been compiled for TESTING only - DO NOT INSTALL\n");
    pw_ctxt.argpasswd[0] = pw_ctxt.argpasswd[1] = NULL;
    test_context.argconfigdir = NULL;
#endif

    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        fprintf(stderr, _("Memory-locking failed...\n"));
    }

    pw_ctxt.verify = 0;
    pw_ctxt.debug_level = 0;

    mode = parse_options(argc, argv, &mode_params,
                         &passwd_fd, &config_fd, &pw_ctxt);

#ifdef TESTING
    if (mode == M_SELFTEST) {
        eflag = cm_run_tests();
        clear_env_dictionary();
        return eflag;
    }
#endif

    (void)cm_path(&cmtab, CM_SYSCONF_PFX, "cmtab");

    if ((mode & M_MODE_MASK) == M_HELP) {
        fprintf(stderr, "%s", _(USAGE_STRING));
        exit(EXIT_OK);
    }

    /* Configure source of passwords: */
    if (passwd_fd >= 0) {
        pw_ctxt.fd_pw_source = fdopen(passwd_fd, "r");
        if (pw_ctxt.fd_pw_source == NULL) {
            fprintf(stderr, _("Bad file-descriptor (%d)\n"), passwd_fd);
            exit(EXIT_BADOPT);
        }
    } else {
        pw_ctxt.fd_pw_source = NULL;
    }

    /* Check & read-in configuration file: */
#ifndef TESTING
    if (sycheck_cmtab(cmtab) != ERR_NOERROR) {
        fprintf(stderr, _("Security failure\n"));
        exit(EXIT_INSECURE);
    }
#endif
    if (config_fd >= 0) {
        tgttable = parse_config_fd(config_fd);
    } else {
        tgttable = parse_config(cmtab);
    }
    free((void*)cmtab);

    if (((mode & M_MODE_MASK) == M_LIST
         || (mode & M_MODE_MASK) == M_STATUS) && optind >= argc) {
        mode |= F_ALL_TARGETS;
    }

    /* if '--all' given, assemble list of targets from entire config-file */
    if ((mode & F_ALL_TARGETS) != 0) {
        if (optind < argc) {
            fprintf(stderr, _("Trailing command-line arguments given with '--all' option\n"));
            exit(EXIT_BADOPT);
        }
        for (tgt=tgttable; tgt!=NULL; tgt=tgt->nx) {
            *eltptr = (targelt_t*)malloc(sizeof(targelt_t));
            (*eltptr)->tgt = tgt;
            (*eltptr)->nx = NULL;
            eltptr = &((*eltptr)->nx);
        }
    }

    /* Assemble list of targets from remaining command-line arguments: */
    while (optind < argc) {
        tgt = get_tgtdefn(tgttable, argv[optind]);
        if (tgt != NULL) {
            *eltptr = (targelt_t*)malloc(sizeof(targelt_t));
            (*eltptr)->tgt = tgt;
            (*eltptr)->nx = NULL;
            eltptr = &((*eltptr)->nx);
        } else {
            fprintf(stderr, _("Target name \"%s\" is not recognized\n"),
                    argv[optind]);
            exit(EXIT_BADTGT);
        }
        ++optind;
    }


    /* Check security of all targets being processed: */
    for (eltptr=&eltlist; *eltptr!=NULL; eltptr=&((*eltptr)->nx)) {
        tgt = (*eltptr)->tgt;
        if (sycheck_target(tgt) != ERR_NOERROR) {
            fprintf(stderr, _("Target security failure for \"%s\"\n"),
                    tgt->ident);
            exit(EXIT_INSECURE);
        }
    }


    /* Execute user-selected task: */
    if ((mode & F_NEEDS_TGT) && eltlist == NULL) {
        fprintf(stderr, _("No targets specified\n"));
        exit(EXIT_BADTGT);
    }
    eflag = execute_list(mode, tgttable, &pw_ctxt, mode_params, eltlist);
    free_keymanagers();


    /* Tidy-up: */
    while (eltlist != NULL) {
        const targelt_t *elt_rm = eltlist;
        eltlist = eltlist->nx;
        free((void*)elt_rm);
    }
    free_config(&tgttable);
    munlockall();

    clear_env_dictionary();

    return eflag;
}

/*
 *  (C)Copyright 2005-2024, RW Penney
 */
