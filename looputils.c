/*
 *  Loopback-device utilities for cryptmount
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

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#if HAVE_SYS_SYSMACROS_H
#  include <sys/sysmacros.h>
#endif
#include <sys/types.h>

#ifdef HAVE_LINUX_LOOP_H
#  include <linux/loop.h>
#else
#  error loop.h kernel-header is needed to build cryptmount
#endif
#include <linux/major.h>

#include "cryptmount.h"
#include "looputils.h"

char *cm_strdup(const char *orig);


/**
 *  Format-strings for loopback devices,
 *  covering legacy /dev/loop/0 style
 *  as well as current /dev/loop0 style.
 */
static const char *loop_formats[] = {
    "/dev/loop%u", "/dev/loop/%u", NULL };


/**
 *  Search for vacant loopback device.
 *
 *  For recent kernels (>=3.1), this will use the /dev/loop-control
 *  interface, while for older kernels this will involve explicit
 *  search through /dev/loop0..255 for a device whose status indicates
 *  that it not associated with a backing file.
 */
int loop_findfree(char *buff, size_t buffsz)
{   unsigned idx, found = 0;
    int devfd, devno;
    struct loop_info64 linfo;
    char loopname[256] = "";
    struct stat sbuff;

#ifdef LOOP_CTL_GET_FREE
    devfd = open("/dev/loop-control", O_RDWR);
    devno = ioctl(devfd, LOOP_CTL_GET_FREE);
    close(devfd);
    if (devfd >=0 && devno >= 0) {
        snprintf(loopname, sizeof(loopname), "/dev/loop%d", devno);
        found = 1;
    }
#endif

    for (devno=0; devno<256 && !found; ++devno) {
        for (idx=0; loop_formats[idx]!=NULL && !found; ++idx) {
            snprintf(loopname, sizeof(loopname),
                     loop_formats[idx], (unsigned)devno);
            if (stat(loopname, &sbuff) || !S_ISBLK(sbuff.st_mode)) continue;
            devfd = open(loopname, O_RDONLY);
            if (devfd < 0) continue;
            if (ioctl(devfd, LOOP_GET_STATUS64, &linfo) && errno == ENXIO) {
                found = 1;
            }
            close(devfd);
        }
    }

    if (found && buff != NULL) strncpy(buff, loopname, buffsz);

    return !found;
}


int loop_setup(const char *dev, const char *file, int flags)
    /** Setup loopback device to point to regular file */
{   int devfd = -1, filefd = -1, eflag = ERR_NOERROR;
    struct loop_info64 lpinfo;

    memset((void*)&lpinfo, 0, sizeof(lpinfo));
    strncpy((char*)lpinfo.lo_file_name, file, (size_t)LO_NAME_SIZE);
    lpinfo.lo_offset = 0;
    lpinfo.lo_encrypt_key_size = 0;

    devfd = open(dev, flags);
#ifdef LOOP_CTL_ADD
    if (devfd < 0) {
        unsigned devno = ~0u;
        int ctlfd;
        sscanf(dev, loop_formats[0], &devno);
        ctlfd = open("/dev/loop-control", O_RDWR);
        (void)ioctl(ctlfd, LOOP_CTL_ADD, devno);
        close(ctlfd);
        devfd = open(dev, flags);
    }
#endif
    if (devfd < 0) {
        fprintf(stderr, "Cannot open \"%s\" for reading\n", dev);
        eflag = ERR_BADFILE;
        goto bail_out;
    }
    filefd = open(file, flags);
    if (filefd < 0) {
        fprintf(stderr, "Cannot open \"%s\" for reading\n", file);
        eflag = ERR_BADFILE;
        goto bail_out;
    }

    if (ioctl(devfd, LOOP_SET_FD, filefd)
      || ioctl(devfd, LOOP_SET_STATUS64, &lpinfo)) {
        fprintf(stderr, "LOOP_SET_FD ioctl() failed on \"%s\"\n", dev);
        eflag = ERR_BADIOCTL;
        goto bail_out;
    }

  bail_out:

    if (filefd >= 0) close(filefd);
    if (devfd >= 0) close(devfd);

    return eflag;
}


int loop_destroy(const char *dev)
    /** Detach loopback device from underlying file */
{   int devfd;
    int eflag = ERR_NOERROR;

    devfd = open(dev, O_RDONLY);
    if (devfd < 0) {
        fprintf(stderr, "Cannot open \"%s\" for reading\n", dev);
        eflag = ERR_BADFILE;
        goto bail_out;
    }

    if (ioctl(devfd, LOOP_CLR_FD, 0)) {
        fprintf(stderr, "LOOP_CLR_FD ioctl() failed on \"%s\"\n", dev);
        eflag = ERR_BADIOCTL;
        goto bail_out;
    }

#ifdef LOOP_CTL_REMOVE
  {   int devno = -1, ctlfd;

      sscanf(dev, loop_formats[0], &devno);
      ctlfd = open("/dev/loop-control", O_RDWR);
      (void)ioctl(ctlfd, LOOP_CTL_REMOVE, devno);
      close(ctlfd);
  }
#endif

  bail_out:

    if (devfd >= 0) (void)close(devfd);

    return eflag;
}


int loop_ident(unsigned maj, unsigned min, char *buff, size_t buffsz)
    /** Find device node for given minor device number */
{   unsigned idx;
    int found=0;
    char str[256];
    struct stat sbuff;

    if (maj != LOOP_MAJOR) return !found;

    for (idx=0; loop_formats[idx]!=NULL && !found; ++idx) {
        sprintf(str, loop_formats[idx], min);
        if (stat(str, &sbuff) || !S_ISBLK(sbuff.st_mode)) continue;
        found = ((unsigned)major(sbuff.st_rdev) == maj
                && (unsigned)minor(sbuff.st_rdev) == min);
    }

    if (found && buff != NULL) strncpy(buff, str, buffsz);

    return !found;
}


int loop_dellist(unsigned devcnt, const dev_t *devids)
    /** Tidy-up list of loopback devices */
{   unsigned i;
    char buff[256];
    int eflag = 0;

    if (devids == NULL) return eflag;

    for (i=0; i<devcnt; ++i) {
        if (loop_ident(major(devids[i]), minor(devids[i]), buff, sizeof(buff))
          || (loop_destroy(buff) != ERR_NOERROR)) {
            fprintf(stderr, _("Failed to free device (%d,%d)\n"),
                        major(devids[i]), minor(devids[i]));
            eflag = 1;
        }
    }

    return eflag;
}


int blockify_file(const char *filename, int fmode, const char *prefdev,
                const char **devname, int *isloop)
    /** Convert the given filename to block-device if it isn't already */
{   enum { BUFFMIN = 1024 };
    struct stat sbuff;
    char *loopdev = NULL;
    int eflag = ERR_NOERROR;

    if (filename == NULL || stat(filename, &sbuff) != 0) {
        *isloop = 0;
        eflag = ERR_BADDEVICE;
        goto bail_out;
    }

    if (S_ISBLK(sbuff.st_mode)) {
        /* Keyfile is block-special already: */
        *devname = cm_strdup(filename);
        *isloop = 0;
    } else if (S_ISREG(sbuff.st_mode)) {
        /* Create loopback device around ordinary file: */
        if (prefdev != NULL && strcmp(prefdev, "auto") != 0) {
            loopdev = (char*)malloc((size_t)(strlen(prefdev) + 1));
            strcpy(loopdev, prefdev);
        } else {
            loopdev = (char*)malloc((size_t)BUFFMIN);
            if (loop_findfree(loopdev, (size_t)BUFFMIN) != 0) {
                fprintf(stderr, _("No available loopback devices\n"));
                eflag = ERR_BADDEVICE;
                goto bail_out;
            }
        }
        if (loop_setup(loopdev, filename, fmode) != ERR_NOERROR) {
            eflag = ERR_BADDEVICE;
            goto bail_out;
        }
        *devname = loopdev;
        loopdev = NULL;
        *isloop = 1;
    } else {
        fprintf(stderr,
            _("Bad device type (%x) for \"%s\" (need block/file)\n"),
            (unsigned)sbuff.st_mode, filename);
        *devname = NULL;
        *isloop = 0;
        eflag = ERR_BADDEVICE;
    }

  bail_out:

    if (loopdev != NULL) free((void*)loopdev);

    return eflag;
}


int unblockify_file(const char **devname, int isloop)
    /** Remove loopback device previously created by blockify_file() */
{   int eflag = ERR_NOERROR;

    if (isloop && *devname != NULL) {
        eflag = loop_destroy(*devname);
        free((void*)*devname);
        *devname = NULL;
    }

    return eflag;
}

/*
 *  (C)Copyright 2005-2022, RW Penney
 */
