/*
 *  Device-mapper utilities for cryptmount
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#if HAVE_SYS_SYSMACROS_H
#  include <sys/sysmacros.h>
#endif
#include <sys/types.h>
#include <time.h>
#if HAVE_LIBUDEV
#  include <libudev.h>
#endif

#if defined(HAVE_LIBDEVMAP)
#  include <libdevmapper.h>
#else
#  error libdevmapper headers are needed to build cryptmount
#endif

#include "cryptmount.h"
#include "dmutils.h"
#include "utils.h"


#if !HAVE_LIBUDEV

struct udev_queue_loc {
    const char *path;
    int is_file;
} udev_queue_locations[] = {
    { "/run/udev/queue.bin",    1 },    /* Debian-7.0 has queue beneath /run */
    { "/dev/.udev/queue.bin",   1 },    /* Recent udev has file in /dev/.udev */
    { "/dev/.udev/queue",       0 }     /* Older udev has directory of events */
};

int udev_queue_size(const char *path);
int udev_active_dir(const char *path, time_t starttime, double timeout);

#endif  // !HAVE_LIBUDEV


struct dm_task *devmap_prepare(int type, const char *ident)
    /*! Prepare device-mapper task structure */
{   struct dm_task *dmt = NULL;

    dmt = dm_task_create(type);
    if (dmt != NULL) {
        if (!dm_task_set_name(dmt, ident)) {
            dm_task_destroy(dmt);
            dmt = NULL;
        }
    }

    return dmt;
}


/*! @brief Create device-mapper full pathname from target description */
int devmap_path(char **buff, const char *ident)
{   size_t pfxlen, sfxlen;

    pfxlen = strlen(dm_dir());
    sfxlen = strlen(ident);
    *buff = (char*)realloc((void*)(*buff), (pfxlen + sfxlen + 2));

    snprintf(*buff, (pfxlen + sfxlen + 2), "%s/%s", dm_dir(), ident);

    return (int)(pfxlen + sfxlen + 1);
}


int devmap_create(const char *ident, uint64_t blk0, uint64_t blklen,
                  const char *tgttype, const char *params)
    /* create new device-mapper target & associated device node: */
{   struct dm_task *dmt=NULL;
    struct dm_info dmi;
    char *devpath=NULL;
    struct stat sbuff;
    mode_t mode;
    dev_t dev;

    /* create device-mapper target: */
    if ((dmt = devmap_prepare(DM_DEVICE_CREATE, ident)) == NULL) {
        fprintf(stderr, "failed to initialize device-mapper task\n");
        return ERR_DMSETUP;
    }
    if (!dm_task_add_target(dmt, blk0, blklen, tgttype, params)) {
        fprintf(stderr, "failed to add device-mapper target \"%s\" { %s }\n",
                tgttype, params);
        return ERR_DMSETUP;
    }
    if (!dm_task_run(dmt)) {
        fprintf(stderr, "device-mapper task failed\n");
        return ERR_DMSETUP;
    }
    if (!dm_task_get_info(dmt, &dmi)) {
        fprintf(stderr, "device-mapper info not available\n");
        return ERR_DMSETUP;
    }
    dm_task_destroy(dmt);

    /* create device node (below /dev?): */
    mode = S_IFBLK | S_IRUSR | S_IWUSR;
    dev = makedev(dmi.major, dmi.minor);
    devmap_path(&devpath, ident);
    if (stat(devpath, &sbuff) != 0 && mknod(devpath, mode, dev) != 0) {
        fprintf(stderr, "device \"%s\" (%u,%u) creation failed\n",
                devpath, dmi.major, dmi.minor);
        return ERR_BADDEVICE;
    }

    if (devpath != NULL) free((void*)devpath);

    return ERR_NOERROR;
}


int devmap_dependencies(const char *ident, unsigned *count, dev_t **devids)
{   struct dm_task *dmt=NULL;
    struct dm_deps *deps;
    unsigned i;
    int eflag=ERR_NOERROR;

    if ((dmt = devmap_prepare(DM_DEVICE_DEPS, ident)) == NULL) {
        fprintf(stderr, "failed to initialize device-mapper task\n");
        eflag = ERR_DMSETUP;
        goto bail_out;
    }
    if (!dm_task_run(dmt)) {
        fprintf(stderr, "device-mapper task failed\n");
        eflag = ERR_DMSETUP;
        goto bail_out;
    }

    if ((deps = dm_task_get_deps(dmt)) == NULL) {
        eflag = ERR_DMSETUP;
        goto bail_out;
    }

    /* copy device info into fresh array: */
    *count = deps->count;
    *devids = (dev_t*)malloc((size_t)(deps->count * sizeof(dev_t)));
    for (i=0; i<deps->count; ++i) (*devids)[i] = (dev_t)deps->device[i];

  bail_out:

    if (dmt != NULL) dm_task_destroy(dmt);

    return eflag;
}


/*! @brief Remove device-mapper target and associated device */
int devmap_remove(const char *ident)
{   struct dm_task *dmt = NULL;
    struct dm_info dmi;
    struct stat sbuff;
    char *devpath = NULL;
    int eflag = ERR_NOERROR;

    /* Check device-mapper target is configured & get info: */
    if (!is_configured(ident, &dmi)) {
        eflag = ERR_BADDEVICE;
        goto bail_out;
    }

    /* Remove device node (below /dev?): */
    devmap_path(&devpath, ident);
    if (stat(devpath, &sbuff) != 0) {
        fprintf(stderr, "unable to stat() device node for %s at %s\n",
                ident, devpath);
        eflag = ERR_DMSETUP;
        goto bail_out;
    }
    if ((uint32_t)major(sbuff.st_rdev) == dmi.major
      && (uint32_t)minor(sbuff.st_rdev) == dmi.minor) {
        unlink(devpath);
    } else {
        fprintf(stderr,"device \"%s\" doesn't match device-mapper info (%d,%d)\n", devpath, dmi.major, dmi.minor);
        eflag = ERR_BADDEVICE;
        goto bail_out;
    }

    /* Remove device-mapper target: */
    if ((dmt = devmap_prepare(DM_DEVICE_REMOVE, ident)) == NULL) {
        fprintf(stderr, "failed to initialize device-mapper task\n");
        eflag = ERR_DMSETUP;
        goto bail_out;
    }
    if (!dm_task_run(dmt)) {
        fprintf(stderr, "device-mapper task failed\n");
        eflag = ERR_DMSETUP;
        goto bail_out;
    }

  bail_out:

    if (dmt != NULL) dm_task_destroy(dmt);
    if (devpath != NULL) free((void*)devpath);

    return eflag;
}


int is_configured(const char *ident, struct dm_info *dminfo)
    /*! Check if device-mapper target has been setup & (optionally) get info */
{   struct dm_task *dmt = NULL;
    struct dm_info *dmi, dmi_local;
    int config = 1;

    dmi = (dminfo != NULL ? dminfo : &dmi_local);

    /* Create device-mapper target: */
    if (ident == NULL
      || (dmt = devmap_prepare(DM_DEVICE_INFO, ident)) == NULL
      || !dm_task_run(dmt)
      || !dm_task_get_info(dmt, dmi)
      || !dmi->exists) {
        config = 0;
    }
    if (dmt != NULL) dm_task_destroy(dmt);

    return config;
}


int await_device(const char *path, int present, unsigned timeout_ms)
    /*! Repeatedly check for presence (or absence) of block device */
{   int st = -1, t_waited = 0, resolved = 0;
    struct stat sbuff;
    struct timespec start_time, now;

    clock_gettime(CLOCK_REALTIME, &start_time);

    do {
        st = stat(path, &sbuff);
        if (present) {
          resolved = (st == 0 && (sbuff.st_mode & S_IFMT) == S_IFBLK);
        } else {
          resolved = (st != 0 && errno == ENOENT);
        }

        if (!resolved) {
            millisleep(250);
        }

        clock_gettime(CLOCK_REALTIME, &now);
        t_waited = (now.tv_sec - start_time.tv_sec) * 1000 +
                    (now.tv_nsec - start_time.tv_nsec) / 1000000;
    } while (!resolved && (t_waited < timeout_ms));

    if (t_waited >= timeout_ms) {
        fprintf(stderr, "Timeout in await_device(%s, %d, %u)\n",
                path, present, timeout_ms);
    }

    return (resolved ? 0 : 1);
}


int await_devmap(const char *ident, int present, unsigned timeout_ms)
    /*! Wrapper around await_device(), using device-mapper target name */
{   char *tgt = NULL;
    int status = -1;

    devmap_path(&tgt, ident);
    status = await_device(tgt, present, timeout_ms);
    free((void*)tgt);

    return status;
}


int udev_settle()
    /*! Allow time for udev events to be processed */
{   double totdelay = 0.0;
    time_t starttime;
#if HAVE_LIBUDEV
    struct udev *udev_ctx;
    struct udev_queue *udev_qu;
#else
    struct udev_queue_loc *udev_mode;
    struct stat sbuff;
#endif
#if HAVE_NANOSLEEP
    struct timespec delay;
#endif
    int inc_ms = 250, settling = 1;
    const double timeout = 10.0;

    /* This routine mitigates apparent race-conditions
     * between udev events which may temporarily take ownership of
     * and rename newly created devices, thereby causing
     * other processes to fail if they try to destroy
     * or reconfigure those devices at the same time.
     * Whether this is the responsibilty of kernel-level functions
     * to resolve, or for user applications to mitigate,
     * is open to debate. */

    time(&starttime);

#if HAVE_LIBUDEV
    udev_ctx = udev_new();
    //udev_selinux_init(udev_ctx);
    udev_qu = udev_queue_new(udev_ctx);
#else
    /* Try to find location and type of udev event queue: */
    udev_mode = udev_queue_locations;
    while (udev_mode->is_file) {
        if (stat(udev_mode->path, &sbuff) == 0) break;
        ++udev_mode;
    }
#endif

    /* Keep waiting until there are no more queued udev events: */
    do {
#if HAVE_NANOSLEEP
        delay.tv_sec = inc_ms / 1000;
        delay.tv_nsec = (inc_ms % 1000) * 1000 * 1000;
        nanosleep(&delay, NULL);
#else
        sleep((unsigned)ceil(inc_ms * 1e-3));
#endif
        totdelay += inc_ms * 1e-3;
        inc_ms += inc_ms / 3;

#if HAVE_LIBUDEV
        settling = !udev_queue_get_queue_is_empty(udev_qu);
#else
        settling = 0;
        if (udev_mode->is_file) {
            /* Current versions of udev place events in a single file: */
            settling |= (udev_queue_size(udev_mode->path) > 0);
        } else {
            /* Older versions of udev use a directory of event files: */
            settling |= udev_active_dir(udev_mode->path, starttime, timeout);
        }
#endif  /* HAVE_LIBUDEV */
    } while (settling && totdelay < timeout);

#if HAVE_LIBUDEV
    udev_queue_unref(udev_qu);
    //udev_selinux_exit(udev_ctx);
    udev_unref(udev_ctx);
#endif

    return settling;
}


#if !HAVE_LIBUDEV

int udev_queue_size(const char *path)
    /*! Count number of unprocessed udev events in queue.bin file */
{   FILE *fp;
    unsigned long long seqnum;
    unsigned short skiplen;
    int nqueued = 0;

    fp = fopen(path, "rb");
    if (fp == NULL) return 0;
    if (fread((void*)&seqnum, sizeof(seqnum), (size_t)1, fp) != 1) goto bail_out;

    for (;;) {
        skiplen = 0;
        if (fread((void*)&seqnum, sizeof(seqnum), (size_t)1, fp) != 1
          || fread((void*)&skiplen, sizeof(skiplen), (size_t)1, fp) != 1) break;

        if (skiplen > 0) {
            void *buff = malloc((size_t)skiplen);
            nqueued += (fread(buff, (size_t)skiplen, (size_t)1, fp) == 1);
            free(buff);
        } else {
            --nqueued;
        }
    }

  bail_out:
    fclose(fp);

    return nqueued;
}


/*!
 *  Check whether the udev queue directory (e.g. /dev/.udev/queue)
 *  has been recently modified.
 *  This is only relevant to older versions of udev (e.g. 0.105).
 */
int udev_active_dir(const char *path, time_t starttime, double timeout)
{   struct stat sbuff;
    int settling = 0;

    /*  If the event directory exists, then we either have active
        events, or possibly it is a remnant from an old udev process. */

    if (stat(path, &sbuff) == 0) {
        settling |= ((starttime - sbuff.st_mtime) < 100 * timeout);
    }

    return settling;
}

#endif  // !HAVE_LIBUDEV

/*
 *  (C)Copyright 2005-2024, RW Penney
 */
