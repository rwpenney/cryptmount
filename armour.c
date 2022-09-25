/*
 *  Methods for encryption/security mechanisms for cryptmount
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

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if HAVE_NANOSLEEP
#  include <time.h>
#endif
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/times.h>

#include <linux/major.h>

#include "armour.h"
#include "cryptmount.h"
#include "tables.h"
#include "utils.h"
#ifdef TESTING
#  include <glob.h>
#  include <libgen.h>
#  include "cmtesting.h"
#endif

/*! \addtogroup keymgrs
 *  @{ */


keymanager_t *kmblti_gethandle(void);
keymanager_t *kmgcry_gethandle(void);
keymanager_t *kmluks_gethandle(void);
keymanager_t *init_keymanager(keymanager_t *km);

/* List of all available key-managers (to be constructed later): */
static keymanager_t *keymgrs = NULL;


/*
 *  ==== Raw key-management routines ====
 */

static int kmraw_init_algs(void)
{
    return 0;
}


static int kmraw_free_algs(void)
{
    return 0;
}


static int kmraw_bind(bound_tgtdefn_t *bound, FILE *fp_key)
{   keyinfo_t *keyinfo = &bound->tgt->key;
    int compat = 0;

    if (keyinfo->format != NULL) {
        compat = (strcmp(keyinfo->format, "raw") == 0);
    } else {
        if (keyinfo->cipheralg != NULL) {
            return (strcmp(keyinfo->cipheralg, "none") == 0);
        }
    }

    if (compat) {
        if (keyinfo->digestalg == NULL) {
            keyinfo->digestalg = cm_strdup("none");
        }

        if (keyinfo->cipheralg == NULL) {
            keyinfo->cipheralg = cm_strdup("none");
        }
    }

    return compat;
}


static unsigned kmraw_get_properties(const bound_tgtdefn_t *boundtgt)
{   struct stat sbuff;
    unsigned props;

    /* We must flag that we have no password & have fixed location,
       otherwise keyfile=/dev/random could be renamed on password-changing! */
    props = KM_PROP_NEEDSKEYFILE | KM_PROP_FIXEDLOC;

    if (stat(boundtgt->tgt->key.filename, &sbuff) == 0) {
        props |= KM_PROP_FORMATTED;
    }

    return props;
}


static int kmraw_get_key(bound_tgtdefn_t *boundtgt,
            const km_pw_context_t *pw_ctxt,
            uint8_t **key, int *keylen, FILE *fp_key)
    /** Extract key from unencrypted (plain) file */
{   const keyinfo_t *keyinfo = &boundtgt->tgt->key;
    enum { BUFFSZ=512 };
    char buff[BUFFSZ];
    size_t len, lmt;
    int eflag=ERR_NOERROR;

    *key = NULL; *keylen = 0;

    if (fp_key == NULL) {
        eflag = ERR_BADFILE;
        goto bail_out;
    }

    /* Read data directly from keyfile: */
    for (;;) {
        lmt = (keyinfo->maxlen > 0 && (*keylen + BUFFSZ) > keyinfo->maxlen
                ? (size_t)(keyinfo->maxlen - *keylen) : (size_t)BUFFSZ);
        len = fread((void*)buff, (size_t)1, (size_t)lmt, fp_key);
        if (len == 0) break;

        /* Copy new block of data onto end of current key: */
        *key = (uint8_t*)sec_realloc((void*)*key, (size_t)(*keylen+len));
        memcpy((void*)(*key + *keylen), (const void*)buff, len);
        *keylen += len;
    }

    if (ferror(fp_key) != 0) {
        fprintf(stderr, _("Key-extraction failed for \"%s\"\n"),
                keyinfo->filename);
        /* This is a trivial case of decryption failure: */
        eflag = ERR_BADDECRYPT;
    }

  bail_out:

    return eflag;
}


static int kmraw_put_key(bound_tgtdefn_t *boundtgt,
            const km_pw_context_t *pw_ctxt,
            const uint8_t *key, const int keylen, FILE *fp_key)
    /** Store key in unencrypted (plain) file */
{   const keyinfo_t *keyinfo = &boundtgt->tgt->key;
    int eflag=ERR_NOERROR;

    /* Write data directly into keyfile: */
    if (cm_fwrite((const void*)key, (size_t)keylen, fp_key) != 0
      || ferror(fp_key) != 0) {
        fprintf(stderr, _("Key-writing failed for \"%s\"\n"),
                keyinfo->filename);
        eflag = ERR_BADENCRYPT;
    }

    return eflag;
}


static keymanager_t keymgr_raw = {
    "raw", 0,       kmraw_init_algs, kmraw_free_algs,
                    kmraw_bind, kmraw_get_properties,
                    kmraw_get_key, kmraw_put_key,
    NULL
#ifdef TESTING
    , NULL, NULL, CM_HASLEGACY
#endif
};



/*
 *  ==== Abstract key-management interfaces ====
 */

static keymanager_t **add_keymgr(keymanager_t **ptr, keymanager_t *km)
    /* Add key-manager interface definition(s) to list of available managers */
{
    if (km == NULL) return ptr;

    *ptr = km;

    /* Allow for addend itself being a list of key-managers: */
    for (;;) {
#ifdef TESTING
        if (km->install_testctxt != NULL) km->install_testctxt(test_ctxtptr);
#endif
        if (km->next == NULL) break;
        km = km->next;
    }

    return &km->next;
}


static void build_keymgrs(void)
    /** Construct list of available key-managers */
{   keymanager_t **ptr;

    if (keymgrs != NULL) return;    /* already initialized */

    ptr = &keymgrs;
    ptr = add_keymgr(ptr, kmblti_gethandle());
    ptr = add_keymgr(ptr, kmgcry_gethandle());
    ptr = add_keymgr(ptr, kmluks_gethandle());
    ptr = add_keymgr(ptr, &keymgr_raw);
}


const char **get_keymgr_list(void)
    /** Construct list of key-manager names */
{   keymanager_t *km;
    const char **arr=NULL;
    int i, cnt;

    build_keymgrs();
    for (km=keymgrs,cnt=0; km!=NULL; km=km->next,++cnt);

    arr = (const char**)malloc((size_t)((cnt+1)*sizeof(const char*)));
    for (i=0,km=keymgrs; i<cnt; km=km->next,++i) {
        arr[i] = km->ident;
    }
    arr[i] = NULL;

    return arr;
}


keymanager_t *init_keymanager(keymanager_t *km)
{
    if (km != NULL) {
        if ((km->initialized & KM_INIT_ALGS) == 0) {
            if (km->init_algs() == 0) {
                km->initialized |= KM_INIT_ALGS;
            } else {
                fprintf(stderr, "Failed to initialize keymanager \"%s\"\n",
                        km->ident);
            }
        }
    }

    return km;
}


int free_keymanagers(void)
{   keymanager_t *km;

    for (km=keymgrs; km!=NULL; km=km->next) {
        if ((km->initialized & KM_INIT_ALGS) != 0) {
            km->free_algs();
            km->initialized = 0;
        }
    }

    return 0;
}


bound_tgtdefn_t *alloc_boundtgt(const tgtdefn_t *tgt)
{   bound_tgtdefn_t *bound;

    bound = (bound_tgtdefn_t*)malloc(sizeof(bound_tgtdefn_t));
    bound->tgt = clone_tgtdefn(tgt);
    bound->keymgr = NULL;
    bound->km_data = NULL;

    return bound;
}


void free_boundtgt(bound_tgtdefn_t *boundtgt)
{
    if (boundtgt == NULL) return;

    free_tgtdefn(boundtgt->tgt);

    if (boundtgt->km_data != NULL) free((void*)boundtgt->km_data);

    free((void*)boundtgt);
}


bound_tgtdefn_t *bind_tgtdefn(const tgtdefn_t *tgt)
    /** Find keymanager that is able to handle given target & keyfile */
{   bound_tgtdefn_t *bound;
    keymanager_t *km;
    FILE *fp_key=NULL;

    if (tgt == NULL) return NULL;

    build_keymgrs();
    bound = alloc_boundtgt(tgt);
    if (tgt->key.filename != NULL) {
        fp_key = fopen(tgt->key.filename, "rb");
    }

    km = keymgrs;
    while (km != NULL) {
        if (fp_key != NULL) (void)fseek(fp_key, 0L, SEEK_SET);
        if (km->bind(bound, fp_key)) {
            bound->keymgr = init_keymanager(km);
            break;
        }
        km = km->next;
    }

    if (bound->keymgr == NULL) {
        free_boundtgt(bound);
        bound = NULL;
    }

    if (fp_key != NULL) fclose(fp_key);

    return bound;
}


/*!
 *  Extract the filesystem encryption key for a particular target.
 *
 *  This delegates most functionality to the methods defined
 *  in the \ref keymanager_t structure.
 */
int cm_get_key(bound_tgtdefn_t *boundtgt, const km_pw_context_t *pw_ctxt,
               uint8_t **key, int *keylen)
{   keyinfo_t *keyinfo = &boundtgt->tgt->key;
    FILE *fp = NULL;
    unsigned props, attempts = 0;
    int eflag=ERR_NOERROR;

    if (keyinfo->filename != NULL) {
        fp = fopen(keyinfo->filename, "rb");
        if (fp == NULL) {
            fprintf(stderr,
                _("Failed to open keyfile \"%s\" for target \"%s\"\n"),
                keyinfo->filename, boundtgt->tgt->ident);
            eflag = ERR_BADFILE;
            goto bail_out;
        }
    } else {
        props = boundtgt->keymgr->get_properties(boundtgt);
        if ((props & KM_PROP_NEEDSKEYFILE) != 0) {
            fprintf(stderr, _("Missing keyfile for target \"%s\"\n"),
                boundtgt->tgt->ident);
            eflag = ERR_BADFILE;
            goto bail_out;
        }
    }

    do {
        if (fp != NULL) (void)fseek(fp, 0L, SEEK_SET);
        eflag = boundtgt->keymgr->get_key(boundtgt, pw_ctxt, key, keylen, fp);
        if (eflag == ERR_BADDECRYPT) sleep(1);
    } while (++attempts < keyinfo->retries && eflag == ERR_BADDECRYPT);

  bail_out:
    if (fp != NULL) fclose(fp);

    return eflag;
}


int cm_put_key(bound_tgtdefn_t *boundtgt, const km_pw_context_t *pw_ctxt,
            const uint8_t *key, const int keylen, FILE *fp_key)
{   unsigned props;
    int eflag = ERR_NOERROR;

    props = boundtgt->keymgr->get_properties(boundtgt);
    if ((props & KM_PROP_NEEDSKEYFILE) != 0 && fp_key == NULL) {
        fprintf(stderr, _("Missing output keyfile for target \"%s\"\n"),
                boundtgt->tgt->ident);
        return ERR_BADFILE;
    }

    eflag = boundtgt->keymgr->put_key(boundtgt, pw_ctxt, key, keylen, fp_key);

    if (fp_key != NULL) {
      int fd = fileno(fp_key);
#if HAVE_SYNCFS
      syncfs(fd);
#else
      fsync(fd);
#endif
    }

    return eflag;
}


unsigned cm_get_keyproperties(const bound_tgtdefn_t *boundtgt)
    /** Extract information about key, e.g. whether encrypted */
{   unsigned props;

    if (boundtgt != NULL && boundtgt->keymgr != NULL) {
        props = boundtgt->keymgr->get_properties(boundtgt);
    } else {
        /* Safest to assume that key shouldn't be overwritten: */
        props = KM_PROP_FIXEDLOC | KM_PROP_FORMATTED;
    }

    return props;
}



#ifdef TESTING

/*! \addtogroup unit_tests
 *  @{ */

const char *km_legacy_key = "cryptmount012345";
const char *km_legacy_passwd = "nothing";

int km_test_managers(void)
{   keymanager_t *km;
    int flg = 0;

    build_keymgrs();

    for (km=keymgrs; km!=NULL; km=km->next) {
        if (km->run_tests == NULL) continue;

        km->init_algs();
        flg |= km->run_tests();
    }

#if 0
    km_archive_keys();
#endif

    return flg;
}


int km_test_keyrw(void)
    /* Test key read-writing (creation/extraction) */
{   enum { MAXKEY=256 };
    const keymanager_t *km;
    tgtdefn_t *target;
    bound_tgtdefn_t *bound=NULL;
    int i, keylen=0, keylen1, eflag;
    char str[256];
    uint8_t key0[MAXKEY], *key1=NULL;
    FILE *fp;
    extern cm_testinfo_t *test_ctxtptr;

    CM_TEST_START("Key read-write");

    build_keymgrs();
    for (km=keymgrs; km!=NULL; km=km->next) {
        if ((km->test_flags & CM_READONLY) != 0) continue;
        km->init_algs();

        target = alloc_tgtdefn(NULL);
        target->key.format = cm_strdup(km->ident);
        target->key.filename = cm_strdup("NOWHERE");
        target->key.digestalg = NULL;
        target->key.cipheralg = NULL;
        target->key.maxlen = -1;

        for (keylen=1; keylen<=MAXKEY; keylen<<=2) {
            sprintf(str, "Key read-write, %s, keylen=%d",
                km->ident, keylen);
            CM_TEST_IDENT(str);

            /* Generate (low-entropy) key: */
            for (i=0; i<keylen; ++i) {
                key0[i] = (i * 0x9d) ^ ((keylen * (unsigned long)km) % 253);
            }

            /* Write key to file: */
            fp = tmpfile();
            if (fp == NULL) CM_TEST_ABORT(context);
            bound = alloc_boundtgt(target);
            if (!km->bind(bound, fp)) CM_TEST_FAIL();
            eflag = km->put_key(bound, NULL, key0, keylen, fp);
            if (eflag != ERR_NOTSUPPORTED) {
                CM_ASSERT_EQUAL(ERR_NOERROR, eflag);

                key1 = NULL; keylen1 = -keylen;

                /* Try reading key back from file: */
                rewind(fp);
                eflag = km->get_key(bound, NULL, &key1, &keylen1, fp);
                CM_ASSERT_EQUAL(ERR_NOERROR, eflag);
                CM_ASSERT_EQUAL(keylen, keylen1);
                CM_ASSERT_DIFFERENT(key0, key1);
                CM_ASSERT_DIFFERENT(NULL, key1);
                for (i=0; i<keylen; ++i) {
                    CM_ASSERT_EQUAL(key0[i], key1[i]);
                }
            }

            if (bound != NULL) free_boundtgt(bound);
            if (fp != NULL) fclose(fp);
            if (key1 != NULL) {
                sec_free((void*)key1);
                key1 = NULL;
            }
        }

        km->free_algs();
        free_tgtdefn(target);
    }
    CM_ASSERT_DIFFERENT(keylen, 0);

    CM_TEST_OK(context);
}


int km_archive_keys(void)
    /** Generate fixed-pattern keys for testing reading by later releases */
{   keymanager_t *km;
    tgtdefn_t *target;
    bound_tgtdefn_t *bound=NULL;
    FILE *fp;
    int flg = 0;
    char filename[256];
    km_pw_context_t pw_ctxt;

    pw_ctxt.fd_pw_source = NULL;
    pw_ctxt.argpasswd[0] = pw_ctxt.argpasswd[1] = km_legacy_passwd;

    build_keymgrs();
    for (km=keymgrs; km!=NULL; km=km->next) {
        if ((km->test_flags & CM_READONLY) != 0) continue;
        km->init_algs();

        target = alloc_tgtdefn(NULL);
        target->key.format = cm_strdup(km->ident);
        target->key.filename = NULL;
        target->key.digestalg = NULL;
        target->key.cipheralg = NULL;
        target->key.maxlen = -1;

        bound = alloc_boundtgt(target);
        km->bind(bound, NULL);
        sprintf(filename, "/tmp/%s_%s_%s_%s_0", PACKAGE_VERSION, km->ident,
                        bound->tgt->key.digestalg, bound->tgt->key.cipheralg);
        bound->tgt->key.filename = cm_strdup(filename);

        /* Write key to file: */
        fp = fopen(filename, "wb");     /* May need to be "r+b" for LUKS */
        flg |= km->put_key(bound, &pw_ctxt,
                        (const uint8_t*)km_legacy_key,
                        strlen(km_legacy_key), fp);
        fclose(fp);

        if (bound != NULL) free_boundtgt(bound);
        km->free_algs();
        free_tgtdefn(target);
    }

    return flg;
}


int km_test_legacy(void)
    /** Check that keyfiles from earlier releases can be read */
{   keymanager_t *km;
    glob_t keyfiles;
    struct stat sbuff;
    tgtdefn_t *target;
    bound_tgtdefn_t *bound=NULL;
    km_pw_context_t pw_ctxt;
    uint8_t *key=NULL;
    int idx, n_legacy = 0, keylen, flg;
    char *tokbuff, keyglob[1024];
    const char *basepath;

    CM_TEST_START("Legacy key support");

    pw_ctxt.fd_pw_source = NULL;
    pw_ctxt.verify = 0;
    pw_ctxt.argpasswd[0] = pw_ctxt.argpasswd[1] = km_legacy_passwd;

    snprintf(keyglob, sizeof(keyglob), CM_SRCDIR "/testing/keys/[0-9]*[0-9]");
    glob(keyglob, 0, NULL, &keyfiles);

    for (km=keymgrs; km!=NULL; km=km->next) {
        km->initialized &= ~KM_TESTED;
    }

    for (idx=0; idx<(int)keyfiles.gl_pathc; ++idx) {
        const char *keypath = keyfiles.gl_pathv[idx];

        if (stat(keypath, &sbuff) != 0) CM_TEST_FAIL();
        if (!S_ISREG(sbuff.st_mode)) continue;
        ++n_legacy;

        strcpy(keyglob, keypath);
        basepath = basename(keyglob);
        tokbuff = cm_strdup(basepath);
        (void)strtok(tokbuff, "_");

        target = alloc_tgtdefn(NULL);
        target->ident = cm_strdup(basepath);
        target->key.format = cm_strdup(strtok(NULL, "_"));
        target->key.filename = cm_strdup(keypath);
        target->key.digestalg = cm_strdup(strtok(NULL, "_"));
        target->key.cipheralg = cm_strdup(strtok(NULL, "_"));

        bound = bind_tgtdefn(target);
        if (bound != NULL) {
            ((keymanager_t*)bound->keymgr)->initialized |= KM_TESTED;
        } else {
            continue;   /* No available key manager - possibly not compiled? */
        }

        key = NULL;
        keylen = 0;
        flg = cm_get_key(bound, &pw_ctxt, &key, &keylen);
        if (flg == ERR_BADDEVICE && getuid() != 0) {
            fprintf(stderr, "Skipping \"%s\" (after %d keys) - possibly requires root privileges\n", keypath, (n_legacy - 1));
            goto skip_jail;
        }
        CM_ASSERT_EQUAL(ERR_NOERROR, flg);

        CM_ASSERT_EQUAL(strlen(km_legacy_key), keylen);
        if (key != NULL) {
            CM_ASSERT_EQUAL(0, memcmp(key, km_legacy_key, (size_t)keylen));
        } else {
            CM_TEST_FAIL();
        }

  skip_jail:

        if (key != NULL) sec_free((void*)key);
        if (bound != NULL) free_boundtgt(bound);
        if (target != NULL) free_tgtdefn(target);

        free((void*)tokbuff);
    }
    globfree(&keyfiles);

    if (n_legacy < 4) CM_TEST_FAIL();

    /* Check that all available keymanagers with legacy keys have been tested */
    for (km=keymgrs; km!=NULL; km=km->next) {
        if ((km->test_flags & CM_HASLEGACY) != 0
          && (km->initialized & KM_TESTED) == 0) {
            CM_TEST_FAIL();
        }
    }

    CM_TEST_OK();
}

/** @} */

#endif  /* TESTING */



/*
 *  ==== Miscellaneous routines ====
 */

size_t mk_key_string(const uint8_t *key, const size_t keylen, char *buff)
    /** Create text version of crypto key */
{   size_t i;

    for (i=0; i<keylen; ++i) {
        sprintf(buff+2*i, "%02x", (unsigned)(key[i]));
    }

    return (2 * keylen);
}


int sycheck_directory(const char *dirname)
    /** Check that permissions on directory are suitably restrictive */
{   struct stat sdir;

    memset(&sdir, 0, sizeof(sdir));

    /* Get information about directory (if present): */
    errno = 0;
    if (stat(dirname, &sdir) != 0) {
        if (errno == ENOENT) return ERR_NOERROR;
        fprintf(stderr, "Cannot open \"%s\"\n", dirname);
        return ERR_INSECURE;
    }

    /* Check file/directory ownerships: */
    if (sdir.st_uid != (uid_t)0) {
        fprintf(stderr, "\"%s\" must be owned by root\n", dirname);
        return ERR_INSECURE;
    }

    /* Check that directory isn't globally writable: */
    if (!S_ISDIR(sdir.st_mode) || (sdir.st_mode & S_IWOTH) != 0) {
        fprintf(stderr, "Lax permissions on \"%s\"\n", dirname);
        return ERR_INSECURE;
    }

    return ERR_NOERROR;
}


int sycheck_cmtab(const char *cmtab)
    /** Check that permissions on ${sysconfdir}/cryptmount/cmtab are sensible */
{   struct stat sfile;
    char *dirname=NULL;
    int pos, eflag=ERR_NOERROR;

    /* Extract directory name from cmtab filename: */
    pos = (int)strlen(cmtab);
    dirname = (char*)malloc((size_t)(pos + 1));
    for ( ; pos>0 && cmtab[pos-1] != '/'; --pos) dirname[pos] = '\0';
    while (--pos >= 0) dirname[pos] = cmtab[pos];
    eflag = sycheck_directory(dirname);
    if (eflag != ERR_NOERROR) goto bail_out;

    if (stat(cmtab,&sfile) != 0) {
        fprintf(stderr, "Cannot open \"%s\"\n", cmtab);
        eflag = ERR_INSECURE;
        goto bail_out;
    }

    /* Check file ownerships: */
    if (sfile.st_uid != (uid_t)0) {
        fprintf(stderr, "\"%s\" must be owned by root\n", cmtab);
        eflag = ERR_INSECURE;
        goto bail_out;
    }

    /* Check that file isn't globally writable: */
    if (!S_ISREG(sfile.st_mode) || (sfile.st_mode & S_IWOTH) != 0) {
        fprintf(stderr, "Lax permissions on \"%s\"\n", cmtab);
        eflag = ERR_INSECURE;
        goto bail_out;
    }

  bail_out:

    if (dirname != NULL) free((void*)dirname);

    return eflag;
}


static int sy_path(const char *path)
    /** Check whether pathname is considered secure */
{
    if (path == NULL) return ERR_NOERROR;
    if (path[0] == '/') return ERR_NOERROR;

    return ERR_INSECURE;
}

int sycheck_target(const tgtdefn_t *tgt)
    /** Check that paths within target-specification are sensible */
{   int eflag=ERR_NOERROR;

    if (tgt == NULL) return 0;

    eflag |= sy_path(tgt->dev);
    eflag |= sy_path(tgt->dir);
    eflag |= sy_path(tgt->key.filename);

    if (eflag != ERR_NOERROR) {
        fprintf(stderr, _("Specification for target \"%s\" contains non-absolute pathname\n"), tgt->ident);
    }

    return eflag;
}



/*
 *  ==== Mutex-locking on configuration directory ====
 */

static const char *cm_lock_filename = "_cryptmount_lock_";

int cm_mutex_lock(void)
    /** Try to acquire lock on configuration directory (via symlink marker) */
{   char *fname=NULL, ident[64];
    int eflag=ERR_BADMUTEX;
#if HAVE_NANOSLEEP
    int delay_ms;
    unsigned dither = ((size_t)&fname % 250) + 1;
    struct timespec delay;
#endif
    const unsigned MAX_ATTEMPTS = 10;

    (void)cm_path(&fname, CM_SYSRUN_PFX, cm_lock_filename);
    snprintf(ident, sizeof(ident), "%u-%u",
             (unsigned)getpid(), (unsigned)getuid());

    for (unsigned attempt=0; attempt<MAX_ATTEMPTS; ++attempt) {
        errno = 0;
        if (symlink(ident, fname) == 0) {
            /* Lock acquired */
            eflag = 0; break;
        } else {
            if (errno == EEXIST) {
                /* Try again later */
#if HAVE_NANOSLEEP
                delay_ms = 53 + attempt * (dither + attempt * 19);
                dither = (dither * 213) % 251;
                delay.tv_sec = (delay_ms / 1000);
                delay.tv_nsec = (delay_ms % 1000) * 1000L * 1000L;
                nanosleep(&delay, NULL);
#else
                sleep(1);
#endif
            }
            else break;     /* failed to make link for more peculiar reason */
        }
    }

    if (eflag != 0) {
        fprintf(stderr, "Failed to create lock-file \"%s\" (errno=%d)\n",
                fname, errno);
    }

    free((void*)fname);

    return eflag;
}

/**
 *  Release an inter-process lock on configuration directory.
 *
 *  \see cm_mutex_lock().
 */
int cm_mutex_unlock(void)
{   char *fname=NULL;
    struct stat sbuff;
    int eflag=0;

    (void)cm_path(&fname, CM_SYSRUN_PFX, cm_lock_filename);

    if (lstat(fname, &sbuff) != 0
      || !S_ISLNK(sbuff.st_mode)
      || unlink(fname) != 0) {
        fprintf(stderr, "Failed to remove lock-file \"%s\"\n", fname);
        eflag = ERR_BADMUTEX;
    }

    free((void*)fname);

    return eflag;
}

/** @} */

/*
 *  (C)Copyright 2005-2022, RW Penney
 */
