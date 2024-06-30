/*
 *  Methods for LUKS-related key-management for cryptmount
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "armour.h"
#include "cryptmount.h"
#include "dmutils.h"
#include "utils.h"
#ifdef TESTING
#  include "cmtesting.h"
#endif

/*! \addtogroup keymgrs
 *  @{ */


#ifndef GCRYPT_REQ_VERSION
#  define GCRYPT_REQ_VERSION "1.1.42"
#endif

typedef struct {
    unsigned keyslot;
} luks_overrides_t;


/*
 *  ==== LUKS key-management routines ====
 */

#if USE_LUKSCOMPAT
#    include <gcrypt.h>
#    include <libcryptsetup.h>


static int kmluks_hdrvalid(FILE *fp_key)
    /* Check whether a valid LUKS header is present */
{   const uint8_t luks_magic[] = { 'L','U','K','S', 0xba, 0xbe };
    const size_t magic_len = sizeof(luks_magic);
    char buff[32];
    int flg = 0;

    if (fp_key == NULL) return 0;

    if (cm_fread((void*)buff, magic_len, fp_key) == 0) {
        fseek(fp_key, -((long)magic_len), SEEK_CUR);
        flg = (strncmp(buff, (const char*)luks_magic,
                (size_t)magic_len) == 0);
    }

    return flg;
}


static void kmluks_splitmode(const char *fullname, char **cipher, char **mode)
    /* Split fully-qualified cipher name into algorithm + mode */
{   size_t divpos=0, nlen=0;
    const char *pos=fullname;

    if (*cipher != NULL) free((void*)*cipher);
    if (*mode != NULL) free((void*)*mode);
    *cipher = *mode = NULL;

    if (fullname != NULL) {
        /* Split name according to 'ALGO-MODE' pattern: */
        while (*pos != '\0' && *pos != '-') {
            ++pos; ++nlen; }
        divpos = nlen;
        while (*pos != '\0') {
            ++pos; ++nlen; }

        if (divpos > 0) {
            *cipher = (char*)malloc(divpos + 1);
            strncpy(*cipher, fullname, divpos); 
            (*cipher)[divpos] = '\0';
        }

        if (divpos < nlen) {
            *mode = (char*)malloc((nlen - divpos));
            strcpy(*mode, fullname + divpos + 1);
        }
    }

    if (*cipher == NULL) *cipher = cm_strdup("aes");
    if (*mode == NULL) *mode = cm_strdup("cbc-plain");
}


static int kmluks_init_algs()
{   static int done_secmem = 0;
    int flg = 0;

    if (!done_secmem || !gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
        if (!gcry_check_version(GCRYPT_REQ_VERSION)) return -1;

        /* Disable gcrypt secure-memory initialization as cryptmount makes
         * its own arrangements for locking pages in memory.
         * gcrypt secmem facilities will also drop setuid privileges,
         * which would conflict with device-mapper system calls
         * within cryptmount */
        (void)gcry_control(GCRYCTL_DISABLE_SECMEM);

        (void)gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

        done_secmem = 1;
    }

    return flg;
}


static int kmluks_free_algs()
{
    /* Nothing needed */
    return 0;
}


static int kmluks_bind(bound_tgtdefn_t *bound, FILE *fp_key)
{   int compat = 0;

    if (bound->tgt->key.format != NULL) {
        compat = (strcmp(bound->tgt->key.format, "luks") == 0);
    } else {
        /* Check header of existing key-file: */
        compat |= kmluks_hdrvalid(fp_key);
    }

    if (compat) {
        tgtdefn_t *tgt = bound->tgt;

        if (tgt->key.filename == NULL && tgt->dev != NULL) {
            tgt->key.filename = cm_strdup(tgt->dev);
        }

        if (tgt->key.digestalg == NULL) {
            tgt->key.digestalg = cm_strdup("sha1");
        }

        if (tgt->key.cipheralg == NULL) {
            tgt->key.cipheralg = cm_strdup("aes128");
        }
    }

    return compat;
}


static unsigned kmluks_get_properties(const bound_tgtdefn_t *boundtgt)
{   unsigned props;
    FILE *fp;

    props = KM_PROP_HASPASSWD | KM_PROP_FIXEDLOC;

    fp = fopen(boundtgt->tgt->key.filename, "rb");
    if (fp != NULL) {
        if (kmluks_hdrvalid(fp)) {
            props |= KM_PROP_FORMATTED;
        }
        fclose(fp);
    }

    return props;
}


/*! @brief Change UID to match EUID when mounting via loopback device
 *
 *  This is a workaround for recent versions of libcryptsetup
 *  (since January 2017), which check that both uid==0 and euid==0
 *  before attempting to create a loopback device
 *  for a filesystem in an ordinary file. Setting up the loopback
 *  device usually only requires euid==0.
 *
 *  For filesystems in ordinary block devices, this function has no effect.
 *  Otherwise, this will call setuid() to attempt to make uid==euid==0,
 *  which appears to be an irreversible change, so will persist
 *  across any other actions taken by cryptmount within the same process.
 *
 *  @returns The previous value of UID.
 */
static uid_t luks_patch_uid(const bound_tgtdefn_t* boundtgt)
{   const uid_t olduid = getuid();
    const char* filename = boundtgt->tgt->key.filename;
    struct stat sbuff;

    if (stat(filename, &sbuff) == 0
        && S_ISREG(sbuff.st_mode)) {
        if (setuid(geteuid()) != 0) {
          fprintf(stderr, _("Failed to acquire privileges for LUKS container\n"));
        }
    }

    return olduid;
}


/*! @brief Change the password associated with a given LUKS key-slot.
 *
 *  This will either create an entirely new keyslot with the given password,
 *  or attempt to change the password associated with a particular keyslot
 *  while taking a temporary backup of the key in that slot. This requires
 *  that there is at least one spare keyslot available to take that backup.
 *
 *  @param key      The volume key for the LUKS device
 *  @param keyslot  Either CRYPT_ANY_SLOT or a nominated slot.
 *
 *  @return The slot associated with the new password.
 */
int kmluks_change_slot_passwd(struct crypt_device *cd, int keyslot,
                              const uint8_t *key, const int keylen,
                              const char *passwd)
{   const size_t passwdlen = strlen(passwd);
    int new_slot = -1, bckp_slot = -1, r;
    char logmsg[256];

    if (keyslot != CRYPT_ANY_SLOT) {
        bckp_slot = crypt_keyslot_add_by_volume_key(cd, CRYPT_ANY_SLOT,
                                                    (const char*)key, keylen,
                                                    passwd, passwdlen);
        if (bckp_slot < 0) return bckp_slot;
        r = crypt_keyslot_destroy(cd, keyslot);
        if (r < 0) return r;

        sprintf(logmsg, "kmluks created keyslot backup %d -> %d",
                        keyslot, bckp_slot);
        crypt_log(cd, CRYPT_LOG_NORMAL, logmsg);
    }

    new_slot = crypt_keyslot_add_by_volume_key(cd, keyslot,
                                               (const char*)key, keylen,
                                               passwd, passwdlen);
    if (new_slot < 0) return new_slot;
    sprintf(logmsg, "kmluks added keyslot %d", new_slot);
    crypt_log(cd, CRYPT_LOG_NORMAL, logmsg);

    if (keyslot != CRYPT_ANY_SLOT
          && bckp_slot >= 0 && bckp_slot != new_slot) {
        crypt_keyslot_destroy(cd, bckp_slot);

        sprintf(logmsg, "kmluks removed keyslot backup %d", bckp_slot);
        crypt_log(cd, CRYPT_LOG_NORMAL, logmsg);
    }

    return new_slot;
}


void kmluks_log(int level, const char *msg, void *data)
  /*! stderr-based logging function for libcryptsetup */
{
  fprintf(stderr, "LUKS[%d] - %s\n", level, msg);
}


static int kmluks_get_key(bound_tgtdefn_t *boundtgt,
            const km_pw_context_t *pw_ctxt,
            uint8_t **key, int *keylen, FILE *fp_key)
    /*! Extract key from LUKS header file */
{   tgtdefn_t *tgt = boundtgt->tgt;
    char *passwd = NULL, label[256];
    struct crypt_device *luks_ctxt = NULL;
    int slot = -1, eflag = ERR_NOERROR;
    luks_overrides_t *luksor;
    int64_t delta;
    size_t lcs_keylen = 256;
    const size_t namesz = 128;

    /* This is vulnerable to permission-issues created by libgcrypt
     *  -- see http://code.google.com/p/cryptsetup/issues/detail?id=47,
     * which are mitigated by kmluks_init_algs(). */

    luks_patch_uid(boundtgt);

    snprintf(label, sizeof(label), "cm-luks-tmp-%d-%x",
             getpid(), (unsigned)(size_t)tgt);

    eflag = km_get_passwd(tgt->ident, pw_ctxt, &passwd, 0, 0);
    if (eflag != ERR_NOERROR) goto bail_out;

    if (crypt_init(&luks_ctxt, tgt->key.filename) < 0
        || crypt_load(luks_ctxt, NULL, NULL) < 0) {
        fprintf(stderr, _("Failed to initialize device for LUKS keyfile\n"));
        eflag = ERR_BADDECRYPT;
        goto bail_out;
    }
    //crypt_set_log_callback(luks_ctxt, kmluks_log, NULL);  // FIXME - remove soon

    slot = crypt_activate_by_passphrase(luks_ctxt, label,
                                        CRYPT_ANY_SLOT, passwd, strlen(passwd),
                                        CRYPT_ACTIVATE_READONLY);
    if (slot < 0) {
        fprintf(stderr, _("Failed to extract LUKS key for \"%s\" (errno=%d)\n"),
                tgt->ident, -slot);
        eflag = ERR_BADDECRYPT;
        goto bail_out;
    }

    /* Extract cipher-algorithm parameters from LUKS header: */
    delta = (crypt_get_data_offset(luks_ctxt) - tgt->start);
    if (delta >= 0) {
        tgt->start += delta;
        if (tgt->length >= 0) tgt->length -= delta;
    }
    if (tgt->cipher != NULL) free((void*)tgt->cipher);
    tgt->cipher = (char*)malloc(namesz);
    snprintf(tgt->cipher, namesz, "%s-%s",
             crypt_get_cipher(luks_ctxt), crypt_get_cipher_mode(luks_ctxt));
    tgt->ivoffset = crypt_get_iv_offset(luks_ctxt);
    if (boundtgt->km_data != NULL) free((void*)boundtgt->km_data);
    luksor = (luks_overrides_t*)malloc(sizeof(luks_overrides_t));
    luksor->keyslot = slot;
    boundtgt->km_data = (void*)luksor;

    /* Take copy of LUKS master-key: */
    *key = (uint8_t*)sec_realloc((void*)*key, lcs_keylen);
    crypt_volume_key_get(luks_ctxt, slot, (char*)*key, &lcs_keylen,
                         passwd, strlen(passwd));
    *keylen = lcs_keylen;

  bail_out:

    crypt_deactivate(luks_ctxt, label);
    crypt_free(luks_ctxt);
    udev_settle();
    if (passwd != NULL) sec_free((void*)passwd);

    return eflag;
}


static int kmluks_put_key(bound_tgtdefn_t *boundtgt,
            const km_pw_context_t *pw_ctxt,
            const uint8_t *key, const int keylen, FILE *fp_key)
    /** Store or create key in LUKS header */
{
    const keyinfo_t *keyinfo = &boundtgt->tgt->key;
    char *passwd = NULL, *ciphername = NULL, *ciphermode = NULL;
    struct crypt_device *luks_ctxt = NULL;
    unsigned keyslot = 0;
    luks_overrides_t *luksor = NULL;
    int formatting = 0, r, eflag = ERR_NOERROR;

    formatting = (boundtgt->km_data == NULL) && !kmluks_hdrvalid(fp_key);

    if (boundtgt->km_data != NULL) {
        luksor = (luks_overrides_t*)boundtgt->km_data;
    }

    if (formatting) {
#ifndef TESTING
        char msgbuff[1024];
        snprintf(msgbuff, sizeof(msgbuff),
                _("Formatting \"%s\", will probably destroy all existing data"),
                keyinfo->filename);
        if (!cm_confirm(msgbuff)) {
            eflag = ERR_ABORT;
            goto bail_out;
        }
#endif  /* !TESTING */
    }

    eflag = km_get_passwd(boundtgt->tgt->ident, pw_ctxt, &passwd, 1, 1);
    if (eflag != ERR_NOERROR) goto bail_out;

    if (crypt_init(&luks_ctxt, keyinfo->filename) < 0) {
        fprintf(stderr, _("Failed to initialize device for LUKS keyfile\n"));
        eflag = ERR_BADDECRYPT;
        goto bail_out;
    }
    //crypt_set_log_callback(luks_ctxt, kmluks_log, NULL);  // FIXME - remove soon

    if (formatting) {
        struct crypt_params_luks1 luks_params = { boundtgt->tgt->key.digestalg,
                                                  0, NULL };

        kmluks_splitmode(boundtgt->tgt->cipher, &ciphername, &ciphermode);

        r = crypt_format(luks_ctxt, CRYPT_LUKS1,
                         ciphername, ciphermode, NULL,
                         (const char*)key, keylen, &luks_params);
        if (r < 0) {
            fprintf(stderr, _("Failed to create LUKS header for \"%s\"\n"),
                    boundtgt->tgt->ident);
            eflag = ERR_BADDEVICE;
            goto bail_out;
        }

        r = crypt_keyslot_add_by_volume_key(luks_ctxt, 0,
                                            (const char*)key, keylen,
                                            passwd, strlen(passwd));
        if (r < 0) {
          fprintf(stderr, _("Failed to create LUKS key for \"%s\"\n"),
                  boundtgt->tgt->ident);
        }
    } else {
        int lukserr = 0;

        keyslot = (luksor != NULL ? luksor->keyslot : 0);

        if (crypt_load(luks_ctxt, NULL, NULL) < 0) {
          eflag = ERR_BADDEVICE;
          goto bail_out;
        }

        printf(_("Setting password on LUKS keyslot-%u\n"), keyslot);
        lukserr = kmluks_change_slot_passwd(luks_ctxt, keyslot,
                                            key, keylen, passwd);
        if (lukserr < 0) {
            fprintf(stderr, "LUKS error code %d\n", -lukserr);
            eflag = ERR_BADENCRYPT;
            goto bail_out;
        }
    }

  bail_out:

    crypt_free(luks_ctxt);
    if (passwd != NULL) sec_free((void*)passwd);
    if (ciphername != NULL) free((void*)ciphername);
    if (ciphermode != NULL) free((void*)ciphermode);
    udev_settle();

    return eflag;
}


#  ifdef TESTING

static int kmluks_test_modesplit()
{   struct tcase {
        const char *orig, *cipher, *mode; };
    struct tcase tcases[] = {
        { "",                       "aes", "cbc-plain" },
        { "nothing",                "nothing", "cbc-plain" },
        { "alg-mode",               "alg", "mode" },
        { "blowfish-cfb-essiv",     "blowfish", "cfb-essiv" },
        { "-mode:suffix",           "aes", "mode:suffix" },
        { NULL,                     "aes", "cbc-plain" } };
    char *head=NULL, *tail=NULL;
    unsigned idx, cnt;

    CM_TEST_START("LUKS cipher-mode parsing");

    cnt = sizeof(tcases) / sizeof(struct tcase);
    for (idx=0; idx<cnt; ++idx) {
        kmluks_splitmode(tcases[idx].orig, &head, &tail);

        if (strcmp(head, tcases[idx].cipher) != 0) CM_TEST_FAIL();
        if (strcmp(tail, tcases[idx].mode) != 0) CM_TEST_FAIL();
    }
    if (head != NULL) free((void*)head);
    if (tail != NULL) free((void*)tail);

    CM_TEST_OK();

    return 0;
}

static void kmluks_testctxt(cm_testinfo_t *context)
{
    test_ctxtptr = context;
}

static int kmluks_runtests()
{   int flg = 0;

    flg |= kmluks_test_modesplit();

    return flg;
}

#  endif    /* TESTING */

keymanager_t keymgr_luks = {
    "luks", 0,   kmluks_init_algs, kmluks_free_algs,
                      kmluks_bind, kmluks_get_properties,
                      kmluks_get_key, kmluks_put_key,
    NULL
#ifdef TESTING
    , kmluks_testctxt, kmluks_runtests, (CM_READONLY | CM_HASLEGACY)
#endif
};

#endif  /* USE_LUKSCOMPAT */


keymanager_t *kmluks_gethandle()
{
#if USE_LUKSCOMPAT
    return &keymgr_luks;
#else
    return NULL;
#endif
}

/**  @} */

/*
 *  (C)Copyright 2005-2024, RW Penney
 */
