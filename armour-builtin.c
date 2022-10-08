/*
 *  Methods for encryption/security mechanisms for cryptmount
 *  (C)Copyright 2007-2022, RW Penney
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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "armour.h"
#include "blowfish.h"
#include "cryptmount.h"
#include "utils.h"
#ifdef TESTING
#  include "cmtesting.h"
#endif

/*! \addtogroup keymgrs
 *  @{ */


typedef struct {
    unsigned fversion;    /*!< File-format version, default==1 since version 4.0 */
} blti_overrides_t;


/*
 *  ==== Built-in sha1/blowfish key-management routines ====
 */


/*
 *  Keyfile format is:
 *      char magic[7]="cm-blti";
 *      uchar version;
 *      uint16{LSB-first} keylength;
 *      uint32{LSB-first} hash-iterations (version>=1);
 *      char salt[kmblti_saltlen];
 *      [64-bit block][64-bit block][...];
 *      uint64{LSB-first} xor-checksum of key
 */

static const char kmblti_magstr[]="cm-blti";
static const uint8_t kmblti_version = (uint8_t)1;
static const size_t kmblti_maglen = 7;  /* = strlen(kmblti_magstr) */
enum {
    kmblti_saltlen = 10,
    kmblti_default_iterations = 1 << 14
};


static int kmblti_checkversion(uint8_t fversion)
{
    if (fversion > kmblti_version) {
        fprintf(stderr, "Bad keyfile version [%d]\n", (int)fversion);
        return ERR_BADFILE;
    }

    return ERR_NOERROR;
}


static cm_bf_ctxt_t *kmblti_initcipher_v0(const uint8_t *salt,
        const char *pass, size_t passlen, uint32_t iv[2])
    /** Initialize cipher key (for file-format version-0) */
{   cm_bf_ctxt_t *ctxt;
    cm_sha1_ctxt_t *md;
    uint8_t *ckey = NULL;
    size_t ckeysz;
    int i;

    /* Generate cipher key by sha1-hashing password: */
    md = cm_sha1_init();
    for (i=16; i--; ) {
        cm_sha1_block(md, (const uint8_t*)pass, passlen);
        cm_sha1_block(md, salt, (size_t)kmblti_saltlen);
    }
    iv[0] = md->H[0];
    iv[1] = md->H[3];
    cm_sha1_block(md, salt, (size_t)kmblti_saltlen);
    cm_sha1_final(md, &ckey, &ckeysz);
    cm_sha1_free(md);

    /* Initialize Blowfish cipher with hashed password: */
    ctxt = cm_bf_init(ckey, ckeysz);
    sec_free((void*)ckey);

    return ctxt;
}


static cm_bf_ctxt_t *kmblti_initcipher_v1(const uint8_t *salt,
        const char *pass, size_t passlen, uint32_t iterations, uint32_t iv[2])
    /** Initialize cipher key (for file-format version-1) */
{   cm_bf_ctxt_t *ctxt;
    uint8_t *ckey = NULL;
    const size_t ckeysz = 56;

    cm_pwd_fortify(pass, iterations, salt, (size_t)kmblti_saltlen,
                   &ckey, ckeysz);

    iv[0] = pack_uint32(ckey + 48);
    iv[1] = pack_uint32(ckey + 52);

    /* Initialize Blowfish cipher with hashed password: */
    ctxt = cm_bf_init(ckey, ckeysz - 8);
    sec_free((void*)ckey);

    return ctxt;
}


static int kmblti_init_algs(void)
{
    /* Nothing needed */
    return 0;
}


static int kmblti_free_algs(void)
{
    /* Nothing needed */
    return 0;
}


static int kmblti_bind(bound_tgtdefn_t *bound, FILE *fp_key)
{   keyinfo_t *keyinfo = &bound->tgt->key;
    const char *fmtptr;
    char buff[32];
    int compat = 1;     /* Be prepared to act as default key-manager */

    if (keyinfo->format != NULL) {
        fmtptr = keyinfo->format;
        compat = cm_startswith(&fmtptr, "builtin");
        if (*fmtptr == ':') {
            /* Extract file-format version from suffix: */
            blti_overrides_t *bltior;
            bltior = (blti_overrides_t*)malloc(sizeof(blti_overrides_t));
            bltior->fversion = atoi(fmtptr + 1);
            bound->km_data = (void*)bltior;
        } else if (*fmtptr != '\0') compat = 0;
    } else {
        if (fp_key != NULL) {
            /* Check header of existing key-file: */
            buff[0] = '\0';
            compat = (cm_fread((void*)buff, kmblti_maglen, fp_key) == 0
                        && strncmp(buff, kmblti_magstr, kmblti_maglen) == 0);
        }
    }

    if (compat) {
        if (keyinfo->digestalg == NULL) {
            keyinfo->digestalg = cm_strdup("sha1");
        }

        if (keyinfo->cipheralg == NULL) {
            keyinfo->cipheralg = cm_strdup("blowfish-cbc");
        }
    }

    return compat;
}


static unsigned kmblti_get_properties(const bound_tgtdefn_t *boundtgt)
{
    return (KM_PROP_HASPASSWD | KM_PROP_NEEDSKEYFILE);
}


static int kmblti_get_key(bound_tgtdefn_t *boundtgt,
            const km_pw_context_t *pw_ctxt,
            uint8_t **key, int *keylen, FILE *fp_key)
    /** Extract key from sha1/blowfish encrypted file */
{   const keyinfo_t *keyinfo = &boundtgt->tgt->key;
    cm_bf_ctxt_t *ctxt;
    enum { BUFFSZ = 512 };
    uint8_t *hbuff = NULL, fversion, salt[kmblti_saltlen],
            *buff = NULL, *bptr;
    uint32_t iv[2], cv[2], pl[2], iterations = kmblti_default_iterations;
    char *passwd = NULL;
    uint32_t chksum, chksum0;
    int cnt, rd_errs=0, eflag=ERR_NOERROR;

    *key = NULL; *keylen = 0;

    eflag = km_get_passwd(boundtgt->tgt->ident, pw_ctxt, &passwd, 0, 0);
    if (eflag != ERR_NOERROR) goto bail_out;

    /* Read key header: */
    hbuff = (uint8_t*)malloc((size_t)(kmblti_maglen + 4));
    hbuff[0] = '\0';
    rd_errs += cm_fread((void*)hbuff, kmblti_maglen, fp_key);
    if (strncmp((const char*)hbuff, kmblti_magstr, kmblti_maglen) != 0) {
        fprintf(stderr, "Bad keyfile format (builtin)\n");
        eflag = ERR_BADFILE;
        goto bail_out;
    }
    rd_errs += cm_fread((void*)&fversion, (size_t)1, fp_key);
    eflag = kmblti_checkversion(fversion);
    if (eflag != ERR_NOERROR) goto bail_out;
    rd_errs += cm_fread((void*)hbuff, (size_t)2, fp_key);
    *keylen = pack_uint16(hbuff);

    /* Read iteration-count from keyfile: */
    if (fversion == 1) {
        rd_errs += cm_fread((void*)hbuff, (size_t)4, fp_key);
        iterations = pack_uint32(hbuff);
    }

    /* Read salt from keyfile: */
    rd_errs += cm_fread((void*)salt, sizeof(salt), fp_key);

    /* Read encrypted key from keyfile: */
    switch (fversion) {
        case 0:
            ctxt = kmblti_initcipher_v0(salt, passwd, strlen(passwd), iv);
            break;
        case 1: /* Fall-through: */
        default:
            ctxt = kmblti_initcipher_v1(salt, passwd, strlen(passwd),
                                        iterations, iv);
            break;
    }
    cnt = km_aug_keysz((unsigned)*keylen, 8u) / 8;
    buff = (uint8_t*)sec_realloc(buff, (size_t)(cnt * 8));
    rd_errs += cm_fread((void*)buff, (size_t)(8 * cnt), fp_key);
    bptr = buff;
    while (cnt--) {
        cv[0] = pack_uint32(bptr+4);
        cv[1] = pack_uint32(bptr);

        /* Apply cipher block-chaining: */
        pl[0] = cv[0];
        pl[1] = cv[1];
        cm_bf_decipher(ctxt, pl, pl+1);
        pl[0] ^= iv[0];
        pl[1] ^= iv[1];
        iv[0] = cv[0];
        iv[1] = cv[1];

        bptr[7] = (uint8_t)((pl[0] >> 24) & 0xff);
        bptr[6] = (uint8_t)((pl[0] >> 16) & 0xff);
        bptr[5] = (uint8_t)((pl[0] >> 8) & 0xff);
        bptr[4] = (uint8_t)(pl[0] & 0xff);
        bptr[3] = (uint8_t)((pl[1] >> 24) & 0xff);
        bptr[2] = (uint8_t)((pl[1] >> 16) & 0xff);
        bptr[1] = (uint8_t)((pl[1] >> 8) & 0xff);
        bptr[0] = (uint8_t)(pl[1] & 0xff);

        bptr += 8;
    }
    cm_bf_free(ctxt);

    /* Verify checksum: */
    if (!km_aug_verify(buff, (unsigned)*keylen, &chksum0, &chksum)) {
        switch (pw_ctxt->debug_level) {
            case 0:
                fprintf(stderr, _("Password mismatch when extracting key\n"));
                break;
            case 1:     /* fall through... */
            default:
                fprintf(stderr, "Checksum mismatch in keyfile (builtin, %x != %x)\n",
                        (unsigned)chksum, (unsigned)chksum0);
                break;
        }
        eflag = ERR_BADDECRYPT;
    }

    if (keyinfo->maxlen > 0 && *keylen > keyinfo->maxlen) {
        *keylen = keyinfo->maxlen;
    }
    *key = (uint8_t*)sec_realloc((void*)*key, (size_t)*keylen);
    memcpy(*key, buff, (size_t)*keylen);

    if (rd_errs > 0 || ferror(fp_key) != 0) {
        fprintf(stderr, _("Key-extraction failed for \"%s\"\n"),
                keyinfo->filename);
        eflag = ERR_BADFILE;
    }

  bail_out:

    if (buff != NULL) sec_free((void*)buff);
    if (passwd != NULL) sec_free((void*)passwd);
    if (hbuff != NULL) free((void*)hbuff);

    return eflag;
}


static int kmblti_put_key(bound_tgtdefn_t *boundtgt,
            const km_pw_context_t *pw_ctxt,
            const uint8_t *key, const int keylen, FILE *fp_key)
    /** Store key in sha1/blowfish encrypted file */
{   cm_bf_ctxt_t *ctxt;
    uint8_t fversion, salt[kmblti_saltlen], hbuff[4],
            *buff=NULL, *bptr;
    uint32_t iv[2], cv[2], iterations = kmblti_default_iterations;
    char *passwd=NULL;
    size_t buffsz;
    blti_overrides_t *bltior=NULL;
    int cnt, wr_errs=0, eflag=ERR_NOERROR;

    eflag = km_get_passwd(boundtgt->tgt->ident, pw_ctxt, &passwd, 1, 1);
    if (eflag != ERR_NOERROR) goto bail_out;

    fversion = kmblti_version;
    if (boundtgt->km_data != NULL) {
        bltior = (blti_overrides_t*)boundtgt->km_data;
        fversion = bltior->fversion;
    }
    eflag = kmblti_checkversion(fversion);
    if (eflag != ERR_NOERROR) goto bail_out;

    /* Write key header: */
    wr_errs += cm_fwrite((const void*)kmblti_magstr, kmblti_maglen, fp_key);
    wr_errs += cm_fwrite((const void*)&fversion, (size_t)1, fp_key);
    unpack_uint16(hbuff, (uint16_t)keylen);
    wr_errs += cm_fwrite((const void*)hbuff, (size_t)2, fp_key);

    /* Write iteration-count: */
    if (fversion == 1) {
        unpack_uint32(hbuff, iterations);
        wr_errs += cm_fwrite((const void*)hbuff, (size_t)4, fp_key);
    }

    /* Generate salt & record in key-file: */
    cm_generate_key(salt, sizeof(salt));
    wr_errs += cm_fwrite((const void*)salt, sizeof(salt), fp_key);

    /* Augment key with simple checksum: */
    buff = km_aug_key(key, (unsigned)keylen, 8u, &buffsz);

    /* Write encrypted key into keyfile: */
    switch (fversion) {
        case 0:
            ctxt = kmblti_initcipher_v0(salt, passwd, strlen(passwd), iv);
        case 1: /* Fall-through: */
        default:
            ctxt = kmblti_initcipher_v1(salt, passwd, strlen(passwd),
                                        iterations, iv);
            break;
    }
    cnt = buffsz / 8;
    bptr = buff;
    while (cnt--) {
        cv[0] = (((uint32_t)bptr[7]) << 24) | (((uint32_t)bptr[6]) << 16)
                | (((uint32_t)bptr[5]) << 8) | ((uint32_t)bptr[4]);
        cv[1] = (((uint32_t)bptr[3]) << 24) | (((uint32_t)bptr[2]) << 16)
                | (((uint32_t)bptr[1]) << 8) | ((uint32_t)bptr[0]);

        /* Apply cipher block-chaining: */
        cv[0] ^= iv[0];
        cv[1] ^= iv[1];
        cm_bf_encipher(ctxt, cv, cv+1);
        iv[0] = cv[0];
        iv[1] = cv[1];

        bptr[7] = (uint8_t)((cv[0] >> 24) & 0xff);
        bptr[6] = (uint8_t)((cv[0] >> 16) & 0xff);
        bptr[5] = (uint8_t)((cv[0] >> 8) & 0xff);
        bptr[4] = (uint8_t)(cv[0] & 0xff);
        bptr[3] = (uint8_t)((cv[1] >> 24) & 0xff);
        bptr[2] = (uint8_t)((cv[1] >> 16) & 0xff);
        bptr[1] = (uint8_t)((cv[1] >> 8) & 0xff);
        bptr[0] = (uint8_t)(cv[1] & 0xff);

        bptr += 8;
    }
    wr_errs += cm_fwrite((const void*)buff, buffsz, fp_key);
    cm_bf_free(ctxt);

    if (wr_errs > 0 || ferror(fp_key) != 0) {
        fprintf(stderr, _("Failed to create new key file\n"));
        eflag = ERR_BADFILE;
        goto bail_out;
    }

  bail_out:

    if (buff != NULL) sec_free((void*)buff);
    if (passwd != NULL) sec_free((void*)passwd);

    return eflag;
}



/*
 *  ==== Pure password based key-manager ====
 */

static int kmpswd_init_algs(void)
{
    /* Nothing needed */
    return 0;
}


static int kmpswd_free_algs(void)
{
    /* Nothing needed */
    return 0;
}


static int kmpswd_bind(bound_tgtdefn_t *bound, FILE *fp_key)
{   keyinfo_t *keyinfo = &bound->tgt->key;
    int compat = 0;

    if (keyinfo->format != NULL) {
        compat = (strcmp(keyinfo->format, "password") == 0);
    }

    if (compat) {
        if (keyinfo->digestalg == NULL) {
            keyinfo->digestalg = cm_strdup("sha1");
        }
    }

    return compat;
}


static unsigned kmpswd_get_properties(const bound_tgtdefn_t *boundtgt)
{
    return (KM_PROP_HASPASSWD | KM_PROP_FIXEDLOC | KM_PROP_FORMATTED);
}


static int kmpswd_get_key(bound_tgtdefn_t *boundtgt,
                          const km_pw_context_t *pw_ctxt,
                          uint8_t **key, int *keylen, FILE *fp_key)
{   const keyinfo_t *keyinfo = &boundtgt->tgt->key;
    char *passwd=NULL;
    int eflag=ERR_NOERROR;
    const unsigned iterations = 1 << 14;

    eflag = km_get_passwd(boundtgt->tgt->ident, pw_ctxt, &passwd, 0, 0);
    if (eflag != ERR_NOERROR) goto bail_out;

    *keylen = (keyinfo->maxlen >= 0 ? keyinfo->maxlen : 16);
    cm_pwd_fortify(passwd, iterations, NULL, 16, key, (size_t)*keylen);

    /* { size_t pos; fprintf(stderr,"pass-key: 0x"); for (pos=0; pos<*keylen; ++pos) fprintf(stderr,"%02x",(unsigned)(*key)[pos]); fprintf(stderr,"\n"); } */

  bail_out:

    if (passwd != NULL) sec_free((void*)passwd);

    return eflag;
}


static int kmpswd_put_key(bound_tgtdefn_t *boundtgt,
            const km_pw_context_t *pw_ctxt,
            const uint8_t *key, const int keylen, FILE *fp_key)
{
    /* This operation isn't valid for a pure-password key */

    return ERR_NOTSUPPORTED;
}



keymanager_t keymgr_pswd = {
    "password", 0,  kmpswd_init_algs, kmpswd_free_algs,
                    kmpswd_bind, kmpswd_get_properties,
                    kmpswd_get_key, kmpswd_put_key,
    NULL
#ifdef TESTING
    , NULL, NULL, 0
#endif
};


keymanager_t keymgr_blti = {
    "builtin", 0,   kmblti_init_algs, kmblti_free_algs,
                    kmblti_bind, kmblti_get_properties,
                    kmblti_get_key, kmblti_put_key,
    &keymgr_pswd
#ifdef TESTING
    , NULL, NULL, CM_HASLEGACY
#endif
};


keymanager_t *kmblti_gethandle(void)
{
    return &keymgr_blti;
}

/**  @} */

/*
 *  (C)Copyright 2007-2022, RW Penney
 */
