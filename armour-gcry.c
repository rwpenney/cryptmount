/*
 *  Methods for encryption/security mechanisms for cryptmount
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

#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "armour.h"
#include "cryptmount.h"
#include "utils.h"
#ifdef TESTING
#  include "cmtesting.h"
#endif

/*! \addtogroup keymgrs
 *  @{ */


/*
 *  ==== libgcrypt key-management routines ====
 */

#if HAVE_LIBGCRYPT
#  include <gcrypt.h>


/*
 *  Keyfile format is:
 *      char magic[7]="cm-gcry";
 *      char version;
 *      uint16{LSB-first} cipher_blocklength, keylength;
 *      char salt[kmgcry_saltlen];
 *      [block][block][block];
 *      (last block ends with uint32 xor-checksum of key
 *      (post-padded with zeros to next 4-byte boundary),
 *      post-padded with zeros to next cipher_blocklength boundary);
 */

const char kmgcry_magstr[]="cm-gcry",
            kmgcryossl_magstr[]="Salted__";
const char kmgcry_version = (char)0;
static const size_t kmgcry_maglen = 7,  /* = strlen(kmgcry_magstr) */
            kmgcryossl_maglen = 8;
enum {
    kmgcry_saltlen = 12,
    kmgcryossl_saltlen = 8
};


static struct kmgcry_mode {
    const char *name;
    unsigned mode; } kmgcry_modes[] = {
    { "aeswrap",  GCRY_CIPHER_MODE_AESWRAP },
    { "cbc",      GCRY_CIPHER_MODE_CBC },
    { "cfb",      GCRY_CIPHER_MODE_CFB },
    { "cfb8",     GCRY_CIPHER_MODE_CFB8 },
    { "ccm",      GCRY_CIPHER_MODE_CCM },
    { "ctr",      GCRY_CIPHER_MODE_CTR },
    { "ecb",      GCRY_CIPHER_MODE_ECB },
    { "gcm",      GCRY_CIPHER_MODE_GCM },
    { "ocb",      GCRY_CIPHER_MODE_OCB },
    { "ofb",      GCRY_CIPHER_MODE_OFB },
    { "poly1305", GCRY_CIPHER_MODE_POLY1305 },
#if GCRYPT_VERSION_NUMBER >= 0x010800
    { "xts",      GCRY_CIPHER_MODE_XTS },
#endif
    { NULL, GCRY_CIPHER_MODE_NONE }
};


static void kmgcry_tx_algnames(const keyinfo_t *keyinfo,
        char **algstr, char **modestr, char **dgststr)
    /* Parse/translate algorithm string into cipher/mode/digest fields */
{   char *buff=NULL, *pos;
    struct map_t {  /* map OpenSSL name to libgcrypt name, if different */
        const char *ssl_name, *gcy_name; }
        *mapent;
    struct map_t ctable[] = {
        { "aes-128",        "aes" },
        { "aes128",         "aes" },
        { "aes-192",        "aes192" },
        { "aes-256",        "aes256" },
        { "bf",             "blowfish" },
        { "camellia-128",   "camellia128" },
        { "camellia-192",   "camellia192" },
        { "camellia-256",   "camellia256" },
        { "cast",           "cast5" },
        { "des3",           "3des" },
        { NULL, NULL }
    };
    struct map_t htable[] = {
        { "rmd160",     "ripemd160" },
        { NULL, NULL }
    };
    const char *default_cipher="aes256", *default_mode="cbc",
               *default_hash="sha256";

    *algstr = NULL;
    *modestr = NULL;
    *dgststr = NULL;

    if (keyinfo->cipheralg != NULL && keyinfo->cipheralg[0] != '\0') {
        buff = cm_strdup(keyinfo->cipheralg);

        /* Extract cipher-mode from trailing -[^-]* of cipher-name: */
        pos = strrchr(buff, '-');
        if (pos != NULL) {
            *modestr = cm_strdup(pos + 1);
            *pos = '\0';
        }
        /* Translate cipher-name to canonical libgcrypt name: */
        for (mapent=ctable; mapent->ssl_name!=NULL; ++mapent) {
            if (cm_strcasecmp(buff, mapent->ssl_name) == 0) {
                *algstr = cm_strdup(mapent->gcy_name);
                break;
            }
        }
        if (*algstr == NULL) {
            *algstr = buff;
            buff = NULL;
        }
    }
    if (*algstr == NULL) *algstr = cm_strdup(default_cipher);
    if (*modestr == NULL) *modestr = cm_strdup(default_mode);


    if (keyinfo->digestalg != NULL && keyinfo->digestalg[0] != '\0') {
        /* Translate digest-name to canonical libgcrypt name: */
        for (mapent=htable; mapent->ssl_name!=NULL; ++mapent) {
            if (cm_strcasecmp(mapent->ssl_name, keyinfo->digestalg) == 0) {
                *dgststr = cm_strdup(mapent->gcy_name);
                break;
            }
        }
        if (*dgststr == NULL) *dgststr = cm_strdup(keyinfo->digestalg);
    }
    if (*dgststr == NULL) *dgststr = cm_strdup(default_hash);

    if (buff != NULL) free((void*)buff);
}


static int kmgcry_get_algos(const keyinfo_t *keyinfo,
                    int *cipher, int *ciphermode, int *digest)
    /* Get libgcrypt algorithms for encoding key */
{   char *algstr=NULL, *mdstr=NULL, *dgststr=NULL;
    struct kmgcry_mode *cmd;
    int eflag=ERR_NOERROR;

    kmgcry_tx_algnames(keyinfo, &algstr, &mdstr, &dgststr);

    *cipher = gcry_cipher_map_name(algstr);
    if (*cipher == 0) {
        fprintf(stderr, _("Couldn't find libgcrypt cipher \"%s\"\n"), algstr);
        eflag = ERR_BADALGORITHM;
        goto bail_out;
    }

    for (cmd=kmgcry_modes; cmd->name!=NULL; ++cmd) {
        if (cm_strcasecmp(cmd->name, mdstr) == 0) break;
    }
    if (cmd->name == NULL) {
      fprintf(stderr, _("Couldn't find libgcrypt cipher mode \"%s\" - using fallback\n"), mdstr);
    }
    *ciphermode = cmd->mode;

    *digest = gcry_md_map_name(dgststr);
    if (*digest == 0) {
        fprintf(stderr, _("Couldn't find libgcrypt digest \"%s\"\n"), dgststr);
        eflag = ERR_BADALGORITHM;
        goto bail_out;
    }

  bail_out:

    if (algstr != NULL) free((void*)algstr);
    if (mdstr != NULL) free((void*)mdstr);
    if (dgststr != NULL) free((void*)dgststr);

    return eflag;
}


#  ifdef TESTING

static int kmgcry_test_getalgos()
{   keyinfo_t keyinfo;
    int cipher=0, mode=0, digest=0, cnt;
    struct cmap {
        const char *cname, *dname;
        const int cipher, mode, digest; } *mapptr;
    struct cmap map[] = {
        { "aes-128-cfb",  "ripemd160",
            GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CFB, GCRY_MD_RMD160 },
        { "aes192-ECB",  "md4",
            GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_ECB, GCRY_MD_MD4 },
        { "bf-cbc", "rmd160",
            GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CBC, GCRY_MD_RMD160 },
        { "CAST5-CFB",  "ripemd160",
            GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_CFB, GCRY_MD_RMD160 },
        { "Camellia-128-cfb8",  "sha256",
            GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_CFB8, GCRY_MD_SHA256 },
#if GCRYPT_VERSION_NUMBER >= 0x010800
        { "ChaCha20-xts",  "blake2b_512",
            GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_XTS, GCRY_MD_BLAKE2B_512 },
#endif
        { "DES-ofb",  "md5",
            GCRY_CIPHER_DES, GCRY_CIPHER_MODE_OFB, GCRY_MD_MD5 },
        { "twofish",    "sha1",
            GCRY_CIPHER_TWOFISH, GCRY_CIPHER_MODE_CBC, GCRY_MD_SHA1 },
        { NULL, NULL, -1, -1, -1 }
    };

    CM_TEST_START("libgcrypt algorithm-identification");

    keyinfo.cipheralg = NULL;
    keyinfo.digestalg = NULL;
    CM_ASSERT_EQUAL(ERR_NOERROR,
        kmgcry_get_algos(&keyinfo, &cipher, &mode, &digest));
    CM_ASSERT_DIFFERENT(0, cipher);
    CM_ASSERT_DIFFERENT(0, mode);
    CM_ASSERT_DIFFERENT(0, digest);

    keyinfo.cipheralg = "";
    keyinfo.digestalg = "";
    CM_ASSERT_EQUAL(ERR_NOERROR,
        kmgcry_get_algos(&keyinfo, &cipher, &mode, &digest));

    for (mapptr=map,cnt=0; mapptr->cipher!=-1; ++mapptr,++cnt) {
        keyinfo.cipheralg = (char*)mapptr->cname;
        keyinfo.digestalg = (char*)mapptr->dname;
        CM_ASSERT_EQUAL(ERR_NOERROR,
            kmgcry_get_algos(&keyinfo, &cipher, &mode, &digest));
        CM_ASSERT_EQUAL(mapptr->cipher, cipher);
        CM_ASSERT_EQUAL(mapptr->mode, mode);
        CM_ASSERT_EQUAL(mapptr->digest, digest);
    }
    CM_ASSERT_DIFFERENT(0, cnt);

    CM_TEST_OK();
}

#  endif    /* TESTING */


typedef void kmgcry_keybuilder_t(gcry_md_hd_t md,
                    int digest, const size_t mdlen,
                    const uint8_t *salt,
                    const uint8_t *pass, const size_t passlen,
                    uint8_t *ckey, const size_t ckeysz,
                    uint8_t *civ, const size_t civsz);

static void kmgcry_keybuilder(gcry_md_hd_t md_hand,
                    int digest, const size_t mdlen,
                    const uint8_t *salt,
                    const uint8_t *pass, const size_t passlen,
                    uint8_t *ckey, const size_t ckeysz,
                    uint8_t *civ, const size_t civsz)
    /*! Generate cipher key & IV from password & salt (default variant) */
{   size_t kpos, ivpos, pos;
    uint8_t *buff;

    kpos = ivpos = 0;
    do {
        /* Fold-together password & salt using message-digest: */
        gcry_md_reset(md_hand);

        gcry_md_write(md_hand, (const void*)salt, (size_t)kmgcry_saltlen);
        gcry_md_write(md_hand, (const void*)pass, passlen);
        if (kpos > 0) {
            gcry_md_write(md_hand, (const void*)ckey, kpos); }
        if (ivpos > 0) {
            gcry_md_write(md_hand, (const void*)civ, ivpos); }
        buff = gcry_md_read(md_hand, digest);

        /* Transfer message digest into cipher key & initialization vector: */
        pos = 0;
        while (kpos < ckeysz && pos < mdlen) {
            ckey[kpos++] = buff[pos++]; }
        while (ivpos < civsz && pos < mdlen) {
            civ[ivpos++] = buff[pos++]; }
    } while (kpos < ckeysz || ivpos < civsz);
}


static void kmgcryossl_keybuilder(gcry_md_hd_t md_hand,
                    int digest, const size_t mdlen,
                    const uint8_t *salt,
                    const uint8_t *pass, const size_t passlen,
                    uint8_t *ckey, const size_t ckeysz,
                    uint8_t *civ, const size_t civsz)
    /*! Generate cipher key & IV from password & salt (a la OpenSSL) */
{   size_t kpos, ivpos, pos;
    uint8_t *buff, *prev=NULL;
    unsigned cnt=0;

    prev = (uint8_t*)sec_realloc(prev, mdlen);

    kpos = ivpos = 0;
    do {
        /* Fold-together password & salt using message-digest: */
        gcry_md_reset(md_hand);

        if (cnt > 0) {
            gcry_md_write(md_hand, (const void*)prev, mdlen);
        }
        gcry_md_write(md_hand, (const void*)pass, passlen);
        gcry_md_write(md_hand, (const void*)salt, kmgcryossl_saltlen);
        buff = gcry_md_read(md_hand, digest);

        /* Transfer message digest into cipher key & initialization vector: */
        pos = 0;
        while (kpos < ckeysz && pos < mdlen) {
            ckey[kpos++] = buff[pos++]; }
        while (ivpos < civsz && pos < mdlen) {
            civ[ivpos++] = buff[pos++]; }

        /* Keep copy of digest to add to next fold: */
        memcpy((void*)prev, (const void*)buff, mdlen);
        ++cnt;
    } while (kpos < ckeysz || ivpos < civsz);

    sec_free(prev);
}


static int kmgcry_initcipher(int cipher, int ciphermode, int digest,
            const uint8_t *salt, kmgcry_keybuilder_t keybuilder,
            const char *pass, size_t passlen, gcry_cipher_hd_t *hd)
    /*! Initialize block cipher from given password, salt & hashing scheme */
{   gcry_md_hd_t md_hand;
    size_t ckeysz, cblksz, mdlen;
    uint8_t *ckey=NULL, *civ=NULL;
    int eflag=ERR_BADALGORITHM;

    if (gcry_cipher_open(hd, cipher, ciphermode, 0) != 0) {
        fprintf(stderr, "Cannot open libgcrypt cipher[%d,%d]\n",
                cipher, ciphermode);
        goto bail_out;
    }

    (void)gcry_cipher_algo_info(cipher, GCRYCTL_GET_KEYLEN, NULL, &ckeysz);
    ckey = (uint8_t*)sec_realloc(ckey, ckeysz);
    (void)gcry_cipher_algo_info(cipher, GCRYCTL_GET_BLKLEN, NULL, &cblksz);
    civ = (uint8_t*)sec_realloc(civ, cblksz);

    /* generate cipher key & iv by hashing password: */
    if (keybuilder == NULL) keybuilder = kmgcry_keybuilder;
    if (gcry_md_open(&md_hand, digest, 0) != 0) {
        fprintf(stderr, "Cannot open libgcrypt digest[%d]\n", digest);
        goto bail_out;
    }
    mdlen = gcry_md_get_algo_dlen(digest);
    keybuilder(md_hand, digest, mdlen, salt,
            (const uint8_t*)pass, passlen, ckey, ckeysz, civ, cblksz);
    gcry_md_close(md_hand);

    /* setup cipher initial state: */
    if (gcry_cipher_setkey(*hd, (void*)ckey, ckeysz) != 0
      || gcry_cipher_setiv(*hd, (void*)civ, cblksz) != 0) {
        fprintf(stderr, "Failed to setup libgcrypt cipher iv[%d,%d]\n",
                (int)ckeysz, (int)cblksz);
        goto bail_out;
    }
    sec_free(ckey);
    sec_free(civ);

    eflag = ERR_NOERROR;

  bail_out:

    return eflag;
}


static int kmgcry_init_algs()
{
    if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
        (void)gcry_check_version(NULL);     /* Initializes library as side-effect */

        (void)gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    }

    return 0;
}


static int kmgcry_free_algs()
{
    /* Nothing needed */
    return 0;
}


static int kmgcry_bind(bound_tgtdefn_t *bound, FILE *fp_key)
{   keyinfo_t *keyinfo = &bound->tgt->key;
    char buff[32];
    int compat = 0;

    if (keyinfo->format != NULL) {
        compat = (strcmp(keyinfo->format, "libgcrypt") == 0);
    } else {
        if (fp_key != NULL) {
            /* Check header of existing key-file: */
            compat = (cm_fread((void*)buff, kmgcry_maglen, fp_key) == 0
                        && strncmp(buff, kmgcry_magstr, kmgcry_maglen) == 0);
        }
    }

    if (compat) {
        if (keyinfo->digestalg == NULL) {
            keyinfo->digestalg = cm_strdup("sha256");
        }

        if (keyinfo->cipheralg == NULL) {
#if GCRYPT_VERSION_NUMBER >= 0x010800
            keyinfo->cipheralg = cm_strdup("aes256-xts");
#else
            keyinfo->cipheralg = cm_strdup("aes256-cbc");
#endif
        }
    }

    return compat;
}


static int kmgcryossl_bind(bound_tgtdefn_t *bound, FILE *fp_key)
    /*! OpenSSL-compatibility version of kmgcy_bind */
{   keyinfo_t *keyinfo = &bound->tgt->key;
    char buff[32];
    int compat = 0;

    if (keyinfo->format != NULL) {
        compat |= (strcmp(keyinfo->format, "openssl-compat") == 0);
        compat |= (strcmp(keyinfo->format, "openssl") == 0);
    } else {
        if (fp_key != NULL) {
            /* Check header of existing key-file: */
            compat = (cm_fread((void*)buff, kmgcryossl_maglen, fp_key) == 0
                        && strncmp(buff, kmgcryossl_magstr, kmgcryossl_maglen) == 0);
        }
    }

    if (compat) {
        if (keyinfo->digestalg == NULL) {
            keyinfo->digestalg = cm_strdup("md5");
        }

        if (keyinfo->cipheralg == NULL) {
            keyinfo->cipheralg = cm_strdup("blowfish");
        }
    }

    return compat;
}


static unsigned kmgcry_get_properties(const bound_tgtdefn_t *boundtgt)
{
    return (KM_PROP_HASPASSWD | KM_PROP_NEEDSKEYFILE);
}


static int kmgcry_get_key(bound_tgtdefn_t *boundtgt,
            const km_pw_context_t *pw_ctxt,
            uint8_t **key, int *keylen, FILE *fp_key)
    /*! Extract key from libgcrypt-encrypted file */
{   const keyinfo_t *keyinfo = &boundtgt->tgt->key;
    gcry_cipher_hd_t chd;
    char *passwd=NULL;
    uint8_t *hbuff = NULL, salt[kmgcry_saltlen], *buff = NULL, *bptr;
    size_t cblksz;
    uint32_t chksum, chksum0;
    int cnt, rd_errs=0, cipher, ciphermode, digest, eflag=ERR_NOERROR;

    *key = NULL; *keylen = 0;
    hbuff = (uint8_t*)sec_realloc(hbuff, (kmgcry_maglen + 4));

    eflag = kmgcry_get_algos(keyinfo, &cipher, &ciphermode, &digest);
    if (eflag != ERR_NOERROR) goto bail_out;
    gcry_cipher_algo_info(cipher, GCRYCTL_GET_BLKLEN, NULL, &cblksz);

    eflag = km_get_passwd(boundtgt->tgt->ident, pw_ctxt, &passwd, 0, 0);
    if (eflag != ERR_NOERROR) goto bail_out;

    /* Read key header: */
    rd_errs += cm_fread((void*)hbuff, kmgcry_maglen, fp_key);
    if (strncmp((const char*)hbuff, kmgcry_magstr, kmgcry_maglen) != 0) {
        fprintf(stderr, _("Bad keyfile format (libgcrypt)\n"));
        eflag = ERR_BADFILE;
        goto bail_out;
    }
    rd_errs += cm_fread((void*)hbuff, (size_t)1, fp_key);
    if (hbuff[0] != '\0') {
        fprintf(stderr, "Bad keyfile version [%d]\n", (int)buff[0]);
        eflag = ERR_BADFILE;
        goto bail_out;
    }
    rd_errs += cm_fread((void*)hbuff, (size_t)4, fp_key);
    if (pack_uint16(hbuff) != cblksz) {
        fprintf(stderr, "Mismatched cipher block size\n");
        eflag = ERR_BADFILE;
        goto bail_out;
    }
    *keylen = pack_uint16(hbuff + 2);

    /* Read salt from keyfile: */
    rd_errs += cm_fread((void*)salt, sizeof(salt), fp_key);

    /* Read encrypted key from keyfile: */
    eflag = kmgcry_initcipher(cipher, ciphermode, digest,
                    salt, NULL, passwd, strlen(passwd), &chd);
    if (eflag != ERR_NOERROR) goto bail_out;
    cnt = km_aug_keysz((unsigned)*keylen, (unsigned)cblksz) / cblksz;
    buff = (uint8_t*)sec_realloc(buff, cnt * cblksz);
    bptr = buff;
    while (cnt--) {
        rd_errs += cm_fread((void*)bptr, cblksz, fp_key);
        gcry_cipher_decrypt(chd, (void*)bptr, cblksz, NULL, 0);
        bptr += cblksz;
    }
    gcry_cipher_close(chd);

    /* Verify checksum: */
    if (!km_aug_verify(buff, (unsigned)*keylen, &chksum0, &chksum)) {
        switch (pw_ctxt->debug_level) {
            case 0:
                fprintf(stderr, _("Password mismatch when extracting key\n"));
                break;
            case 1:     /* fall through... */
            default:
                fprintf(stderr, _("Checksum mismatch in keyfile (gcry, %x != %x)\n"),
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
    if (hbuff != NULL) sec_free((void*)hbuff);

    return eflag;
}


static int kmgcry_put_key(bound_tgtdefn_t *boundtgt,
            const km_pw_context_t *pw_ctxt,
            const uint8_t *key, const int keylen, FILE *fp_key)
    /*! Store key in libgcrypt-encrypted file */
{   const keyinfo_t *keyinfo = &boundtgt->tgt->key;
    gcry_cipher_hd_t chd;
    char *passwd=NULL;
    uint8_t hbuff[4], salt[kmgcry_saltlen], *buff=NULL, *bptr;
    size_t buffsz, cblksz;
    int cnt, wr_errs = 0, cipher, ciphermode, digest, eflag=ERR_NOERROR;

    eflag = kmgcry_get_algos(keyinfo, &cipher, &ciphermode, &digest);
    if (eflag != ERR_NOERROR) goto bail_out;
    gcry_cipher_algo_info(cipher, GCRYCTL_GET_BLKLEN, NULL, &cblksz);

    eflag = km_get_passwd(boundtgt->tgt->ident, pw_ctxt, &passwd, 1, 1);
    if (eflag != ERR_NOERROR) goto bail_out;

    /* Write key header: */
    wr_errs += cm_fwrite((const void*)kmgcry_magstr, kmgcry_maglen, fp_key);
    wr_errs += cm_fwrite((const void*)&kmgcry_version, (size_t)1, fp_key);
    unpack_uint16(hbuff, (uint16_t)cblksz);
    unpack_uint16(hbuff + 2, (uint16_t)keylen);
    wr_errs += cm_fwrite((const void*)hbuff, (size_t)4, fp_key);

    /* Generate salt & record in keyfile: */
    cm_generate_key(salt, sizeof(salt));
    wr_errs += cm_fwrite((const void*)salt, sizeof(salt), fp_key);

    /* Augment key with simple checksum: */
    buff = km_aug_key(key, (unsigned)keylen, (unsigned)cblksz, &buffsz);

    /* Write encrypted key into keyfile: */
    eflag = kmgcry_initcipher(cipher, ciphermode, digest,
                    salt, NULL, passwd, strlen(passwd), &chd);
    if (eflag != ERR_NOERROR) goto bail_out;
    cnt = buffsz / cblksz;
    bptr = buff;
    while (cnt--) {
        gcry_cipher_encrypt(chd, (void*)bptr, cblksz, NULL, 0);
        wr_errs += cm_fwrite((const void*)bptr, cblksz, fp_key);
        bptr += cblksz;
    }
    gcry_cipher_close(chd);

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


#if USE_GCRYOSSL

static int kmgcryossl_get_key(bound_tgtdefn_t *boundtgt,
            const km_pw_context_t *pw_ctxt,
            uint8_t **key, int *keylen, FILE *fp_key)
    /*! Extract key from OpenSSL-compatible file via libgcrypt */
{   const keyinfo_t *keyinfo = &boundtgt->tgt->key;
    gcry_cipher_hd_t chd;
    char *passwd=NULL;
    uint8_t *hbuff=NULL, salt[kmgcryossl_saltlen], *buff=NULL;
    size_t cblksz, buffsz=0, pos, ofs, idx;
    int kbad=0, cipher, ciphermode, digest,
        rd_errs=0, eflag=ERR_NOERROR;

    *key = NULL; *keylen = 0;
    hbuff = (uint8_t*)sec_realloc(hbuff, kmgcryossl_maglen);

    eflag = kmgcry_get_algos(keyinfo, &cipher, &ciphermode, &digest);
    if (eflag != ERR_NOERROR) goto bail_out;
    gcry_cipher_algo_info(cipher, GCRYCTL_GET_BLKLEN, NULL, &cblksz);

    eflag = km_get_passwd(boundtgt->tgt->ident, pw_ctxt, &passwd, 0, 0);
    if (eflag != ERR_NOERROR) goto bail_out;

    /* Read key header: */
    rd_errs += cm_fread((void*)hbuff, kmgcryossl_maglen, fp_key);
    if (strncmp((const char*)hbuff, kmgcryossl_magstr, kmgcryossl_maglen) != 0) {
        fprintf(stderr, _("Bad keyfile format (openssl-compat)\n"));
        eflag = ERR_BADFILE;
        goto bail_out;
    }

    /* Read salt from keyfile: */
    rd_errs += cm_fread((void*)salt, sizeof(salt), fp_key);

    /* read encrypted key from keyfile: */
    eflag = kmgcry_initcipher(cipher, ciphermode, digest,
                    salt, kmgcryossl_keybuilder, passwd, strlen(passwd), &chd);
    if (eflag != ERR_NOERROR) goto bail_out;
    pos = 0;
    while (!feof(fp_key)) {
        if ((pos + cblksz) > buffsz) {
            buffsz = (buffsz * 2) + 4 * cblksz;
            buff = (uint8_t*)sec_realloc(buff, buffsz);
        }
        if (cm_fread((void*)(buff + pos), cblksz, fp_key) != 0) break;
        gcry_cipher_decrypt(chd, (void*)(buff + pos), cblksz, NULL, 0);
        pos += cblksz;
    }
    gcry_cipher_close(chd);

    /* Remove & check end-marker from key-data: */
    ofs = 0; idx = 0; kbad = 0;
    if (pos > 0) ofs = buff[pos - 1]; else kbad |= 1;
    if (ofs > cblksz) kbad |= 1;
    while (idx < ofs && !kbad) {
        kbad |= (buff[--pos] != ofs);
        ++idx;
    }
    if (kbad) {
        switch (pw_ctxt->debug_level) {
            case 0:
                fprintf(stderr, _("Password mismatch when extracting key\n"));
                break;
            case 1:     /* fall through... */
            default:
                fprintf(stderr, _("Checksum mismatch in keyfile (openssl-compat, ofs=%u,idx=%u)\n"),
                        (unsigned)ofs, (unsigned)idx);
                break;
        }
        eflag = ERR_BADDECRYPT;
    }
    *keylen = pos;

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
    if (hbuff != NULL) sec_free((void*)hbuff);

    return eflag;
}


static int kmgcryossl_put_key(bound_tgtdefn_t *boundtgt,
            const km_pw_context_t *pw_ctxt,
            const uint8_t *key, const int keylen, FILE *fp_key)
    /*! Store key in OpenSSL-compatible file via libgcrypt */
{   const keyinfo_t *keyinfo = &boundtgt->tgt->key;
    gcry_cipher_hd_t chd;
    char *passwd = NULL;
    uint8_t salt[kmgcryossl_saltlen], *buff = NULL;
    size_t buffsz, cblksz, pos;
    int wr_errs=0, cipher, ciphermode, digest, eflag=ERR_NOERROR;

    eflag = kmgcry_get_algos(keyinfo, &cipher, &ciphermode, &digest);
    if (eflag != ERR_NOERROR) goto bail_out;
    gcry_cipher_algo_info(cipher, GCRYCTL_GET_BLKLEN, NULL, &cblksz);

    eflag = km_get_passwd(boundtgt->tgt->ident, pw_ctxt, &passwd, 1, 1);
    if (eflag != ERR_NOERROR) goto bail_out;

    /* Write key header: */
    wr_errs += cm_fwrite((const void*)kmgcryossl_magstr, kmgcryossl_maglen, fp_key);

    /* Generate salt & record in keyfile: */
    cm_generate_key(salt, sizeof(salt));
    wr_errs += cm_fwrite((const void*)salt, sizeof(salt), fp_key);

    /* Pad key-data with end-marker: */
    buffsz = cblksz * ((keylen + cblksz) / cblksz);
    buff = (uint8_t*)sec_realloc(buff, buffsz);
    memcpy((void*)buff, (const void*)key, (size_t)keylen);
    for (pos=keylen; pos<buffsz; ++pos) buff[pos] = (buffsz - keylen);

    /* Write encrypted key into keyfile: */
    eflag = kmgcry_initcipher(cipher, ciphermode, digest,
                    salt, kmgcryossl_keybuilder, passwd, strlen(passwd), &chd);
    if (eflag != ERR_NOERROR) goto bail_out;
    pos = 0;
    while (pos < buffsz) {
        gcry_cipher_encrypt(chd, (void*)(buff + pos), cblksz, NULL, 0);
        wr_errs += cm_fwrite((const void*)(buff + pos), cblksz, fp_key);
        pos += cblksz;
    }
    gcry_cipher_close(chd);

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

#endif  /* USE_GCRYOSSL */


#  ifdef TESTING

static int kmgcry_test_hash()
{   gcry_md_hd_t mdcontext;
    int algo;
    uint8_t *mdval = NULL;
    size_t mdlen, i;
    unsigned q;
    const char *str = "noisy\n";
    const char *hash = "7c1c9261fa774475ec1c0d887eaf00c19b0eb218";

    CM_TEST_START("libgcrypt hashing");

    gcry_md_open(&mdcontext, GCRY_MD_SHA1, 0);
    gcry_md_write(mdcontext, (const void*)str, strlen(str));
    gcry_md_final(mdcontext);
    algo = gcry_md_get_algo(mdcontext);
    mdlen = gcry_md_get_algo_dlen(algo);
    mdval = gcry_md_read(mdcontext, algo);
    CM_ASSERT_DIFFERENT(NULL, mdval);
    CM_ASSERT_EQUAL(strlen(hash)/2, mdlen);
    for (i=0; i<mdlen; ++i) {
        sscanf(hash+2*i, "%2x", &q);
        CM_ASSERT_EQUAL(q, (unsigned)mdval[i]);
    }

    gcry_md_close(mdcontext);

    CM_TEST_OK();
}

static void kmgcry_testctxt(cm_testinfo_t *context)
{
    test_ctxtptr = context;
}

static int kmgcry_runtests()
{   int flg = 0;

    flg |= kmgcry_test_hash();
    flg |= kmgcry_test_getalgos();

    return flg;
}

#  endif    /* TESTING */


#if USE_GCRYOSSL

keymanager_t keymgr_gcryossl = {
    "openssl-compat", 0,    kmgcry_init_algs, kmgcry_free_algs,
                      kmgcryossl_bind, kmgcry_get_properties,
                      kmgcryossl_get_key, kmgcryossl_put_key,
    NULL
#ifdef TESTING
    , NULL, NULL, CM_HASLEGACY
#endif
};

#endif

keymanager_t keymgr_gcry = {
    "libgcrypt", 0,   kmgcry_init_algs, kmgcry_free_algs,
                      kmgcry_bind, kmgcry_get_properties,
                      kmgcry_get_key, kmgcry_put_key,
#if USE_GCRYOSSL
    &keymgr_gcryossl
#else
    NULL
#endif
#ifdef TESTING
    , kmgcry_testctxt, kmgcry_runtests, CM_HASLEGACY
#endif
};

#endif  /* HAVE_LIBGCRYPT */


keymanager_t *kmgcry_gethandle()
{
#if HAVE_LIBGCRYPT
    return &keymgr_gcry;
#else
    return NULL;
#endif
}

/**  @} */

/*
 *  (C)Copyright 2005-2025, RW Penney
 */
