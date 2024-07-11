/*
 *  Miscellaneous utility functions for cryptmount
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
#include <linux/major.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if HAVE_SYS_SYSMACROS_H
#  include <sys/sysmacros.h>
#endif
#include <sys/times.h>
#include <sys/types.h>
#include <sys/stat.h>
#if HAVE_TERMIOS
#  include <termios.h>
#endif
#include <time.h>
#include <unistd.h>

#include "cryptmount.h"
#include "utils.h"
#ifdef TESTING
#  include "cmtesting.h"
#endif


cm_string_t *cm_str_init(const char *val)
    /** Construct a new string object from a plain char* string */
{   cm_string_t *str;

    if (val != NULL) {
        const size_t len = strlen(val);
        str = cm_str_alloc((len + 1));
        memcpy(str->buffer, val, len + 1);
        str->size = len;
    } else {
        str = cm_str_alloc(32);
    }

    return str;
}


cm_string_t *cm_str_alloc(size_t bufflen)
    /** Construct a new string object of a specified size (including null) */
{   cm_string_t *str;

    str = (cm_string_t*)malloc(sizeof(cm_string_t));
    str->buffer = (char*)malloc(bufflen);
    if (bufflen > 0) str->buffer[0] = '\0';
    str->bufflen = bufflen;
    str->size = 0;

    return str;
}


cm_string_t *cm_str_realloc(cm_string_t *str, size_t bufflen)
    /** Ensure that string object can contain at least bufflen bytes */
{
    if (str->bufflen < bufflen) {
        const size_t newbuff = 32 * (1 + (bufflen + 31) / 32);
        str->buffer = (char*)realloc(str->buffer, newbuff);
        str->bufflen = newbuff;
    }

    return str;
}


cm_string_t *cm_str_append(cm_string_t *str, const cm_string_t *addend)
    /** Concatenate addend onto str, reserving additional memory as needed */
{   const size_t totlen = (str->size + addend->size);

    cm_str_realloc(str, (totlen + 1));

    memcpy((void*)(str->buffer + str->size),
            addend->buffer, addend->size + 1);
    str->size = totlen;

    return str;
}


cm_string_t *cm_str_append_char(cm_string_t *str, const char addend)
    /** Concatenate addend onto str, reserving additional memory as needed */
{
    cm_str_realloc(str, (str->size + 2));

    str->buffer[str->size] = addend;
    ++str->size;
    str->buffer[str->size] = '\0';

    return str;
}


cm_string_t *cm_str_append_str(cm_string_t *str, const char *addend)
    /** Concatenate addend onto str, reserving additional memory as needed */
{   const size_t addlen = (addend != NULL ? strlen(addend) : 0);

    cm_str_realloc(str, (str->size + addlen + 1));

    memcpy((void*)(str->buffer + str->size), addend, addlen + 1);
    str->size += addlen;

    return str;
}


char *cm_str_strip(cm_string_t *str)
    /** Extract character buffer from string object, and dispose of container */
{   char *buff = str->buffer;

    free((void*)str);

    return buff;
}


void cm_str_free(cm_string_t *str)
    /** Relinquish storage associated with string object */
{
    if (str == NULL) return;

    free((void*)str->buffer);
    free((void*)str);
}


#ifdef TESTING

/*! \addtogroup unit_tests
 *  @{ */

int ut_test_strings()
    /* Check enhanced basic class */
{   cm_string_t *str, *str2;

    CM_TEST_START("String class methods");

    str = cm_str_init("not much");
    CM_ASSERT_STR_EQUAL("not much", str->buffer);

    cm_str_append_char(str, ' ');
    CM_ASSERT_STR_EQUAL("not much ", str->buffer);

    cm_str_append_str(str, "to see");
    CM_ASSERT_STR_EQUAL("not much to see", str->buffer);

    str2 = cm_str_init(" here");
    cm_str_append(str, str2);
    CM_ASSERT_STR_EQUAL("not much to see here", str->buffer);

    CM_ASSERT_EQUAL(20, str->size);
    if (str->bufflen <= str->size) CM_TEST_FAIL();

    cm_str_free(str);
    cm_str_free(str2);

    CM_TEST_OK();
}

/** @} */

#endif  /* TESTING */


/**
 *  Create full pathname of config file.
 *
 *  The resulting path is allocated within \a buff,
 *  whose length is returned.
 *
 *  The path is calculated at runtime to allow
 *  the built-in testing mechanisms to override the location
 *  of configuration files via a command-line option,
 *  when compiled with -DTESTING=1.
 */
int cm_path(char **buff, cm_path_prefix_t prefix_code, const char *file)
{   size_t pfxlen, sfxlen;
    const char *pfx = NULL;

    if (buff == NULL || file == NULL) return 0;

#ifdef TESTING
    pfx = (test_ctxtptr->argconfigdir != NULL ? test_ctxtptr->argconfigdir
                                              : "/nowhere");
#else
    switch (prefix_code) {
      case CM_SYSCONF_PFX:
        pfx = CM_SYSCONF_DIR;
        break;
      case CM_SYSRUN_PFX:
        pfx = CM_SYSRUN_DIR;
        break;
      default:
        pfx = CM_SYSCONF_DIR;
        break;
    }
#endif

    pfxlen = strlen(pfx);
    sfxlen = strlen(file);
    *buff = (char*)realloc((void*)(*buff), (pfxlen + sfxlen + 2));

    snprintf(*buff, (pfxlen + sfxlen + 2), "%s/%s", pfx, file);

    return (int)(pfxlen + sfxlen + 1);
}


char *cm_strdup(const char *orig)
    /** Make duplicate of existing string, allocating memory for copy */
{   char *cpy = NULL;

    if (orig == NULL) return NULL;

    cpy = (char*)malloc(strlen(orig) + 1);

    return strcpy(cpy, orig);
}


int cm_strcasecmp(const char *s1, const char *s2)
    /** Find legigraphical order of s1 & s2, ignoring case */
{
    if (s1 == NULL || s2 == NULL) return (s1 != NULL) - (s2 != NULL);
    while (*s1 != '\0' && *s2 != '\0' && tolower(*s1) == tolower(*s2)) {
        ++s1; ++s2;
    }

    return (tolower(*s1) - tolower(*s2));
}


int cm_startswith(const char **str, const char *prefix)
    /** Check whether *prefix appears at start of **str */
{   int valid=1;

    if (str == NULL) return 0;
    if (*str == NULL || prefix == NULL) return (*str == NULL && prefix == NULL);

    while (valid && *prefix != '\0') {
        valid &= (*prefix == **str);
        ++prefix;
        ++*str;
    }

    return valid;
}


#ifdef TESTING

/*! \addtogroup unit_tests
 *  @{ */

int ut_test_strops()
    /* Check basic string operations */
{   const char *refstr="alphabet", *refp;

    CM_TEST_START("String operations");

    CM_ASSERT_EQUAL(cm_strcasecmp("alpha", "alpha"), 0);
    CM_ASSERT_EQUAL(cm_strcasecmp("alpha", "ALPHA"), 0);
    CM_ASSERT_EQUAL(cm_strcasecmp("alpha", "beta"), -1);
    CM_ASSERT_EQUAL(cm_strcasecmp("alpha", "BETA"), -1);
    CM_ASSERT_EQUAL(cm_strcasecmp("beta", "alpha"), +1);
    CM_ASSERT_EQUAL(cm_strcasecmp("beta", "ALPHA"), +1);

    refp = refstr; CM_ASSERT_EQUAL(cm_startswith(&refp, "alpha"), 1);
    CM_ASSERT_EQUAL(strcmp(refp, "bet"), 0);
    refp = refstr; CM_ASSERT_EQUAL(cm_startswith(&refp, "alpa"), 0);

    CM_TEST_OK();
}

/** @} */

#endif  /* TESTING */


void *sec_realloc(void *ptr, size_t size)
    /** Slightly more secure version of realloc() */
{   size_t cnt, *memarr;

    cnt = (size + 2 * sizeof(size_t) - 1) / sizeof(size_t);
    memarr = (size_t*)calloc(cnt, sizeof(size_t));

    if (memarr == NULL) {
        fprintf(stderr, _("Unable to allocate memory\n"));
        abort();
        return NULL;
    }

    /* Prepend usable memory chunk with record of size of chunk: */
    memarr[0] = (cnt - 1) * sizeof(size_t);

    if (ptr != NULL) {
        size_t oldsz;

        /* Copy (usable) part of old memory block into new: */
        oldsz = *(((size_t*)ptr) - 1);
        if (oldsz > size) oldsz = size;
        memcpy((void*)(memarr + 1), (const void*)ptr, oldsz);

        /* Dispose of old memory block: */
        sec_free(ptr);
    }

    return (void*)(memarr + 1);
}


void mem_cleanse(uint8_t *addr, size_t sz)
    /** Overwrite memory with (weak) pseudo-random numbers */
{   size_t i;
    static unsigned long salt=0x917c;

    salt ^= (unsigned long)addr;

    for (i=0; i<sz; ++i) {
        addr[i] = (i % 21) ^ (salt % 221);
        salt += 4;
    }
}


void sec_free(void *ptr)
    /** Slightly more secure version of free() */
{   size_t *memarr, sz;

    if (ptr == NULL) return;

    memarr = ((size_t*)ptr) - 1;
    sz = memarr[0];

    mem_cleanse((uint8_t*)(memarr + 1), sz);

    free((void*)memarr);
}


void millisleep(unsigned ms)
{
#if HAVE_NANOSLEEP
    struct timespec delay;
    delay.tv_sec = ms / 1000;
    delay.tv_nsec = (ms % 1000) * 1000 * 1000;
    nanosleep(&delay, NULL);
#else
    sleep((ms + 999) / 1000);
#endif
}


/**
 *  Generate a random sequence of \a len bytes,
 *  using a cryptographic-quality iterative message-digest
 *  applied to various entropy sources including /dev/random.
 */
int cm_generate_key(uint8_t *buff, size_t len)
{   struct rnddev {
        const char *name;
        unsigned short devmaj;
        unsigned short devmin; } *rndsrc;
    struct rnddev devs[] = {
        { "/dev/urandom",   MEM_MAJOR,      9 },
        { "/dev/random",    MEM_MAJOR,      8 },
        { "/dev/hwrng",     MISC_MAJOR,   183 },
        { NULL, 0, 0 } };
    const size_t POOL_SIZE = 256, NOISE_CHUNK = 16;
    uint8_t *mdval, *pool, *devbuff = NULL;
    size_t pos, step, mdlen;
    const pid_t pid = getpid();
    struct tms tbuff;
    clock_t clk;
    static unsigned seed = 1993;
    int first = 1, total_entropy = 0, eflag = ERR_NOERROR;

    pool = (uint8_t*)sec_realloc(NULL, POOL_SIZE);

    devbuff = (uint8_t*)sec_realloc(NULL, NOISE_CHUNK);
    for (rndsrc=devs; rndsrc->name!=NULL; ++rndsrc) {
        struct stat sbuff;
        ssize_t nread;
        int fd = -1;

        if (stat(rndsrc->name, &sbuff) != 0) continue;
        if ((unsigned)major(sbuff.st_rdev) != rndsrc->devmaj
          || (unsigned)minor(sbuff.st_rdev) != rndsrc->devmin) continue;

        fd = open(rndsrc->name, O_RDONLY | O_NONBLOCK);
        if (fd < 0) continue;

        if (first) {
            nread = read(fd, pool, POOL_SIZE);
            if (nread > 0) total_entropy += nread;
            first = 0;
        } else {
            nread = read(fd, devbuff, NOISE_CHUNK);
            if (nread > 0) {
                total_entropy += nread;
                memmove(pool + nread, pool, (POOL_SIZE - nread));
                memcpy(pool, devbuff, nread);
            }
        }

        close(fd);
    }
    sec_free(devbuff);

    if (total_entropy < 32) {
        fprintf(stderr, _("Too few random-number sources found\n"));
        eflag = WRN_LOWENTROPY;
    }

    /* Generate key-bytes by recursive hashing of entropy pool: */
    pos = 0;
    while (pos < len) {
        cm_sha1_ctxt_t *mdcontext = cm_sha1_init();

        /* Fold-in various sources of entropy: */
        cm_sha1_block(mdcontext, pool, POOL_SIZE);

        cm_sha1_block(mdcontext, (uint8_t*)&pid, sizeof(pid));
        clk = times(&tbuff);
        cm_sha1_block(mdcontext, (uint8_t*)&clk, sizeof(clk));
        cm_sha1_block(mdcontext, (uint8_t*)&seed, sizeof(seed));
        cm_sha1_block(mdcontext, (uint8_t*)&tbuff, sizeof(tbuff));

        cm_sha1_final(mdcontext, &mdval, &mdlen);

        step = ((pos + mdlen) > len ? (len - pos) : mdlen);
        memcpy((void*)(buff + pos),(const void*)mdval, step);
        pos += step;

        memmove(pool + mdlen, pool, (POOL_SIZE - mdlen));
        memcpy(pool, mdval, mdlen);
        seed = seed * 151 + 1279;

        cm_sha1_free(mdcontext);
        sec_free(mdval);
    }

    sec_free((void*)pool);

    return eflag;
}


ssize_t cm_ttygetpasswd(const char *prompt, char **buff)
    /* Read password from standard input terminal */
{   ssize_t pwlen=0;
#if HAVE_TERMIOS
    struct termios oldttystate, newttystate;
    int echook=1;
    char tmppass[2048];
#else
    char *tmppass=NULL;
#endif

#if HAVE_TERMIOS
    if (tcgetattr(fileno(stdin), &oldttystate) != 0) echook = 0;
    newttystate = oldttystate;
    newttystate.c_lflag &= ~ECHO;
    if (tcsetattr(fileno(stdin), TCSAFLUSH, &newttystate) != 0) echook = 0;
    if (tcgetattr(fileno(stdin), &newttystate) != 0
      || (newttystate.c_lflag & ECHO) != 0) echook = 0;
    if (echook) {
        printf("%s", prompt);
        if (fgets(tmppass, (int)sizeof(tmppass), stdin) == NULL) {
            fprintf(stderr, _("Cannot read stdin"));
            return -1;
        }
        pwlen = strlen(tmppass);
        if (pwlen > 0 && tmppass[pwlen-1] == '\n') {
            tmppass[--pwlen] = '\0'; }
        *buff = (char*)sec_realloc((void*)*buff, (size_t)(pwlen+1));
        strcpy(*buff, tmppass);
        mem_cleanse((uint8_t*)tmppass, sizeof(tmppass));
        tcsetattr(fileno(stdin), TCSAFLUSH, &oldttystate);
        printf("\n");
    } else {
        fprintf(stderr, _("Failed to turn off keyboard echoing on terminal\n"));
        pwlen = -1;
    }
#else
    tmppass = getpass(prompt);
    pwlen = strlen(tmppass);
    *buff = sec_realloc((void*)*buff, (size_t)(pwlen+1));
    strcpy(*buff, tmppass);
    mem_cleanse((uint8_t*)tmppass, (size_t)(pwlen+1));
#endif  /* !HAVE_TERMIOS */

    return pwlen;
}


int km_get_passwd(const char *ident, const km_pw_context_t *pw_ctxt,
                char **passwd, int isnew, int verify)
    /* Read password from terminal, possibly asking for confirmation */
{   enum { BUFFSZ=2048 };
    char *tmppass=NULL;
    ssize_t plen=0;
    int eflag=ERR_NOERROR;

    if (pw_ctxt != NULL && pw_ctxt->verify) verify |= 1;

    if (pw_ctxt == NULL || pw_ctxt->fd_pw_source == NULL) {
#ifndef TESTING
        /* Read (+confirm) password from terminal: */
        char prompt[BUFFSZ];
        snprintf(prompt, sizeof(prompt),
                (isnew ? _("Enter new password for target \"%s\": ")
                    : _("Enter password for target \"%s\": ")),
                ident);

        if (cm_ttygetpasswd(prompt, passwd) < 0) {
            eflag = ERR_BADPASSWD;
            goto bail_out;
        }

        if (verify) {
            snprintf(prompt, sizeof(prompt), _("Confirm password: "));
            plen = cm_ttygetpasswd(prompt, &tmppass);
            if (strcmp(*passwd, tmppass) != 0) {
                fprintf(stderr, _("Password mismatch\n"));
                sec_free(*passwd);
                *passwd = NULL;
                eflag = ERR_BADPASSWD;
            }
        }
#else   /* TESTING */
        /* Read passwords passed in via command-line arguments: */
        const char *argpw;
        argpw = (pw_ctxt != NULL ? pw_ctxt->argpasswd[(isnew ? 1 : 0)] : NULL);
        *passwd = (char*)sec_realloc((void*)*passwd, (size_t)1024);
        strncpy(*passwd, (argpw != NULL ? argpw : ""), (size_t)1024);
#endif
    } else {
        /* Read password (once only) from input stream: */
        tmppass = (char*)sec_realloc(tmppass, (size_t)BUFFSZ);
        if (fgets(tmppass, BUFFSZ, pw_ctxt->fd_pw_source) == NULL) {
            eflag = ERR_BADFILE;
            goto bail_out;
        }

        /* Remove trailing carriage-return(s): */
        plen = strlen(tmppass);
        while (plen > 0 && tmppass[plen-1] == '\n') tmppass[--plen] = '\0';

        *passwd = (char*)sec_realloc(*passwd, (plen + 1));
        strcpy(*passwd, tmppass);
    }

  bail_out:

    sec_free((void*)tmppass);

    return eflag;
}


int cm_confirm(const char *msg)
    /* Invite user to pause before taking dangerous action */
{   char *affirmativeResponse=_("yes");
    char response[64];
    int rlen;

    if (msg != NULL) {
        printf("%s\n", msg);
    }
    fprintf(stdout, _("Are you sure? (Type \"%s\" to proceed): "), affirmativeResponse);

    if (fgets(response, (int)sizeof(response), stdin) == NULL) {
        fprintf(stderr, _("Cannot read stdin\n"));
        return 0;
    }
    rlen = strlen(response);
    if (rlen > 0 && response[rlen-1] == '\n') response[--rlen] = '\0';

    return (cm_strcasecmp(response, affirmativeResponse) == 0);
}


unsigned km_aug_keysz(unsigned keylen, unsigned blksz)
    /* Calculate size of augmented cipher-key after appending checksum etc */
{
    return blksz * ((keylen + 2 * sizeof(uint32_t) + blksz - 1) / blksz);
}


uint8_t *km_aug_key(const uint8_t *key, unsigned keylen,
                    unsigned blocksz, size_t *buffsz)
    /* Augment cipher key with checksum prior to encryption & storage */
{   uint8_t *buff=NULL;
    uint32_t chksum, *kptr=NULL;
    size_t idx, cnt;

    *buffsz = km_aug_keysz(keylen, blocksz);
    buff = (uint8_t*)sec_realloc(buff, *buffsz);

    /* Copy key into zero-padded buffer: */
    memset(buff, 0, (size_t)*buffsz);
    memcpy(buff, key, (size_t)keylen);

    /* Compute crude EOR checksum (invariant to byte-ordering): */
    cnt = (keylen + sizeof(chksum) - 1) / sizeof(chksum);
    chksum = 0;
    kptr = (uint32_t*)buff;
    for (idx=0; idx<cnt; ++idx) {
        chksum ^= *kptr;
        ++kptr;
    }

    /* Install checksum at next 4-byte boundary & pad with noise: */
    *kptr = chksum;
    idx = (idx + 1) * sizeof(chksum);
    if (idx < *buffsz) {
        cm_generate_key((buff + idx), (*buffsz - idx));
    }

    return buff;
}


int km_aug_verify(const uint8_t *buff, unsigned keylen,
                uint32_t *expected, uint32_t *actual)
    /* Check augmented cipher key against simple checksum */
{   unsigned cnt;
    uint32_t *kptr;

    cnt = (keylen + sizeof(*expected) - 1) / sizeof(*expected);
    *actual = 0;
    kptr = (uint32_t*)buff;
    while (cnt--) {
        *actual ^= *kptr;
        ++kptr;
    }

    *expected = *kptr;
    return (*expected == *actual);
}


/*
 *  SHA1 message-digest algorithm
 *  - based on "Cryptography - theory & practice" (2nd Ed.), DR Stinson, 2002
 *  (rather inefficient implementation, but good enough for short messages)
 */

static const uint32_t
    SHA1_H0 = 0x67452301U,
    SHA1_H1 = 0xEFCDAB89U,
    SHA1_H2 = 0x98BADCFEU,
    SHA1_H3 = 0x10325476U,
    SHA1_H4 = 0xC3D2E1F0U,
    SHA1_K0 = 0x5A827999U,
    SHA1_K1 = 0x6ED9EBA1U,
    SHA1_K2 = 0x8F1BBCDCU,
    SHA1_K3 = 0xCA62C1D6U;


cm_sha1_ctxt_t *cm_sha1_init(void)
{   cm_sha1_ctxt_t *ctxt;
    unsigned idx;

    ctxt = (cm_sha1_ctxt_t*)sec_realloc(NULL, sizeof(cm_sha1_ctxt_t));

    ctxt->msglen = 0;
    ctxt->buffpos = 0;
    ctxt->H[0] = SHA1_H0;
    ctxt->H[1] = SHA1_H1;
    ctxt->H[2] = SHA1_H2;
    ctxt->H[3] = SHA1_H3;
    ctxt->H[4] = SHA1_H4;
    for (idx=0; idx<16; ++idx) ctxt->buff[idx] = 0;

    return ctxt;
}


void cm_sha1_block(cm_sha1_ctxt_t *ctxt, const uint8_t *buff, size_t len)
{   uint32_t W[80], A, B, C, D, E, q;
    unsigned idx, round;

    while (len > 0) {
        /* Accumulate bytes into buffer (respecting endianess): */
        idx = ctxt->buffpos >> 2;
        round = 3 - (ctxt->buffpos & 0x03);
        ctxt->buff[idx] |= ((uint32_t)*buff) << (round * 8);
        ctxt->msglen += 8;
        ++ctxt->buffpos;
        ++buff;
        --len;

        if (ctxt->buffpos >= 64) {
            /* Whole 512-bit string is ready - apply SHA1 update to block: */
            for (idx=0; idx<16; ++idx) W[idx] = ctxt->buff[idx];
            for (idx=16; idx<80; ++idx) {
                q = W[idx-3] ^ W[idx-8] ^ W[idx-14] ^ W[idx-16];
                W[idx] = ((q & 0x7fffffff)) << 1 | ((q & 0x80000000) >> 31);
            }

            A = ctxt->H[0];
            B = ctxt->H[1];
            C = ctxt->H[2];
            D = ctxt->H[3];
            E = ctxt->H[4];

            for (round=0; round<80; ++round) {
                q = (((A & 0x07ffffff) << 5) | ((A & 0xf8000000) >> 27))
                            + E + W[round];
                switch (round / 20) {
                case 0:
                    q += ((B & C) | ((~B) & D)) + SHA1_K0;
                    break;
                case 1:
                    q += (B ^ C ^ D) + SHA1_K1;
                    break;
                case 2:
                    q += ((B & C) | (B & D) | (C & D)) + SHA1_K2;
                    break;
                case 3:
                    q += (B ^ C ^ D) + SHA1_K3;
                    break;
                }
                E = D;
                D = C;
                C = ((B & 0xfffffffc) >> 2) | ((B & 0x03) << 30);
                B = A;
                A = q;
            }

            ctxt->H[0] += A;
            ctxt->H[1] += B;
            ctxt->H[2] += C;
            ctxt->H[3] += D;
            ctxt->H[4] += E;
            ctxt->buffpos = 0;
            for (idx=0; idx<16; ++idx) ctxt->buff[idx] = 0;
        }
    }
}


void cm_sha1_final(cm_sha1_ctxt_t *ctxt, uint8_t **mdval, size_t *mdlen)
{   uint8_t *cptr, buff[64], mrk=0x80;
    unsigned idx, padlen;
    uint32_t msglen;

    /* Add closing sequence onto message string: */
    msglen = ctxt->msglen;
    for (idx=0; idx<64; ++idx) buff[idx] = 0;
    padlen = (ctxt->buffpos < 56 ? 55 - ctxt->buffpos : 119 - ctxt->buffpos);
    cm_sha1_block(ctxt, &mrk, (size_t)1);
    if (padlen > 0) cm_sha1_block(ctxt, buff, (size_t)padlen);
    buff[4] = (msglen & 0xff000000) >> 24;
    buff[5] = (msglen & 0xff0000) >> 16;
    buff[6] = (msglen & 0xff00) >> 8;
    buff[7] = msglen & 0xff;
    cm_sha1_block(ctxt, buff, (size_t)8);

    /* Transcribe internal state into array of bytes: */
    *mdval = (uint8_t*)sec_realloc(NULL, (size_t)CM_SHA1_SIZE);
    *mdlen = CM_SHA1_SIZE;
    cptr = *mdval;
    for (idx=0; idx<5; ++idx) {
        cptr[0] = (uint8_t)((ctxt->H[idx] >> 24) & 0xff);
        cptr[1] = (uint8_t)((ctxt->H[idx] >> 16) & 0xff);
        cptr[2] = (uint8_t)((ctxt->H[idx] >> 8) & 0xff);
        cptr[3] = (uint8_t)(ctxt->H[idx] & 0xff);
        cptr += 4;
    }
}


void cm_sha1_free(cm_sha1_ctxt_t *ctxt)
{
    sec_free((void*)ctxt);
}


#ifdef TESTING

/*! \addtogroup unit_tests
 *  @{ */

int ut_test_sha1()
    /* Check internal SHA1 hashing algorithm against known test-vectors */
{   cm_sha1_ctxt_t *ctxt;
    uint8_t *mdval;
    unsigned b, q, idx;
    size_t mdlen;
    struct {
        const char *input, *hash; } cases[] = {
    { "",                       "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
    { "a",                      "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8" },
    { "alpha",                  "be76331b95dfc399cd776d2fc68021e0db03cc4f" },
    { "alphabetti spaghetti",   "c5fe3361dfdf6f17706cbe3ab0cc6419d057c329" },
    { "163dac44e979cdaef82868a26abf392e3ee58e11f00b02d31daa20ed458e", "0fc6075902f1cc2c9e19819830bb294c820f016f" },
    { "Cryptography - theory and practice, by Douglas R Stinson, Chapman & Hall/CRC",  "2e0e07901c8460bc57b0097a66c7086ed5e97808" },
    { NULL, NULL } };

    CM_TEST_START("Internal SHA1");
    CM_ASSERT_EQUAL(CM_SHA1_SIZE, 5 * sizeof(uint32_t));

    idx = 0;
    while (cases[idx].input != NULL) {
        ctxt = cm_sha1_init();
        cm_sha1_block(ctxt, (const uint8_t*)cases[idx].input,
                            strlen(cases[idx].input));
        cm_sha1_final(ctxt, &mdval, &mdlen);
        cm_sha1_free(ctxt);

        for (b=0; b<CM_SHA1_SIZE; ++b) {
            sscanf((cases[idx].hash + 2*b), "%02x", &q);
            CM_ASSERT_EQUAL(q, (unsigned)mdval[b]);
        }

        sec_free((void*)mdval);
        ++idx;
    }

    CM_TEST_OK();
}

/** @} */

#endif  /* TESTING */



void cm_pwd_fortify(const char *passwd, unsigned iterations,
                const uint8_t *salt, size_t saltlen,
                uint8_t **key, size_t keylen)
    /* Iteratively apply hashing algorithm to stretch & fortify password */
{   cm_sha1_ctxt_t *mdcontext = NULL;
    uint8_t q, *permsalt = NULL, *mdval = NULL, *mdval_prev = NULL;
    size_t idx, pos, mdlen, pwlen, sz=0, newidx;
    uint32_t cnt, r_val;
    const uint32_t r_mult = 421, r_inc = 54773,
                   r_mod = 259200, r_scale = 69317;

    /* Initialize random-number seed from password vector: */
    pwlen = strlen(passwd);
    r_val = 1;
    for (idx=0; idx<pwlen; ++idx) {
        r_val = (r_val * r_scale + (uint32_t)passwd[idx]) % r_mod;
    }

    /* Assemble salt-vector which can be randomly permuted: */
    if (salt != NULL && saltlen > 0) {
        permsalt = (uint8_t*)sec_realloc((void*)permsalt, saltlen);
        memcpy((void*)permsalt, (const void*)salt, saltlen);
    } else {
        if (saltlen == 0) saltlen = 16;
        permsalt = (uint8_t*)sec_realloc((void*)permsalt, saltlen);
        for (idx=0; idx<saltlen; ++idx) permsalt[idx] = idx;
    }

    *key = (uint8_t*)sec_realloc((void*)*key, keylen);
    pos = 0;
    while (pos < keylen) {
        /* Iteratively apply hashing function to fortify password: */
        for (cnt=0; cnt<iterations; ++cnt) {
            mdcontext = cm_sha1_init();

            if (cnt == 0) {
                /* Permute salt vector: */
                for (idx=0; idx<(saltlen-1); ++idx) {
                    newidx = idx + (r_val % (saltlen - idx));

                    q = permsalt[newidx];
                    permsalt[newidx] = permsalt[idx];
                    permsalt[idx] = q;

                    r_val = (r_mult * r_val + r_inc) % r_mod;
                }

                /* Mix-in salt vector: */
                cm_sha1_block(mdcontext, permsalt, saltlen);

                /* Mix-in head of output vector: */
                if (pos > 0) {
                    cm_sha1_block(mdcontext, *key, pos);
                }
            } else {
                /* Mix-in result of previous iteration: */
                cm_sha1_block(mdcontext, mdval_prev, mdlen);
            }

            /* Mix-in password: */
            cm_sha1_block(mdcontext, (const uint8_t*)passwd, pwlen);

            cm_sha1_final(mdcontext, &mdval, &mdlen);

            /* Merge (subset of) hash-code bytes into output key: */
            if (cnt == 0) {
                sz = ((pos + mdlen) > keylen ? (keylen - pos) : mdlen);
                memcpy((void*)(*key + pos), (const void*)mdval, sz);
            } else {
                /* Mix with results from previous iterations: */
                for (idx=0; idx<sz; ++idx) *(*key + pos + idx) ^= mdval[idx];
            }

            cm_sha1_free(mdcontext);

            if (cnt > 0) sec_free(mdval_prev);
            mdval_prev = mdval;
            mdval = NULL;
        }
        pos += sz;
        sec_free(mdval_prev);
        mdval_prev = NULL;
    }

    sec_free(permsalt);
}


#ifdef TESTING

/*! \addtogroup unit_tests
 *  @{ */

int ut_pwfort()
    /* Check that password-fortification behaves sensibly */
{   unsigned idx, pos, r=0;
    struct fwdbck {
        char *passwd;
        uint8_t *fwd, *bck;
    } *fbs;
    struct tcase {
        const char *passwd;
        const char *salt;
        uint8_t front[4], back[4];
    } tcases[] = {
        { "Mary", "alpha",      { 0x46, 0x94, 0x0f, 0xb1 },
                                { 0x8e, 0x0c, 0x6a, 0x6b } },
        { "had", "beta",        { 0x99, 0xd7, 0x51, 0x0f },
                                { 0x72, 0x23, 0x89, 0x2c } },
        { "a", "gamma",         { 0x6a, 0xcf, 0x38, 0xa5 },
                                { 0x57, 0x95, 0x6f, 0xcc } },
        { "little", "delta",    { 0xe6, 0x53, 0x17, 0x26 },
                                { 0x4c, 0x87, 0x05, 0xd7 } },
        { "lamb", "epsilon",    { 0xc2, 0x16, 0xf6, 0x11 },
                                { 0xf6, 0xaa, 0x02, 0x5d } },
        { NULL, NULL,           {},
                                {} } };
    uint8_t *key=NULL;
    const unsigned n_fbs = 64, n_its = 32;
    const size_t pwlen = 13, saltlen = 17, keylen = 1024;

    CM_TEST_START("Password fortification");

    /* Generate set of keys from pseudo-random passwords: */
    fbs = (struct fwdbck*)malloc(n_fbs * sizeof(struct fwdbck));
    for (idx=0; idx<n_fbs; ++idx) {
        fbs[idx].passwd = (char*)malloc(pwlen + 1);
        fbs[idx].fwd = fbs[idx].bck = NULL;

        for (pos=0; pos<pwlen; ++pos) {
            fbs[idx].passwd[pos] = (char)('A' + (r++ % 61));
        }
        fbs[idx].passwd[pwlen] = '\0';

        cm_pwd_fortify(fbs[idx].passwd, n_its, NULL, saltlen,
                    &fbs[idx].fwd, keylen);

        if (idx > 0) {
            CM_ASSERT_DIFFERENT(0, memcmp((const void*)fbs[idx].fwd,
                                    (const void*)fbs[idx-1].fwd, keylen));
        }
    }

    /* Check that keys generated in reverse order match: */
    for (idx=n_fbs; idx-->0; ) {
        cm_pwd_fortify(fbs[idx].passwd, n_its, NULL, saltlen,
                    &fbs[idx].bck, keylen);

        CM_ASSERT_EQUAL(0, memcmp((const void*)fbs[idx].fwd,
                                (const void*)fbs[idx].bck, keylen));

        /* Check that key doesn't contain trivial repetitions: */
        pos = 0;
        while ((pos + 2 *CM_SHA1_SIZE) < keylen) {
            CM_ASSERT_DIFFERENT(0, memcmp((const void*)(fbs[idx].fwd + pos),
                                        (const void*)(fbs[idx].fwd + pos + CM_SHA1_SIZE), (size_t)CM_SHA1_SIZE));
            pos += CM_SHA1_SIZE;
        }

        sec_free((void*)fbs[idx].fwd);
        sec_free((void*)fbs[idx].bck);
        free((void*)fbs[idx].passwd);
    }
    free((void*)fbs);

    /* Check known test cases: */
    for (idx=0; tcases[idx].passwd!=NULL; ++idx) {
        cm_pwd_fortify(tcases[idx].passwd, n_its,
                    (uint8_t*)tcases[idx].salt, strlen(tcases[idx].salt),
                    &key, keylen);
#if 0
        fprintf(stderr, "%s: ", tcases[idx].passwd);
        for (pos=0; pos<keylen; ++pos) fprintf(stderr, "0x%02x, ", key[pos]);
        fprintf(stderr, "\n\n");
#endif

        CM_ASSERT_EQUAL(0, memcmp((const void*)key,
                                (const void*)tcases[idx].front, (size_t)4));
        CM_ASSERT_EQUAL(0, memcmp((const void*)(key + keylen - 4),
                                (const void*)tcases[idx].back, (size_t)4));
    }

    if (key != NULL) sec_free((void*)key);

    CM_TEST_OK();
}

/** @} */

#endif  /* TESTING */

/*
 *  (C)Copyright 2005-2024, RW Penney
 */
