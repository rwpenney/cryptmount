/*
 *  Declarations for miscellaneous utilities for cryptmount
 *  (C)Copyright 2005-2019, RW Penney
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


#ifndef _UTILS_H
#define _UTILS_H

#include <inttypes.h>
#include <stdio.h>

typedef struct km_pw_context {
    FILE *fd_pw_source;         /* Stream from which to read passwords */
    int verify;                 /* Always verify passwords from terminal */
    unsigned debug_level;       /* Verbosity of debugging information */
#ifdef TESTING
    const char *argpasswd[2];   /* Password(s) passed via command-line */
#endif
} km_pw_context_t;


/**
 *  Representation of a string of characters,
 *  analogous to minimalistic std::string from C++
 */
typedef struct cm_string {
    char *buffer;               /**< Storage area for characters */
    size_t bufflen;             /**< Total space available within buffer */
    size_t size;                /**< Current length of string (less null) */
} cm_string_t;


/**
 *  Symbolic representations of directories containing
 *  either configuration files (e.g. /etc/cryptmount/),
 *  or run-time state files (e.g. /run).
 */
typedef enum {
    CM_SYSCONF_PFX, CM_SYSRUN_PFX } cm_path_prefix_t;

cm_string_t *cm_str_init(const char *val);
cm_string_t *cm_str_alloc(size_t bufflen);
cm_string_t *cm_str_realloc(cm_string_t *str, size_t bufflen);
cm_string_t *cm_str_append(cm_string_t *str, const cm_string_t *addend);
cm_string_t *cm_str_append_char(cm_string_t *str, const char addend);
cm_string_t *cm_str_append_str(cm_string_t *str, const char *addend);
char *cm_str_strip(cm_string_t *str);
void cm_str_free(cm_string_t *str);

int cm_path(char **buff, cm_path_prefix_t prefix, const char *file);
char *cm_strdup(const char *orig);
int cm_strcasecmp(const char *s1, const char *s2);
int cm_startswith(const char **str, const char *prefix);

void *sec_realloc(void *ptr, size_t size);
void mem_cleanse(uint8_t *addr, size_t sz);
void sec_free(void *ptr);

int cm_generate_key(uint8_t *key, size_t len);
int km_get_passwd(const char *ident, const km_pw_context_t *pw_ctxt,
                char **passwd, int isnew, int verify);
int cm_confirm(const char *msg);
unsigned km_aug_keysz(unsigned keylen, unsigned blksz);
uint8_t *km_aug_key(const uint8_t *key, unsigned keylen,
                unsigned blocksz, size_t *buffsz);
int km_aug_verify(const uint8_t *buff, unsigned keylen,
                uint32_t *expected, uint32_t *actual);

enum { CM_SHA1_SIZE = 20 };
typedef struct cm_sha1_ctxt {
    uint32_t msglen;
    uint32_t buffpos;
    uint32_t H[5];
    uint32_t buff[16];
} cm_sha1_ctxt_t;

cm_sha1_ctxt_t *cm_sha1_init(void);
void cm_sha1_block(cm_sha1_ctxt_t *ctxt, const uint8_t *buff, size_t len);
void cm_sha1_final(cm_sha1_ctxt_t *ctxt, uint8_t **mdval, size_t *mdlen);
void cm_sha1_free(cm_sha1_ctxt_t *ctxt);

void cm_pwd_fortify(const char *passwd, unsigned iterations,
                const uint8_t *salt, size_t saltlen,
                uint8_t **key, size_t keylen);


static inline uint16_t pack_uint16(const uint8_t *buff) {
    return (((uint16_t)buff[1]) << 8) | ((uint16_t)buff[0]); }

static inline void unpack_uint16(uint8_t *buff, const uint16_t val) {
    buff[0] = (val & 0x00ff); buff[1] = (val & 0xff00) >> 8; }

static inline uint32_t pack_uint32(const uint8_t *buff) {
    return (((uint32_t)buff[3]) << 24) | (((uint32_t)buff[2]) << 16) \
            | (((uint32_t)buff[1]) << 8) | ((uint32_t)buff[0]); }

static inline void unpack_uint32(uint8_t *buff, const uint32_t val) {
    buff[0] = (val & 0x000000ff); buff[1] = (val & 0x0000ff00) >> 8;
    buff[2] = (val & 0x00ff0000) >> 16; buff[3] = (val & 0xff000000) >> 24; }


static inline int cm_fread(void *buff, size_t nbytes, FILE *stream) {
    /* Read bytes from file, returning 0 on success */
    return (fread(buff, nbytes, (size_t)1, stream) != 1);
}


static inline int cm_fwrite(const void *buff, size_t nbytes, FILE *stream) {
    /* Write buffer to file, returning 0 on success */
    return (fwrite(buff, nbytes, (size_t)1, stream) != 1);
}




#endif  /* _UTILS_H */

/*
 *  (C)Copyright 2005-2019, RW Penney
 */
