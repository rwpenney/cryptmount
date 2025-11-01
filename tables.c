/*
 *  Config-table and mount-table utilities for cryptmount
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
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "armour.h"
#include "cryptmount.h"
#include "delegates.h"
#include "tables.h"
#include "utils.h"
#ifdef TESTING
#  include "cmtesting.h"
#endif


const char *cm_status_filename = "cryptmount.status";


enum                /* config-file tokens */
{
    T_IDENT,
    T_LBRACE, T_OPT, T_RBRACE,
    T_ERROR
};


/**
 *  Description of an open target-status file.
 *
 *  Internally, the status-file has the following structure:
 \verbatim
    # [TITLE]           - one-line text header
    0                   - integer file-format version number
    n,[TARGET],uid      - target-name length, target-name, uid of mounter
    ...                 - further target records
 \endverbatim
 */
struct statfile     /* information about status file */
{
    int version;        /* file format version */
    FILE *fp;           /* file handle */
};


/**
 *  Representation of an option flag within the configuration file,
 *  associated with a bit field within a target definition.
 */
typedef struct {
    const char *name;
    unsigned andmask;
    unsigned ormask;
} tgt_option_t;


static tgt_option_t
    /** Menu of options within 'flags' field of target definition */
    setup_options[] = {
        { "defaults",   0U,                 FLG_DEFAULTS },
        { "user",       ~0U,                FLG_USER },
        { "nouser",     ~0U ^ FLG_USER,     0U },
        { "fsck",       ~0U,                FLG_FSCK },
        { "nofsck",     ~0U ^ FLG_FSCK,     0U },
        { "mkswap",     ~0U,                FLG_MKSWAP },
        { "nomkswap",   ~0U ^ FLG_MKSWAP,   0U },
        { "trim",       ~0U,                FLG_TRIM },
        { "notrim",     ~0U ^ FLG_TRIM,     0U },
        { NULL, ~0U, 0U } },
    /** Menu of options within 'bootaction' field of target definition */
    boot_options[] = {
        { "none",       ~0U ^ FLG_BOOT_MASK,    0 },
        { "mount",      ~0U ^ FLG_BOOT_MASK,    FLG_BOOT_MOUNT },
        { "swap",       ~0U ^ FLG_BOOT_MASK,    FLG_BOOT_SWAP },
        { "prepare",    ~0U ^ FLG_BOOT_MASK,    FLG_BOOT_PREP },
        { NULL, ~0U, 0U }
    };

struct vardefn
    /** Description of a quasi-environmental variable */
{
    char *varname;
    char *value;
    struct vardefn *next;
};
static struct vardefn *vardefns = NULL;


static tgtdefn_t *parse_stream(FILE *fp, const char *cfgname);


void set_variable(const char *varname, const char *value)
    /** Set the value of an environmental variable */
{   struct vardefn *newvar;

    newvar = (struct vardefn*)malloc(sizeof(struct vardefn));
    newvar->next = vardefns;

    newvar->varname = cm_strdup(varname);
    newvar->value = cm_strdup(value);

    vardefns = newvar;
}


const char *query_variable(char *varname)
    /** Get the current value of an environmental variable */
{   struct vardefn *var;

    for (var=vardefns; var!=NULL; var=var->next) {
        if (strcmp(varname, var->varname) == 0) return var->value;
    }

    return NULL;
}


void init_env_dictionary()
    /** Initialize internal dictionary of quasi-environmental variables */
{   char buff[512];
    const uid_t uid = getuid();
    const gid_t gid = getgid();
    struct passwd *pwent = NULL;
    struct group *grent = NULL;

    if (vardefns != NULL) return;

    sprintf(buff, "%d", (int)uid);
    set_variable("UID", buff);

    pwent = getpwuid(uid);
    if (pwent != NULL) {
        set_variable("USERNAME", pwent->pw_name);
        set_variable("HOME", pwent->pw_dir);
    }

    sprintf(buff, "%d", (int)gid);
    set_variable("GID", buff);

    grent = getgrgid(gid);
    if (grent != NULL) set_variable("GROUPNAME", grent->gr_name);
}


void clear_env_dictionary()
{   struct vardefn *vd;

    while (vardefns != NULL) {
        vd = vardefns;
        if (vd->varname != NULL) free((void*)vd->varname);
        if (vd->value != NULL) free((void*)vd->value);
        vardefns = vd->next;
        free((void*)vd);
    }
}


tgtdefn_t *alloc_tgtdefn(const tgtdefn_t *prototype)
    /** Allocate storage for a target-structure */
{   tgtdefn_t *tgt;

#define DFLT_OR_PROTO(dflt, proto) \
        (prototype == NULL ? (dflt) : (proto))

    tgt = (tgtdefn_t*)malloc(sizeof(tgtdefn_t));

    tgt->ident = NULL;
    tgt->flags = DFLT_OR_PROTO(FLG_DEFAULTS, prototype->flags);

    tgt->dev = NULL;
    tgt->sectorsize = -1;
    tgt->start = 0; tgt->length = -1;
    tgt->dir = NULL;
    tgt->fstype = DFLT_OR_PROTO(NULL, cm_strdup(prototype->fstype));
    tgt->mountoptions = DFLT_OR_PROTO(NULL, cm_strdup(prototype->mountoptions));
    tgt->fsckoptions = DFLT_OR_PROTO(NULL, cm_strdup(prototype->fsckoptions));
    tgt->loopdev = NULL;
    tgt->supath = DFLT_OR_PROTO(NULL, cm_strdup(prototype->supath));

    tgt->cipher = DFLT_OR_PROTO(cm_strdup(CM_DEFAULT_CIPHER),
                                cm_strdup(prototype->cipher));
    tgt->ivoffset = 0;

    tgt->key.format = DFLT_OR_PROTO(NULL, cm_strdup(prototype->key.format));
    tgt->key.filename = NULL;
    tgt->key.digestalg = DFLT_OR_PROTO(NULL, cm_strdup(prototype->key.digestalg));
    tgt->key.cipheralg = DFLT_OR_PROTO(NULL, cm_strdup(prototype->key.cipheralg));
    tgt->key.maxlen = DFLT_OR_PROTO(-1L, prototype->key.maxlen);
    tgt->key.retries = DFLT_OR_PROTO(1U, prototype->key.retries);

    tgt->nx = NULL;

#undef DFLT_OR_PROTO

    return tgt;
}


const tgtdefn_t *get_tgtdefn(const tgtdefn_t *head, const char *ident)
    /** Find info-structure for target of given name */
{   const tgtdefn_t *itr,*ent=NULL;

    for (itr=head; itr!=NULL && ent==NULL; itr=itr->nx) {
        if (strcmp(ident, itr->ident) == 0) {
            ent = itr;
        }
    }

    return ent;
}


tgtdefn_t *clone_tgtdefn(const tgtdefn_t *orig)
    /** Create (deep) copy of target-definition */
{   tgtdefn_t *clone;

    if (orig == NULL) return NULL;

    clone = (tgtdefn_t*)malloc(sizeof(tgtdefn_t));

    clone->ident = cm_strdup(orig->ident);
    clone->flags = orig->flags;

    clone->dev = cm_strdup(orig->dev);
    clone->sectorsize = orig->sectorsize;
    clone->start = orig->start;
    clone->length = orig->length;
    clone->dir = cm_strdup(orig->dir);
    clone->fstype = cm_strdup(orig->fstype);
    clone->mountoptions = cm_strdup(orig->mountoptions);
    clone->fsckoptions = cm_strdup(orig->fsckoptions);
    clone->loopdev = cm_strdup(orig->loopdev);
    clone->supath = cm_strdup(orig->supath);

    clone->cipher = cm_strdup(orig->cipher);
    clone->ivoffset = orig->ivoffset;

    clone->key.format = cm_strdup(orig->key.format);
    clone->key.filename = cm_strdup(orig->key.filename);
    clone->key.digestalg = cm_strdup(orig->key.digestalg);
    clone->key.cipheralg = cm_strdup(orig->key.cipheralg);
    clone->key.maxlen = orig->key.maxlen;
    clone->key.retries = orig->key.retries;

    clone->nx = NULL;

    return clone;
}


void free_tgtdefn(tgtdefn_t *tgt)
    /** Relinquish storage for a target-structure */
{
    free((void*)tgt->ident);

    free((void*)tgt->dev);
    free((void*)tgt->dir);
    free((void*)tgt->fstype);
    free((void*)tgt->mountoptions);
    free((void*)tgt->fsckoptions);
    free((void*)tgt->loopdev);
    free((void*)tgt->supath);

    free((void*)tgt->cipher);

    free((void*)tgt->key.format);
    free((void*)tgt->key.filename);
    free((void*)tgt->key.digestalg);
    free((void*)tgt->key.cipheralg);

    free((void*)tgt);
}


static void append(char c, char **buff, unsigned *pos, unsigned *bufflen)
    /** Append character to string, reallocating memory as necessary */
{   unsigned newlen;

    if (*pos >= *bufflen) {
        newlen = (*bufflen) * 2 + 64;
        *buff = (char*)realloc(*buff, (size_t)newlen);
        *bufflen = newlen;
    }

    (*buff)[*pos] = c;
    ++(*pos);
}


void expand_variables(char **buff, const char *src)
    /** Expand $(VAR) patterns within a string */
{   const size_t srclen = strlen(src);
    enum { S_PLAIN, S_VAR };
    const char *curs = src;
    char *varname, *varp = NULL;
    int literal = 0;
    unsigned state;
    cm_string_t *result;

    result = cm_str_alloc(64);

    state = S_PLAIN;
    varname = (char*)malloc(srclen * 2);
    for (curs=src; *curs!='\0'; ++curs) {
        if (!literal && *curs == '\\') {
            literal = 1;
            continue;
        }

        switch (state) {
            case S_PLAIN:
                if (!literal && curs[0] == '$' && curs[1] == '(') {
                    /* Mark start of variable term */
                    state = S_VAR;
                    varp = varname;
                    ++curs;
                } else {
                    /* Copy character unchanged into output */
                    cm_str_append_char(result, *curs);
                }
                break;
            case S_VAR:
                if (!literal && *curs == ')') {
                    /* Extract value from dictionary */
                    *varp = '\0';
                    cm_str_append_str(result, query_variable(varname));
                    state = S_PLAIN;
                } else {
                    /* accumulate characters of variable name */
                    *varp = *curs;
                    ++varp;
                }
                break;
            default:
                break;
        }

        literal = 0;
    }
    free((void*)varname);

    if (*buff != NULL) free((void*)(*buff));
    *buff = cm_str_strip(result);
}


#ifdef TESTING

/*! \addtogroup unit_tests
 *  @{ */

int tb_test_expand()
    /** Check variable expansion in configuration-file parser */
{   char answer[1024], *buff = NULL;

    CM_TEST_START("Variable expansion");

    expand_variables(&buff, "nothing here");
    CM_ASSERT_STR_EQUAL("nothing here", buff);

    expand_variables(&buff, "nothing\\ here");
    CM_ASSERT_STR_EQUAL("nothing here", buff);

    expand_variables(&buff, "nothing-$(UID) here");
    sprintf(answer, "nothing-%d here", getuid());
    CM_ASSERT_STR_EQUAL(answer, buff);

    if (buff != NULL) free((void*)buff);

    CM_TEST_OK();
}

/** @} */

#endif  /* TESTING */


static int proc_string(void *ptr, const char *src, const void *config)
    /** Process var=val entry in config-table for "string" type */
{   char **addr = (char**)ptr;

    expand_variables(addr, src);

    return (*addr == NULL);
}


#define PROC_VARVAL(FN_NAME, TYPE, FMT)                             \
    static int FN_NAME(void *ptr, const char *src, const void *x)   \
        /** Process var=val entry in config-table for "TYPE" */     \
    {   TYPE qv, *addr=(TYPE*)ptr;                                  \
        if (sscanf(src, FMT, &qv) == 1) {                           \
            *addr = qv; return 0;                                   \
        }                                                           \
        return 1;                                                   \
    }

PROC_VARVAL(proc_unsigned, unsigned, "%u")
PROC_VARVAL(proc_long, long, "%ld")
PROC_VARVAL(proc_int64, int64_t, "%" SCNi64)

#undef PROC_VARVAL


/**
 *  Convert string of comma-separated configuration-switches
 *  within \a selection into binary flags. A pointer to the (unsigned) flags,
 *  is supplied via \a flagptr, and the set of available switches
 *  is in the form of an array of tgt_option_t, passed via \a menuptr.
 */
int proc_flags(void *flagptr, const char *selection, const void *menuptr)
{   unsigned *flags = (unsigned*)flagptr;
    const tgt_option_t *menu = (const tgt_option_t*)menuptr;
    unsigned idx, len;

    if (selection == NULL) return 0;

    for (;;) {
        for (len=0; selection[len]!='\0' && selection[len]!=','; ++len);
        for (idx=0; menu[idx].name!=NULL; ++idx) {
            if (strncmp(selection, menu[idx].name, (size_t)len) == 0) {
                *flags = (*flags & menu[idx].andmask)
                        | menu[idx].ormask;
                break;
            }
        }
        if (menu[idx].name == NULL) {
            fprintf(stderr, "bad option \"%s\"\n", selection);
            return 1;
        }

        if (selection[len] == '\0') break;
        selection += len + 1;
    }

    return 0;
}


static void read_token(char *buff, unsigned *t_state, tgtdefn_t *tgt)
    /** Process token (word) from configuration-file while parsing */
{   struct tokinfo_t {
        const char *name;
        int varoffset;
        int (*proc)(void *var, const char *val, const void *config);
        const void *config;
    } *tok;
#define OFFSET(x) (int)((char*)&((tgtdefn_t*)NULL)->x - (char*)NULL)
    struct tokinfo_t toktable[] = {
        { "flags",          OFFSET(flags),
                            proc_flags,     setup_options },
        { "bootaction",     OFFSET(flags),
                            proc_flags,     boot_options },
        { "dev",            OFFSET(dev),
                            proc_string,    NULL },
        { "dir",            OFFSET(dir),
                            proc_string,    NULL },
        { "startsector",    OFFSET(start),
                            proc_int64,     NULL },
        { "numsectors",     OFFSET(length),
                            proc_int64,     NULL },
        { "fstype",         OFFSET(fstype),
                            proc_string,    NULL },
        { "mountoptions",   OFFSET(mountoptions),
                            proc_string,    NULL },
    /* FIXME - "fsoptions" was deprecated in version 4.1 - remove by Jan2016 */
        { "fsoptions",      OFFSET(mountoptions),
                            proc_string,    NULL },
        { "fsckoptions",    OFFSET(fsckoptions),
                            proc_string,    NULL },
        { "loop",           OFFSET(loopdev),
                            proc_string,    NULL },
        { "supath",         OFFSET(supath),
                            proc_string,    NULL },
        { "cipher",         OFFSET(cipher),
                            proc_string,    NULL },
        { "ivoffset",       OFFSET(ivoffset),
                            proc_int64,     NULL },
        { "keyformat",      OFFSET(key.format),
                            proc_string,    NULL },
        { "keyfile",        OFFSET(key.filename),
                            proc_string,    NULL },
        { "keyhash",        OFFSET(key.digestalg),
                            proc_string,    NULL },
        { "keycipher",      OFFSET(key.cipheralg),
                            proc_string,    NULL },
        { "keymaxlen",      OFFSET(key.maxlen),
                            proc_long,      NULL },
        { "passwdretries",  OFFSET(key.retries),
                            proc_unsigned,  NULL },
        { NULL, 0, NULL }
    };
#undef OFFSET
    char *eq;

    switch (*t_state) {
        case T_IDENT:
            (void)proc_string((void*)&tgt->ident, buff, NULL);
            *t_state = T_LBRACE;
            break;
        case T_LBRACE:
            *t_state = (strcmp(buff, "{") == 0 ? T_OPT : T_ERROR);
            break;
        case T_OPT:
            if (strcmp(buff, "}") == 0) {
                *t_state = T_RBRACE; break;
            }
            if ((eq = strchr(buff,'=')) == NULL) {
                *t_state = T_ERROR; break;
            }
            *eq = '\0'; ++eq;

            /* Delegate processing to specific token-processor from table: */
            for (tok=toktable; tok->name!=NULL; ++tok) {
                if (strcmp(tok->name, buff) == 0) {
                    (*tok->proc)((void*)((char*)tgt + tok->varoffset),
                                    eq, tok->config);
                    break;
                }
            }
            if (strcmp(buff, "fsoptions") == 0) {
                fprintf(stderr, _("cryptmount: please replace \"fsoptions\" with \"mountoptions\" in cmtab\n"));
                *t_state = T_ERROR;
            }

            if (tok->name == NULL) {
                fprintf(stderr, _("cryptmount: unrecognized option \"%s\" in cmtab\n"), buff);
                *t_state = T_ERROR;
            }
            break;
        default:
            break;
    }
}


tgtdefn_t *parse_stream(FILE *fp, const char *cfgname)
    /** Convert config-file information into linked-list of target-structures */
{   enum { C_SPACE, C_WORD, C_COMMENT };
    int ch, lineno = 1, literal = 0;
    unsigned pos = 0, bufflen = 0;
    unsigned c_state, t_state;
    char *buff = NULL;
    tgtdefn_t *head = NULL, **cmp = &head, *tgt = NULL, *prototype = NULL;

    c_state = C_SPACE;
    t_state = T_IDENT;
    tgt = alloc_tgtdefn(prototype);

    while (!feof(fp) && t_state != T_ERROR) {
        ch = fgetc(fp);
        if (ch == (int)'\n') ++lineno;

        if (literal && ch == (int)'\n') {    /* Ignore escaped end-of-line */
            literal = 0;
            continue;
        }

        if (!literal && ch == (int)'#') c_state = C_COMMENT;
        if (!literal && ch == (int)'\\') {
            /* Treat next character literally */
            literal = 1;
            continue;
        }

        switch (c_state) {
            case C_SPACE:
                if (literal || !isspace(ch)) {
                    pos = 0;
                    append((char)ch, &buff, &pos, &bufflen);
                    c_state = C_WORD;
                }
                break;
            case C_WORD:
                if (literal || !isspace(ch)) {
                    append((char)ch, &buff, &pos, &bufflen);
                } else {
                    append('\0', &buff, &pos, &bufflen);
                    read_token(buff, &t_state, tgt);
                    c_state = C_SPACE;
                }
                break;
            case C_COMMENT:
                if (!literal && ch == '\n') c_state = C_SPACE;
                break;
            default:
                break;
        }

        literal = 0;
        if (t_state == T_RBRACE) {
            /* Parsing has reached end of target definition */

            if (strcmp(tgt->ident, "_DEFAULTS_") == 0) {
                /* New target definition is set of default values */
                if (prototype != NULL) free_tgtdefn(prototype);
                prototype = tgt;
            } else {
                /* New target definition is genuine target */
                *cmp = tgt;
                cmp = &tgt->nx;
            }

            tgt = alloc_tgtdefn(prototype);
            t_state = T_IDENT;
        }
    }

    if (t_state == T_ERROR) {
        fprintf(stderr, _("Configuration error near %s:%d\n"),
                cfgname, lineno);
    }

    if (prototype != NULL) free_tgtdefn(prototype);
    if (tgt != NULL) free_tgtdefn(tgt);
    if (buff != NULL) free((void*)buff);

    return head;
}


tgtdefn_t *parse_config(const char *cfgname)
    /** Convert config-file into linked-list of target-structures */
{   FILE *fp;
    tgtdefn_t *head = NULL;

    fp = fopen(cfgname, "r");
    if (fp == NULL) {
        fprintf(stderr, "failed to open \"%s\"\n", cfgname);
        return NULL;
    }

    head = parse_stream(fp, cfgname);
    fclose(fp);

    return head;
}


tgtdefn_t *parse_config_fd(int fd)
    /** Convert input-stream config-data into target-structures */
{   FILE *fp = NULL;
    tgtdefn_t *head = NULL;
    char label[64];

    fp = fdopen(fd, "r");
    if (fp == NULL) {
        fprintf(stderr, "failed to read input-stream %d\n", fd);
        return NULL;
    }

    snprintf(label, sizeof(label), "stream-%d", fd);
    head = parse_stream(fp, label);

    return head;
}


void free_config(tgtdefn_t **head)
    /** Free all entries in target-config list */
{   tgtdefn_t *cmx;

    if (head == NULL) return;

    while ((cmx = *head) != NULL) {
        *head = cmx->nx;
        free_tgtdefn(cmx);
    }
}



tgtstat_t *alloc_tgtstatus(const tgtdefn_t *tgt)
    /** Create new status record for given target */
{   tgtstat_t *ts;

    ts = (tgtstat_t*)malloc(sizeof(tgtstat_t));
    ts->ident = NULL;
    ts->uid = 0;
    ts->nx = NULL;

    if (tgt != NULL) ts->ident = cm_strdup(tgt->ident);

    return ts;
}


void free_tgtstatus(tgtstat_t *ts)
    /** Free storage of target-status record (or list thereof) */
{   tgtstat_t *tx = NULL;

    while ((tx = ts) != NULL) {
        ts = tx->nx;
        if (tx->ident != NULL) free((void*)tx->ident);
        free((void*)tx);
    }
}


/**
 *  Prepare status-file for reading/writing.
 *
 *  This will perform basic validation on the header
 *  of the status file (typically /var/run/cmstatus).
 *  If the file appears to be corrupted, this function
 *  will return NULL.
 */
struct statfile *statfile_open(const char *fname, const char *mode)
{   struct statfile *sf = NULL;
    char buff[256];
    FILE *fp;

    if ((fp = fopen(fname, mode)) != NULL) {
        sf = (struct statfile*)malloc(sizeof(struct statfile));
        sf->fp = fp;

        if (mode[0] == 'w') {
            sf->version = 0;        /* Format-version for new files */
            fprintf(fp,"# auto-generated by cryptmount - do not edit\n");
            fprintf(fp, "%d\n", sf->version);
        } else {
            if (fgets(buff, (int)sizeof(buff), fp) == NULL
              || fscanf(fp, "%d", &sf->version) != 1) {
                fclose(sf->fp);
                free((void*)sf);
                sf = NULL;
            }
        }
    }

    return sf;
}


/**
 *  Read information about next target from the status-file.
 *
 *  This will typically only be called after acquiring
 *  a lock via cm_mutex_lock().
 */
tgtstat_t *statfile_read(struct statfile *sf)
{   tgtstat_t *ts = NULL;
    char *ident = NULL;
    int len;
    unsigned long uid;

    if (sf == NULL) goto bail_out;

    if (fscanf(sf->fp, "%d,", &len) != 1) goto bail_out;

    ident = (char*)malloc((size_t)(len + 1));
    if (cm_fread((void*)ident, (size_t)(len + 1), sf->fp) != 0) {
        goto bail_out;
    }
    ident[len] = '\0';

    if (fscanf(sf->fp, "%lu", &uid) != 1) goto bail_out;
    if (feof(sf->fp)) goto bail_out;

    ts = alloc_tgtstatus(NULL);
    ts->ident = ident;
    ts->uid = uid;
    ident = NULL;

  bail_out:

    if (ident != NULL) free((void*)ident);

    return ts;
}


/**
 *  Write mount-status information about the given target
 *  into the status-file.
 *
 *  This will typically only be called after acquiring
 *  a lock via cm_mutex_lock().
 */
void statfile_write(struct statfile *sf, const tgtstat_t *stat)
{
    fprintf(sf->fp, "%u,", (unsigned)strlen(stat->ident));
    fprintf(sf->fp, "%s,", stat->ident);
    fprintf(sf->fp, "%lu\n", stat->uid);
}


void statfile_close(struct statfile *sf)
{
#if HAVE_SYNCFS
    syncfs(fileno(sf->fp));
#endif
    fclose(sf->fp);
    free((void*)sf);
}


/*! @brief Find mount/owner status of given target
 *
 *  Read an entry from persistent storage within /run/cryptmount.status
 *  to identify whether the given target is currently mounted
 *  or used as an active swap partition.
 *
 *  Note that any unmount/swapoff operations applied by tools
 *  other than cryptmount are likely to make this metadata unreliable.
 *
 *  \see put_tgtstatus().
 */
tgtstat_t *get_tgtstatus(const tgtdefn_t *tgt)
{   char *fname = NULL;
    tgtstat_t *ts = NULL;
    struct statfile *sf;
    int badlock;

    (void)cm_path(&fname, CM_SYSRUN_PFX, cm_status_filename);
    badlock = cm_mutex_lock();
    sf = statfile_open(fname, "r");
    if (sf == NULL) goto bail_out;

    while ((ts = statfile_read(sf)) != NULL) {
        if (strcmp(tgt->ident, ts->ident) == 0) break;
        else free_tgtstatus(ts);
    }

    statfile_close(sf);

  bail_out:

    if (!badlock) cm_mutex_unlock();
    if (fname != NULL) free((void*)fname);

    return ts;
}


/*! @brief Find list of mount/owner status for all mounted targets.
 *
 *  \see get_tgtstatus(), statfile_read().
 */
tgtstat_t *get_all_tgtstatus()
{   char *fname = NULL;
    tgtstat_t *ts = NULL, *head = NULL, **sfp = &head;
    struct statfile *sf;
    int badlock;

    (void)cm_path(&fname, CM_SYSRUN_PFX, cm_status_filename);
    badlock = cm_mutex_lock();
    sf = statfile_open(fname, "r");
    if (sf == NULL) goto bail_out;

    while ((ts = statfile_read(sf)) != NULL) {
        *sfp = ts;
        sfp = &ts->nx;
    }

    statfile_close(sf);

  bail_out:

    if (!badlock) cm_mutex_unlock();
    if (fname != NULL) free((void*)fname);

    return head;
}


/*! @brief Update mount/owner status of given target
 *
 *  Insert or update an entry from persistent storage
 *  within /run/cryptmount.status to mark the given target
 *  as currently being mounted or used as an active swap partition.
 *
 *  \see get_tgtstatus().
 */
int put_tgtstatus(const tgtdefn_t *tgt, const tgtstat_t *newstat)
{   char *newfname = NULL, *oldfname = NULL;
    struct statfile *sfin, *sfout;
    tgtstat_t *ts = NULL;
    struct stat sbuff;
    int badlock, eflag = 0;

    (void)cm_path(&oldfname, CM_SYSRUN_PFX, cm_status_filename);
    (void)cm_path(&newfname, CM_SYSRUN_PFX, "cmstatus-temp");
    badlock = cm_mutex_lock();

    sfout = statfile_open(newfname, "w");
    if (sfout == NULL) {
        eflag = 1; goto bail_out;
    }

    if (stat(oldfname, &sbuff) == 0) {
        sfin = statfile_open(oldfname, "r");
        if (sfin == NULL) {
            statfile_close(sfout);
            unlink(newfname);
            eflag = 1; goto bail_out;
        }

        /* Copy most entries from existing status-file: */
        while ((ts = statfile_read(sfin)) != NULL) {
            if (strcmp(tgt->ident, ts->ident) != 0) {
                statfile_write(sfout, ts);
            }
            free_tgtstatus(ts);
        }
        statfile_close(sfin);
    }

    /* Add new entry onto end of new status-file: */
    if (newstat != NULL) {
        statfile_write(sfout, newstat);
    }
    statfile_close(sfout);

    /* Overwrite old status-file: */
    if (rename(newfname, oldfname) != 0
      || chown(oldfname, (uid_t)0, (gid_t)0) != 0
      || chmod(oldfname, S_IWUSR|S_IRUSR | S_IRGRP | S_IROTH) != 0) {
        eflag = 1; goto bail_out;
    }

  bail_out:

    if (!badlock) cm_mutex_unlock();
    if (newfname != NULL) free((void*)newfname);
    if (oldfname != NULL) free((void*)oldfname);

    return eflag;
}


/**
 *  Perform basic validation on the contents of the target-status file
 *  (typically /var/run/cmstatus).
 *
 *  @return zero if the file is known to be damaged.
 */
int is_cmstatus_intact()
{   char *fname = NULL;
    struct stat sbuff;
    struct statfile *sf;
    int intact = 1, badlock;

    (void)cm_path(&fname, CM_SYSRUN_PFX, cm_status_filename);
    badlock = cm_mutex_lock();

    if (stat(fname, &sbuff) != 0) {
      /* A missing file is considered to be valid */
      goto bail_out;
    }

    sf = statfile_open(fname, "r");
    if (sf == NULL) {
      intact = 0;
      goto bail_out;
    }

    /* Read each status line, performing basic syntax checking */
    while (intact) {
      unsigned long uid = 0;
      int len = 0, err;

      err = fscanf(sf->fp, "%d,", &len);
      if (err == EOF) break;
      if (err != 1) intact = 0;

      if (len > 1024 || fseek(sf->fp, len, SEEK_CUR) < 0) intact = 0;
      if (fgetc(sf->fp) != ',') intact = 0;

      if (fscanf(sf->fp, "%lu", &uid) != 1) intact = 0;
    }

    statfile_close(sf);

  bail_out:

    if (!badlock) cm_mutex_unlock();
    if (fname != NULL) free((void*)fname);

    return intact;
}

/*
 *  (C)Copyright 2005-2025, RW Penney
 */
