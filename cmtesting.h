/*
 *  Declarations for unit-test utilities for cryptmoumt
 *  (C)Copyright 2006-2025, RW Penney
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


#ifndef _CMTEST_H
#define _CMTEST_H

#include "config.h"

/*! \addtogroup unit_tests
 *  @{ */

enum {
    CM_TEST_PASSED = 0,
    CM_TEST_FAILED,
    CM_TEST_ABORTED,
    CM_TEST_LAST
};

enum {
    CM_READONLY =   0x001,              /* Omit tests of key-creation */
    CM_HASLEGACY =  0x002               /* Test against legacy key files */
};


typedef struct cm_testinfo {
    const char *current;                /* name of current test */
    int tests_run;                      /* total number of tests initiated */
    int test_stats[CM_TEST_LAST];       /* statistics of test outcomes */

    const char *argconfigdir;           /* adjustable config-directory */
} cm_testinfo_t;
extern cm_testinfo_t *test_ctxtptr;


#define CM_TEST_START(name) \
    { \
        fprintf(stderr, "starting test \"%s\"...", name); \
        ++test_ctxtptr->tests_run; \
        test_ctxtptr->current = NULL; \
    }

#define CM_TEST_IDENT(ident) \
    { \
        test_ctxtptr->current = (const char*)ident; \
    }

#define CM_ASSERT_EQUAL(expected, actual) \
    if ((expected) != (actual)) { \
        fprintf(stderr, "  test failed %s:%d  (%s != %s)\n", \
                 __FILE__, __LINE__, #expected, #actual); \
        if (test_ctxtptr->current != NULL) { \
            fprintf(stderr, "    [%s]\n", test_ctxtptr->current); } \
        ++test_ctxtptr->test_stats[CM_TEST_FAILED]; \
        return CM_TEST_FAILED; \
    }

#define CM_ASSERT_STR_EQUAL(expected, actual) \
    if (strcmp(expected, actual) != 0) { \
        fprintf(stderr, "  test failed %s:%d  (\"%s\" != \"%s\")\n", \
                 __FILE__, __LINE__, expected, actual); \
        if (test_ctxtptr->current != NULL) { \
            fprintf(stderr, "    [%s]\n", test_ctxtptr->current); } \
        ++test_ctxtptr->test_stats[CM_TEST_FAILED]; \
        return CM_TEST_FAILED; \
    }

#define CM_ASSERT_DIFFERENT(expected, actual) \
    if ((expected) == (actual)) { \
        fprintf(stderr, "  test failed %s:%d\n  (%s == %s)", \
                 __FILE__, __LINE__, #expected, #actual); \
        if (test_ctxtptr->current != NULL) { \
            fprintf(stderr, "    [%s]\n", test_ctxtptr->current); } \
        ++test_ctxtptr->test_stats[CM_TEST_FAILED]; \
        return CM_TEST_FAILED; \
    }

#define CM_TEST_OK(TI) \
    { \
        fprintf(stderr, " ok\n"); \
        ++test_ctxtptr->test_stats[CM_TEST_PASSED]; \
        return CM_TEST_PASSED; \
    }

#define CM_TEST_FAIL(TI) \
    { \
        fprintf(stderr, " FAILED at %s:%d\n", __FILE__, __LINE__); \
        if (test_ctxtptr->current != NULL) { \
            fprintf(stderr, "    [%s]\n", test_ctxtptr->current); } \
        ++test_ctxtptr->test_stats[CM_TEST_FAILED]; \
        return CM_TEST_FAILED; \
    }

#define CM_TEST_ABORT(TI) \
    { \
        fprintf(stderr, " ABORTED at %s:%d\n", __FILE__, __LINE__); \
        if (test_ctxtptr->current != NULL) { \
            fprintf(stderr, "    [%s]\n", test_ctxtptr->current); } \
        ++test_ctxtptr->test_stats[CM_TEST_ABORTED]; \
        return CM_TEST_ABORTED; \
    }


int cm_run_tests();

/**  @} */

#endif  /* _CMTEST_H */

/*
 *  (C)Copyright 2006-2025, RW Penney
 */
