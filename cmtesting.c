/*
 *  Methods for unit-testing utiltities for cryptmount
 *  (C)Copyright 2006-2023, RW Penney
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

#ifdef TESTING

#include "config.h"

#include <stdio.h>

#include "cmtesting.h"


/*! \addtogroup unit_tests
 *  @{ */


static void cm_tests_init();
static int cm_tests_close();


static void cm_tests_init()
{   int i;

    test_ctxtptr->current = NULL;
    test_ctxtptr->tests_run = 0;
    for (i=0; i<CM_TEST_LAST; ++i) {
        test_ctxtptr->test_stats[i] = 0;
    }
}


int cm_tests_close()
{   int i,nt;

    for (i=0,nt=0; i<CM_TEST_LAST; ++i) {
        nt += test_ctxtptr->test_stats[i];
    }

    if (nt != test_ctxtptr->tests_run) {
        fprintf(stderr, "mismatch in test-statistics (%d != %d)\n",
                nt, test_ctxtptr->tests_run);
    }

    if (test_ctxtptr->test_stats[CM_TEST_PASSED] == test_ctxtptr->tests_run) {
        fprintf(stderr, "++++ all %d tests PASSED ++++\n", test_ctxtptr->tests_run);
    } else {
        fprintf(stderr, "!!!! %2d tests FAILED !!!!\n",
            test_ctxtptr->test_stats[CM_TEST_FAILED]);
        fprintf(stderr, "!!!! %2d tests passed !!!!\n",
            test_ctxtptr->test_stats[CM_TEST_PASSED]);
        fprintf(stderr, "!!!! %2d tests aborted !!!!\n",
            test_ctxtptr->test_stats[CM_TEST_ABORTED]);
    }

    return (test_ctxtptr->test_stats[CM_TEST_PASSED] != test_ctxtptr->tests_run);
}


int cm_run_tests()
    /* Front-end to self-testing routines */
{
    int bf_test_blowfish(),
        fs_test_blkgetsz(), fs_test_splitopts(), fs_test_entropy(),
        km_test_managers(), km_test_keyrw(), km_test_legacy(),
        tb_test_expand(),
        ut_test_strings(), ut_test_strops(), ut_test_sha1(), ut_pwfort();

    cm_tests_init();

    ut_test_strings();
    ut_test_strops();
    tb_test_expand();
    fs_test_blkgetsz();
    fs_test_splitopts();
    fs_test_entropy();
    ut_test_sha1();
    ut_pwfort();
    bf_test_blowfish();

    km_test_managers();
    km_test_keyrw();
    km_test_legacy();

    return cm_tests_close();
}

/** @} */

#else   /* !TESTING */

int _keep_ansi_pedantic_quiet = 0;

#endif  /* TESTING */

/*
 *  (C)Copyright 2006-2023, RW Penney
 */
