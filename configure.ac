dnl autoconf script for cryptmount
dnl (C)Copyright 2005-2022, RW Penney

dnl run 'aclocal; autoconf; automake -a -c -i; ./configure; make'

AC_INIT(cryptmount, 6.0, cryptmount@rwpenney.uk)
AC_PREREQ(2.59)

test "$sysconfdir" = '${prefix}/etc' && sysconfdir=/etc

SYSPATH="/sbin:/bin:/usr/sbin:/usr/bin"
CM_SYSCONF_DIR="${sysconfdir}/cryptmount"
CM_DEFAULT_SUPATH=${SYSPATH}
CM_DEFAULT_CIPHER="aes-cbc-plain"
LIBS_GCRY=""
LIBS_LUKS=""

AM_INIT_AUTOMAKE([foreign no-dependencies])

AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_SYS_LARGEFILE


AC_SEARCH_LIBS(nanosleep, posix,
    [AC_DEFINE(HAVE_NANOSLEEP,[1],[Define to 1 if you have nanosleep()])],
    [AC_DEFINE(HAVE_NANOSLEEP,[0],[Define to 1 if you have nanosleep()])])

AC_SEARCH_LIBS(tcgetattr, termios,
    [AC_DEFINE(HAVE_TERMIOS,[1],[Define to 1 if you have tcgetattr()])],
    [AC_DEFINE(HAVE_TERMIOS,[0],[Define to 1 if you have tcgetattr()])])


AC_HEADER_STDC
AC_CHECK_HEADERS([errno.h getopt.h mntent.h \
                  linux/fs.h linux/loop.h sys/sysmacros.h])

AC_CHECK_FUNCS([ioctl memset mknod open strncpy syslog])
AC_SEARCH_LIBS(log, m)

AC_C_CONST


dnl --------
dnl allow customization of /run or /var/run
dnl - this will eventually be superseded by $runstatedir in autoconf-2.70
dnl
if test -d /run; then default_sysrundir="/run";
else default_sysrundir="/var/run"; fi
AC_ARG_WITH([sysrundir],
    AS_HELP_STRING([--with-sysrundir=DIR], [directory for run-time state]),
    [sysrundir="${withval}"], [sysrundir="${default_sysrundir}"])
if test "x${sysrundir}" = "xyes" -o "x${sysrundir}" = "xno"; then
    CM_SYSRUN_DIR="${default_sysrundir}"
else
    CM_SYSRUN_DIR="${sysrundir}"
fi


dnl --------
dnl check for (essential) presence of libdevmapper
dnl

AC_CHECK_HEADER([libdevmapper.h],
    [AC_DEFINE(HAVE_LIBDEVMAP,[1],
        [Define to 1 if you have libdevmapper header files])],
    [AC_MSG_ERROR([libdevmapper-devel package is needed to build cryptmount])])
AC_SEARCH_LIBS(dm_task_create, devmapper, [],
    [AC_MSG_ERROR([libdevmapper package is needed to build cryptmount])])
AC_CHECK_DECLS([dm_task_secure_data],
    [], [], [#include <libdevmapper.h>])



dnl --------
dnl libgcrypt key-manager
dnl
AC_CHECK_HEADER([gcrypt.h], [dfltGCRY="yes"], [dfltGCRY="no"])

AC_ARG_WITH([libgcrypt],
    AS_HELP_STRING([--with-libgcrypt],
        [support libgcrypt-encryption of keys]),
    [libgcrypt="${withval}"], [libgcrypt="${dfltGCRY}"])
if test "x${libgcrypt}" = "xyes"; then
    AC_SEARCH_LIBS(gcry_cipher_open, gcrypt,
        [AC_DEFINE(HAVE_LIBGCRYPT, [1],
            [Define to 1 if you have libgcrypt header files])],
        [AC_MSG_ERROR([cannot find libgcrypt libraries])])
else
    AC_DEFINE(HAVE_LIBGCRYPT, [0],
            [Define to 1 to enable libgcrypt support])
fi


dnl --------
dnl OpenSSL emulation with libgcrypt
dnl
AC_ARG_ENABLE([openssl-compat],
    AS_HELP_STRING([--enable-openssl-compat],
        [enable libgcrypt-based OpenSSL compatible key-files (default is YES)]),
    [sslcompat="${enableval}"], [sslcompat="yes"])
if test "x${sslcompat}" = "xyes"; then
    AC_DEFINE(USE_GCRYOSSL, [1],
            [Define to 1 to enable OpenSSL-compatible keys via libgcrypt])
else
    AC_DEFINE(USE_GCRYOSSL, [0])
fi


dnl --------
dnl udev libraries
dnl
AC_ARG_ENABLE([libudev],
    AS_HELP_STRING([--enable-libudev],
        [(EXPERIMENTAL) use libudev for /dev events (default=NO)]),
    [use_libudev="${enableval}"], [use_libudev="no"])
if test "x${use_libudev}" = "xyes"; then
    AC_CHECK_HEADER([libudev.h],
        AC_SEARCH_LIBS(udev_queue_get_queue_is_empty, udev,
                        [udevlib="yes"], [udevlib="no"]),
        [udevlib="no"])
else
    udevlib="no"
fi
if test "x${udevlib}" = "xyes"; then
    AC_DEFINE(HAVE_LIBUDEV, [1],
            [Define to 1 if you have libudev header files])
fi


dnl --------
dnl libcryptsetup libraries (needed for LUKS/cryptsetup key-manager)
dnl
PKG_CHECK_MODULES([libcryptsetup], [libcryptsetup >= 1.4],
                  [libcs="yes"], [libcs="no"])
if test "x${libcs}" = "xyes"; then
    AC_DEFINE(HAVE_LIBCRYPTSETUP, [1],
              [Define to 1 if you have the libcryptsetup header files])
fi


dnl --------
dnl LUKS key-management (implicitly dependent on libgcrypt)
dnl
AC_ARG_ENABLE([luks],
    AS_HELP_STRING([--enable-luks],
        [enable key-management via Linux Unified Key Setup (default is YES)]),
    [use_lukscompat="${enableval}"], [use_lukscompat="${libgcrypt}"])
if test "x${use_lukscompat}" = "xyes" \
        -a \( "x${libgcrypt}" != "xyes" -o "x${libcs}" != "xyes" \); then
    AC_MSG_WARN([LUKS support requires libcryptsetup and libgcrypt libraries])
    use_lukscompat="no"
fi
if test "x${use_lukscompat}" = "xyes"; then
    AC_DEFINE(USE_LUKSCOMPAT, [1],
            [Define to 1 to enable LUKS compatbility layer])
    LIBS="${LIBS} ${libcryptsetup_LIBS}"
    CPPFLAGS="${CPPFLAGS} ${libcryptsetup_CFLAGS}"
    AC_SEARCH_LIBS(crypt_keyslot_change_by_passphrase, libcryptsetup,
                   [AC_DEFINE(HAVE_LIBCRYPTSETUP_1_6, [1],
                                [Is libcryptsetup >= 1.6.0 available?])],
                   [AC_DEFINE(HAVE_LIBCRYPTSETUP_1_6, [0])])
else
    AC_DEFINE(USE_LUKSCOMPAT, [0])
fi
AM_CONDITIONAL(BUILD_LUKSCOMPAT, test "x$use_lukscompat" = "xyes")


dnl --------
dnl delegation of mount/umount functionality
dnl
AC_ARG_ENABLE([delegation],
    AS_HELP_STRING([--enable-delegation],
        [delegate (un)mounting to /bin/(u)mount (default is YES)]),
    [delegation="${enableval}"], [delegation="yes"])
if test "x${delegation}" = "xyes"; then
    dfltERSATZ=0;
else
    dlftERSATZ=1;
fi

AC_CHECK_PROG([ERSATZ_MOUNT], [mount], [${dfltERSATZ}], [1], ${SYSPATH})
AC_PATH_PROG([PATH_MOUNT], [mount], [NOTHING], ${SYSPATH})
AC_CHECK_PROG([ERSATZ_UMOUNT], [umount], [${dfltERSATZ}], [1], ${SYSPATH})
AC_PATH_PROG([PATH_UMOUNT], [umount], [NOTHING], ${SYSPATH})


dnl --------
dnl crypt-swap support
dnl
AC_ARG_ENABLE([cswap],
    AS_HELP_STRING([--enable-cswap],
        [enable crypto-swap support (default is YES)]),
    [use_cswap="${enableval}"], [use_cswap="yes"])
if test "x${use_cswap}" = "xyes"; then
    dfltSWAP=1;
    AC_SEARCH_LIBS(swapon, c, [],
        [AC_MSG_ERROR([swapon() system-call is needed for crypto-swap])])
else
    dfltSWAP=0;
fi
AC_CHECK_PROG([WITH_CSWAP], [mkswap], [${dfltSWAP}], [0], ${SYSPATH})
AC_PATH_PROG([PATH_MKSWAP], [mkswap], [NOTHING], ${SYSPATH})


dnl --------
dnl automatic filesystem checking
dnl
AC_ARG_ENABLE([fsck],
    AS_HELP_STRING([--enable-fsck],
        [check filesystems before mounting (default is YES)]),
    [fsck="${enableval}"], [fsck="yes"])
if test "x${fsck}" = "xyes"; then
    dfltFSCK=1;
else
    dfltFSCK=0;
fi
AC_CHECK_PROG([WITH_FSCK], [fsck], [${dfltFSCK}], [0], ${SYSPATH})
AC_PATH_PROG([PATH_FSCK], [fsck], [NOTHING], ${SYSPATH})


dnl --------
dnl internationalization
dnl
AM_GNU_GETTEXT_VERSION([0.16.1])
AM_GNU_GETTEXT([external])


dnl --------
dnl argv[0] switches of default mode
dnl
AC_ARG_ENABLE([argv0switch],
    AS_HELP_STRING([--enable-argv0switch],
       [default action given by progname (default is NO)]),
    [argv0switch="${enableval}"], [argv0switch="no"])
if test "x${argv0switch}" = "xyes"; then
    AC_DEFINE(WITH_ARGV0, 1, [use program-name to alter default action])
fi


dnl --------
dnl Doxygen documentation
dnl
AC_CHECK_PROG([use_doxygen], [doxygen], [yes], [no], ${SYSPATH})
AC_ARG_WITH([docdir],
    AS_HELP_STRING([--with-docdir],
        [directory for assembling source-code documentation]),
        [], [with_docdir=./DoxyDocs])
if test "x${with_docdir}" != "xno"; then
    DOXYGEN_DOCDIR="${with_docdir}"
fi
AM_CONDITIONAL(HAVE_DOXYGEN, test "x$use_doxygen" = "xyes")
AC_SUBST(DOXYGEN_DOCDIR)


dnl --------
dnl systemd vs sysv boot support
dnl
AC_ARG_WITH([systemd],
    AS_HELP_STRING([--with-systemd],
        [whether boot-up support should be via systemd or sysvinit (default is NO)]))
if test "x${with_systemd}" != "xyes"; then
    true
fi
AM_CONDITIONAL(USE_SYSTEMD, test "x$with_systemd" = "xyes")


dnl --------
dnl substitute variables for location of configuration files etc
dnl
AC_SUBST(CM_SYSCONF_DIR)
AC_SUBST(CM_SYSRUN_DIR)
AC_SUBST(LIBS_GCRY)
AC_SUBST(LIBS_LUKS)
AC_SUBST(CM_DEFAULT_CIPHER)
AC_SUBST(CM_DEFAULT_SUPATH)
AC_DEFINE(CM_DEFAULT_CIPHER, [], [Default filesystem encryption algorithm])
AC_DEFINE_UNQUOTED(CM_DEFAULT_CIPHER, ["${CM_DEFAULT_CIPHER}"])

AC_CONFIG_FILES([
    Makefile
    delegates.h
    man/Makefile
    man/fr/Makefile
    po/Makefile.in
    sysinit/Makefile
    testing/Makefile
    doxygen.conf
])

AC_CONFIG_HEADERS([config.h])

AC_OUTPUT


dnl --------
dnl configuration-summary messages
dnl
eval msg_conf="${CM_SYSCONF_DIR}"
if test "${ERSATZ_MOUNT}" -ne 0; then msg_mount="(internal)"; else msg_mount="${PATH_MOUNT}"; fi
if test "${ERSATZ_UMOUNT}" -ne 0; then msg_umount="(internal)"; else msg_umount="${PATH_UMOUNT}"; fi
if test "${WITH_FSCK}" -ne 0; then msg_fsck="${PATH_FSCK}"; else msg_fsck="(disabled)"; fi
msg_gcry="${libgcrypt}"
if test "x${libgcrypt}" = "xyes"; then
    if test "x${sslcompat}" = "xyes"; then msg_gcry="${msg_gcry} (with OpenSSL emulator)"; else msg_gcry="${msg_gcry} (without OpenSSL emulator)"; fi
fi
msg_luks="${use_lukscompat}"

AC_MSG_NOTICE([

    cryptmount-${PACKAGE_VERSION} is now configured with:

        Source location:                $srcdir
        Installation prefix:            $prefix
        Configuration directory:        $msg_conf
        Run-state directory:            ${CM_SYSRUN_DIR}
        Filesystem mounting:            $msg_mount
        Filesystem unmounting:          $msg_umount
        Filesystem checking:            $msg_fsck
        Crypto-swap support:            $use_cswap
        libgcrypt support:              $msg_gcry
        libudev support (EXPERIMENTAL): $udevlib
        LUKS support:                   $msg_luks

])

dnl vim: set ts=4 sw=4 et:
