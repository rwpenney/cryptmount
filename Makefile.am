# automake script for 'cryptmount'
# RW Penney, November 2005

ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -DCM_SYSCONF_DIR="\"$(CM_SYSCONF_DIR)\"" \
		-DCM_SYSRUN_DIR="\"$(CM_SYSRUN_DIR)\""

bin_PROGRAMS=cryptmount
cryptmount_SOURCES=cryptmount.c cryptmount.h \
	armour.c armour.h \
	armour-builtin.c armour-gcry.c armour-luks.c \
	blowfish.c blowfish.h \
	dmutils.c dmutils.h \
	fsutils.c fsutils.h \
	looputils.c looputils.h \
	tables.c tables.h \
	utils.c utils.h \
	cmtesting.c cmtesting.h
cryptmount_NONHEADERS = $(shell echo "${cryptmount_SOURCES}" | sed 's%\<[^ ]*\.h\>%%g')

if BUILD_LUKSCOMPAT
cryptmount_LDADD = ${libcryptsetup_LIBS}
endif

localedir=$(datadir)/locale
AM_CPPFLAGS += -DLOCALEDIR=\"$(localedir)\"
EXTRA_DIST = config.rpath mkinstalldirs cmtab.example \
	INSTALL.md README.md README.sshfs RELNOTES cryptmount.spec \
	debian/changelog debian/control \
	debian/copyright debian/docs \
	debian/rules debian/cryptmount.lintian-overrides \
	debian/postinst debian/postrm debian/watch debian/source/format \
	debian/upstream/signing-key.asc

SUBDIRS = man po sysinit testing


install-exec-hook:	install-etcdir
	chown root:root $(DESTDIR)$(bindir)/cryptmount$(EXEEXT)
	chmod u+srwx,go-w,go+r $(DESTDIR)$(bindir)/cryptmount$(EXEEXT)
	@if test -z "$(DESTDIR)" -o "$(DESTDIR)" = "/"; then \
		modprobe -a loop dm-crypt || true; \
		( egrep -q '\<device-mapper\>' /proc/devices \
			&& egrep -q '\<loop\>' /proc/devices ) || \
		echo "Warning: kernel support for /dev/loop and /dev/mapper is needed by cryptmount"; \
	fi


.PHONY:	install-etcdir
install-etcdir:
	if test ! -d "${DESTDIR}${CM_SYSCONF_DIR}" ; then \
	    ${mkdir_p} "${DESTDIR}${CM_SYSCONF_DIR}" ; \
	fi
	if test ! -f "${DESTDIR}${CM_SYSCONF_DIR}/cmtab" ; then \
	    echo -e "# ${CM_SYSCONF_DIR}/cmtab - encrypted filesystem information for cryptmount\n# try 'man 8 cryptmount' or 'man 5 cmtab' for more details\n# or refer to ${CM_SYSCONF_DIR}/cmtab.example\n" >> "${DESTDIR}${CM_SYSCONF_DIR}/cmtab"; \
	fi
	${mkdir_p} "${DESTDIR}$(datarootdir)/doc/cryptmount/examples"
	${INSTALL_PROGRAM_ENV} ${INSTALL_DATA} cmtab.example "${DESTDIR}$(datarootdir)/doc/cryptmount/examples/cmtab"


install-setup:	setupscript
	test -d "${DESTDIR}${sbindir}" || ${mkdir_p} "${DESTDIR}${sbindir}"
	${INSTALL_PROGRAM_ENV} ${INSTALL_SCRIPT} setupscript "${DESTDIR}${sbindir}/cryptmount-setup"


clean-local:
	-rm -f splint.log

dist-hook:
	sed -e "s,^\(Version:\s*\)[0-9].*,\1${VERSION}," cryptmount.spec > cm_spec.new; cmp -s cryptmount.spec cm_spec.new || mv cm_spec.new cryptmount.spec; rm -f cm_spec.new

pedantic:	CFLAGS = -Wall -W -pedantic -g
pedantic:	${bin_PROGRAMS}

if HAVE_DOXYGEN
doxydocs:	doxygen.conf
	doxygen doxygen.conf
endif

.PHONY:	splint
splint:
	@echo -n "" > splint.log
	for src in ${cryptmount_NONHEADERS}; do \
		echo "==== $${src} ====" >> splint.log; \
		splint ${DEFS} ${DEFAULT_INCLUDES} ${INCLUDES} ${AM_CPFLAGS} ${CPPFLAGS} -D__signed__="" -posix-lib -checks $${src} >> splint.log 2>&1 ; \
		echo -e "\n\n" >> splint.log || true; \
	done

# 'cmtest' target is for use with 'mudslinger' testing script:
cmtest:	CFLAGS = -Wall -g -DTESTING -DCM_SRCDIR=\"${abs_srcdir}\"
cmtest:	${bin_PROGRAMS}
	${MAKE} -C testing autokeys mudslinger

test:	cmtest
	cd testing && sudo ./mudslinger

.PHONY:	depend
depend:
	${CC} -MM ${DEFS} ${DEFAULT_INCLUDES} ${INCLUDES} ${AM_CPFLAGS} ${CPPFLAGS} ${cryptmount_NONHEADERS} > .depend
-include .depend
