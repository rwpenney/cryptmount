# automake script for cryptmount system-startup mechanisms
# RW Penney, April 2013

EXTRA_DIST = cryptmount.service.in modules-load.conf \
	setupscript.sh.in initscript.in

scripttransform='s,@EXENAME@,$(bindir)/cryptmount$(EXEEXT),g; \
		s,@SYSCONF_DIR@,$(CM_SYSCONF_DIR),g; \
		s,@PKG_NAME@,$(PACKAGE_NAME),g; \
		s,@PKG_VERSION@,$(VERSION),g; \
		s,@LCL_DIR@,$(localedir),g'


initscript:	initscript.in
	sed ${scripttransform} $< > $@

cryptmount.service:	cryptmount.service.in
	sed ${scripttransform} $< > $@

setupscript:	setupscript.sh.in
	sed ${scripttransform} $< > $@


install-exec-hook:	install-inits install-setup


install-inits:	cryptmount.service initscript
if USE_SYSTEMD
	test -d "${DESTDIR}${CM_SYSD_UNITDIR}" || ${mkdir_p} "${DESTDIR}${CM_SYSD_UNITDIR}"
endif	# USE_SYSTEMD
	if test -d "${DESTDIR}${CM_SYSD_UNITDIR}" ; then \
	    ${INSTALL_PROGRAM_ENV} ${INSTALL_DATA} cryptmount.service "${DESTDIR}${CM_SYSD_UNITDIR}"; \
	fi
	test -d "${DESTDIR}/etc/modules-load.d" || ${mkdir_p} "${DESTDIR}/etc/modules-load.d"
	${INSTALL_PROGRAM_ENV} ${INSTALL_DATA} modules-load.conf "${DESTDIR}/etc/modules-load.d/cryptmount.conf";
if !USE_SYSTEMD
	test -d "${DESTDIR}/etc/init.d" -o -d "${DESTDIR}/etc/rc.d/init.d" || ${mkdir_p} "${DESTDIR}/etc/init.d"
	for initdir in /etc/init.d /etc/rc.d/init.d; do \
	    if test -d "${DESTDIR}$${initdir}" ; then \
	        ${INSTALL_PROGRAM_ENV} ${INSTALL_SCRIPT} initscript "${DESTDIR}$${initdir}/cryptmount" ; \
	        break; \
	    fi; \
	done
endif	# !USE_SYSTEMD


install-setup:	setupscript
	test -d "${DESTDIR}${sbindir}" || ${mkdir_p} "${DESTDIR}${sbindir}"
	${INSTALL_PROGRAM_ENV} ${INSTALL_SCRIPT} setupscript "${DESTDIR}${sbindir}/cryptmount-setup"


clean-local:
	-rm -f cryptmount.service initscript setupscript
