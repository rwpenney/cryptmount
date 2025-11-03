# automake script for cryptmount testing suite
# RW Penney, March 2014

EXTRA_DIST = mudslinger.in passwd.fs

KEYHEADERS =	$(shell ls keys/*.hdr)
AUTOKEYS =	$(KEYHEADERS:%.hdr=%)

clean-local:
	-rm -f mudslinger-*-*.log
	-rm -f ${AUTOKEYS}

dist-hook:
	mkdir "${distdir}/keys"; cp -p "${srcdir}/keys"/[0-9]* "${distdir}/keys/"
	for k in ${AUTOKEYS}; do if test -f "${distdir}/$${k}"; then rm "${distdir}/$${k}"; fi; done

mudslinger:	mudslinger.in
	sed -e 's,@PKG_VERSION@,$(PACKAGE_VERSION),g' $< > $@
	chmod +x mudslinger

autokeys:	${AUTOKEYS}

${AUTOKEYS}:	${KEYHEADERS} Makefile.am
	for k in ${AUTOKEYS}; do \
		cp $${k}.hdr $${k}; \
		dd if=/dev/zero of=$${k} bs=1M count=2 \
			conv=notrunc oflag=append; done
