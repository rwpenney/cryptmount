# automake script for cryptmount testing suite
# RW Penney, March 2014

EXTRA_DIST = mudslinger.in passwd.fs

KEYHEADERS =	$(shell ls keys/*.hdr)
AUTOKEYS =	$(KEYHEADERS:%.hdr=%)

clean-local:
	-rm -f mudslinger-*-*.log
	-rm -f ${AUTOKEYS}

dist-hook:
	mkdir ${distdir}/keys; cp -p ${srcdir}/keys/[0-9]* ${distdir}/keys/

mudslinger:	mudslinger.in
	sed -e 's,@PKG_VERSION@,$(PACKAGE_VERSION),g' \
		-e 's,@CM_KEYMODS@,$(CM_MODULES),g' $< > $@
	chmod +x mudslinger

autokeys:	${AUTOKEYS}

${AUTOKEYS}:	${KEYHEADERS}
	for k in ${AUTOKEYS}; do \
		cp $${k}.hdr $${k}; \
		dd if=/dev/zero of=$${k} bs=32k count=64 \
			conv=notrunc oflag=append; done
