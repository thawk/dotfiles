PREFIX:=/usr
BINDIR:=${PREFIX}/bin
MANDIR:=${PREFIX}/share/man
LIBDIR:=${PREFIX}/share/mr
LIBSHDIR:=${PREFIX}/share/mr.sh
EGDIR:=${PREFIX}/share/doc/myrepos/examples
TEST_PREFIX:=./

mans=mr.1 webcheckout.1

build: $(mans)

mr.1: mr
	pod2man -c mr mr | sed s/mailto:// > mr.1

webcheckout.1: webcheckout
	pod2man -c webcheckout webcheckout | sed s/mailto:// > webcheckout.1

test:
	(echo "[.]"; echo "checkout=") > .mrconfig
	HOME='${CURDIR}' ${TEST_PREFIX}mr --trust-all ed | grep -q "horse"
	rm -f .mrconfig

install: build
	install -d ${DESTDIR}${BINDIR}
	install -d ${DESTDIR}${MANDIR}/man1
	install -d ${DESTDIR}${LIBDIR}
	install -d ${DESTDIR}${LIBSHDIR}
	install -d ${DESTDIR}${EGDIR}

	install -m0755 mr ${DESTDIR}${BINDIR}/
	install -m0755 webcheckout ${DESTDIR}${BINDIR}/

	install -m0644 mr.1 ${DESTDIR}${MANDIR}/man1/
	install -m0644 webcheckout.1 ${DESTDIR}${MANDIR}/man1/

	install -m0644 lib/* ${DESTDIR}${LIBDIR}/
	install -m0644 lib.sh/* ${DESTDIR}${LIBSHDIR}/

	install -m0644 mrconfig ${DESTDIR}${EGDIR}/
	install -m0644 mrconfig.complex ${DESTDIR}${EGDIR}/
clean:
	rm -f $(mans)
