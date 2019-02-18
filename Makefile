
all:	spindump.tar.gz
	(cd src; $(MAKE) all)

test:
	(cd src; $(MAKE) test)

install:
	(cd src; $(MAKE) install)

uninstall:
	(cd src; $(MAKE) uninstall)

clean:
	(cd src; $(MAKE) clean)
	-rm -f spindump.tar.gz
	-rm -f spindump.debug
	-rm -f spindump.error

spindump.tar.gz:	src/*.h	src/*.c src/Makefile README.md Makefile LICENSE.txt
	-rm -f spindump.tar.gz
	tar czf spindump.tar.gz Makefile README.md LICENSE.txt \
				images/*.jpg images/*.png \
				src/Makefile src/*.h src/*.c

wc:
	(cd src; $(MAKE) wc)
