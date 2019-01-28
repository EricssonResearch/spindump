
all:
	(cd src; $(MAKE) all)

test:
	(cd src; $(MAKE) test)

install:
	(cd src; $(MAKE) install)

uninstall:
	(cd src; $(MAKE) uninstall)

clean:
	(cd src; $(MAKE) clean)

wc:
	(cd src; $(MAKE) wc)
