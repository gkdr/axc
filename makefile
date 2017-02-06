SDIR = src
LDIR = lib
BDIR = build
TDIR = test
TFN = test_all
CDIR = coverage

AX_DIR=./lib/libaxolotl-c
AX_BDIR=$(AX_DIR)/build/src

PKGCFG_C=$(shell pkg-config --cflags sqlite3 glib-2.0) $(shell libgcrypt-config --cflags)
PKGCFG_L=$(shell pkg-config --libs sqlite3 glib-2.0) $(shell libgcrypt-config --libs)

HEADERS=-I$(AX_DIR)/src
CFLAGS=$(HEADERS) $(PKGCFG_C) -std=c11 -Wall -Wextra -Wpedantic -Wstrict-overflow -fno-strict-aliasing -funsigned-char -D_XOPEN_SOURCE=700 -D_BSD_SOURCE -D_POSIX_SOURCE -D_GNU_SOURCE -fno-builtin-memset
TESTFLAGS=$(HEADERS) $(PKGCFG_C) -g -O0 --coverage
PICFLAGS=-fPIC $(CFLAGS)
LFLAGS = -pthread -ldl $(PKGCFG_L) $(AX_BDIR)/libaxolotl-c.a -lm
LFLAGS_T= -lcmocka $(LFLAGS)

all: client

$(BDIR):
	mkdir -p $@

client: $(SDIR)/message_client.c $(BDIR)/store.o $(BDIR)/crypto.o $(BDIR)/axc.o
	mkdir -p $@
	gcc -D_POSIX_SOURCE -D_XOPEN_SOURCE=700 $(CFLAGS) $^ -o $@/$@.o $(LFLAGS)
	
$(BDIR)/axc.o: $(SDIR)/axc.c $(BDIR)
	gcc -D_POSIX_SOURCE -D_GNU_SOURCE $(CFLAGS) -c $< -o $@
	
$(BDIR)/crypto.o: $(SDIR)/axc_crypto.c $(BDIR)
	gcc $(CFLAGS) -c $< -o $@

$(BDIR)/store.o: $(SDIR)/axc_store.c $(BDIR)
	gcc $(CFLAGS) -c $< -o $@
	
axc.o: $(SDIR)/axc.c $(BDIR)
	gcc $(PICFLAGS) -c $< -o $(BDIR)/$@
	
axc_crypto.o: $(SDIR)/axc_crypto.c $(BDIR)
	gcc $(PICFLAGS) -c $< -o $(BDIR)/$@

axc_store.o: $(SDIR)/axc_store.c $(BDIR)
	gcc $(PICFLAGS) -c $< -o $(BDIR)/$@
	
axc-pic: axc.o axc_crypto.o axc_store.o

libax:
	cd $(AX_DIR) && mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug .. && make
	
.PHONY: test
test: libax test_store.o test_client.o

.PHONY: test_store.o
test_store.o: $(SDIR)/axc_store.c $(SDIR)/axc_crypto.c $(TDIR)/test_store.c
	gcc $(TESTFLAGS) -o $(TDIR)/$@  $(TDIR)/test_store.c $(SDIR)/axc_crypto.c $(LFLAGS_T)
	-$(TDIR)/$@
	mv *.g* $(TDIR)
	
test_store: test_store.o
	
.PHONY: test_client.o
test_client.o: $(SDIR)/axc.c $(SDIR)/axc_crypto.c  $(SDIR)/axc_store.c $(TDIR)/test_client.c
	gcc $(TESTFLAGS) -g $(HEADERS) -o $(TDIR)/$@ $(SDIR)/axc_crypto.c $(TDIR)/test_client.c $(LFLAGS_T)
	-$(TDIR)/$@
	mv *.g* $(TDIR)
	
test_client: test_client.o	
	
.PHONY: coverage
coverage: test
	gcovr -r . --html --html-details -o $@.html
	gcovr -r . -s
	mkdir -p $@
	mv $@.* $@
	 
.PHONY: clean
clean:
	rm -rf client $(BDIR) $(CDIR) $(AX_DIR)/build
	rm -f $(TDIR)/*.o
	rm -f $(TDIR)/*.gcno $(TDIR)/*.gcda $(TDIR)/*.sqlite
	
	
