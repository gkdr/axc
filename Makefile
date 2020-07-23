### toolchain
#
CC ?= gcc
AR ?= ar
MKDIR = mkdir
MKDIR_P = mkdir -p
CMAKE ?= cmake
CMAKE_FLAGS = -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS=-fPIC
ARCH := $(shell gcc -print-multiarch)
VER_MAJ = 0
VERSION = 0.3.3

AX_DIR=./lib/libsignal-protocol-c
AX_BDIR=$(AX_DIR)/build/src
AX_PATH=$(AX_BDIR)/libsignal-protocol-c.a

PKG_CONFIG ?= pkg-config
GLIB_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags glib-2.0)
GLIB_LDFLAGS ?= $(shell $(PKG_CONFIG) --libs glib-2.0)

SQLITE3_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags sqlite3)
SQLITE3_LDFLAGS ?= $(shell $(PKG_CONFIG) --libs sqlite3)

SIGNAL_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags libsignal-protocol-c)
SIGNAL_LDFLAGS ?= $(shell $(PKG_CONFIG) --libs libsignal-protocol-c)

LIBGCRYPT_CONFIG ?= libgcrypt-config
LIBGCRYPT_LDFLAGS ?= $(shell $(LIBGCRYPT_CONFIG) --libs)


SDIR = src
LDIR = lib
BDIR = build
TDIR = test
TFN = test_all
CDIR = coverage

PKGCFG_C=$(GLIB_CFLAGS) \
	 $(SQLITE3_CFLAGS) \
	 $(LIBGCRYPT_CFLAGS)

PKGCFG_L=$(GLIB_LDFLAGS) \
	 $(SQLITE3_LDFLAGS) \
	 $(LIBGCRYPT_LDFLAGS)

CPPFLAGS += -D_XOPEN_SOURCE=700 -D_BSD_SOURCE -D_POSIX_SOURCE -D_GNU_SOURCE -D_DEFAULT_SOURCE
PICFLAGS=-fPIC $(CFLAGS)

ifeq ($(OS),Windows_NT)
	HEADERS=-I$(AX_DIR)/src
	CFLAGS += $(HEADERS) $(PKGCFG_C) -std=c11 -g -Wall -Wextra -Wpedantic \
		  -Wstrict-overflow -fno-strict-aliasing -funsigned-char \
		  -fno-builtin-memset
	TESTFLAGS=$(HEADERS) $(PKGCFG_C) -g -O0 --coverage
	LDFLAGS += -pthread -ldl $(PKGCFG_L) $(AX_PATH) -lm
	LDFLAGS_T= -lcmocka $(LDFLAGS)
else
	PKGCFG_C += $(SIGNAL_CFLAGS)
	PKGCFG_L += $(SIGNAL_LDFLAGS)
	CFLAGS += $(PKGCFG_C) -std=c11 -g -Wall -Wextra -Wpedantic \
		  -Wstrict-overflow -fno-strict-aliasing -funsigned-char \
		  -fno-builtin-memset -fstack-protector-strong -Wformat -Werror=format-security
	TESTFLAGS=$(PKGCFG_C) -g -O0 --coverage -fstack-protector-strong -Wformat -Werror=format-security
	LDFLAGS += -pthread -ldl $(PKGCFG_L) -lm
	LDFLAGS_T= -lcmocka $(LDFLAGS)

	ifeq ($(PREFIX),)
		PREFIX := /usr/local
	endif
endif



all: $(BDIR)/libaxc.a shared

$(BDIR):
	$(MKDIR_P) $@

client: $(SDIR)/message_client.c $(BDIR)/axc_store.o $(BDIR)/axc_crypto.o $(BDIR)/axc.o $(AX_PATH)
	$(MKDIR_P) $@
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@/$@.o $(LDFLAGS)

$(BDIR)/axc.o: $(SDIR)/axc.c $(BDIR)
	$(CC) $(PICFLAGS) $(CPPFLAGS) -c $< -o $@

$(BDIR)/axc-nt.o: $(SDIR)/axc.c $(BDIR)
	$(CC) $(PICFLAGS) $(CPPFLAGS) -DNO_THREADS -c $< -o $@

$(BDIR)/axc_crypto.o: $(SDIR)/axc_crypto.c $(BDIR)
	$(CC) $(PICFLAGS) $(CPPFLAGS) -c $< -o $@

$(BDIR)/axc_store.o: $(SDIR)/axc_store.c $(BDIR)
	$(CC) $(PICFLAGS) $(CPPFLAGS) -c $< -o $@

$(BDIR)/libaxc.a: $(BDIR)/axc.o $(BDIR)/axc_crypto.o $(BDIR)/axc_store.o
	$(AR) rcs $@ $^

$(BDIR)/libaxc-nt.a: $(BDIR)/axc-nt.o $(BDIR)/axc_crypto.o $(BDIR)/axc_store.o
	$(AR) rcs $@ $^

$(BDIR)/libaxc.so: $(BDIR)
	$(CC) -shared -Wl,-soname,libaxc.so.$(VER_MAJ) -o $@ $(PICFLAGS) $(SDIR)/axc.c $(SDIR)/axc_crypto.c $(SDIR)/axc_store.c $(LDFLAGS) $(CPPFLAGS)

$(BDIR)/libaxc.pc: $(BDIR)
	echo 'prefix='$(PREFIX) > $@
	echo 'exec_prefix=$${prefix}' >> $@
	echo 'libdir=$${prefix}/lib/$(ARCH)' >> $@
	echo 'includedir=$${prefix}/include' >> $@
	echo 'Name: libaxc' >> $@
	echo 'Version: ${VERSION}' >> $@
	echo 'Description: client library for libsignal-protocol-c' >> $@
	echo 'Requires: libsignal-protocol-c' >> $@
	echo 'Cflags: -I$${includedir}/axc' >> $@
	echo 'Libs: -L$${libdir} -laxc' >> $@

$(AX_PATH):
	cd $(AX_DIR) && \
		$(MKDIR_P) build && \
		cd build && \
		$(CMAKE) $(CMAKE_FLAGS) ..  && \
		$(MAKE)


shared: $(BDIR)/libaxc.so $(BDIR)/libaxc.pc


install: $(BDIR)
	install -d $(DESTDIR)/$(PREFIX)/lib/$(ARCH)/pkgconfig/
	install -m 644 $(BDIR)/libaxc.a  $(DESTDIR)/$(PREFIX)/lib/$(ARCH)/libaxc.a
	install -m 644 $(BDIR)/libaxc.so $(DESTDIR)/$(PREFIX)/lib/$(ARCH)/libaxc.so.$(VERSION)
	install -m 644 $(BDIR)/libaxc.pc $(DESTDIR)/$(PREFIX)/lib/$(ARCH)/pkgconfig/
	install -d $(DESTDIR)/$(PREFIX)/include/axc/
	install -m 644 $(SDIR)/axc.h $(DESTDIR)/$(PREFIX)/include/axc/
	install -m 644 $(SDIR)/axc_crypto.h $(DESTDIR)/$(PREFIX)/include/axc/
	install -m 644 $(SDIR)/axc_store.h $(DESTDIR)/$(PREFIX)/include/axc/

.PHONY: test
test: test_store test_client

.PHONY: test_store
test_store: $(SDIR)/axc_store.c $(SDIR)/axc_crypto.c $(TDIR)/test_store.c
	$(CC) $(TESTFLAGS) -o $(TDIR)/$@.o  $(TDIR)/test_store.c $(SDIR)/axc_crypto.c $(LDFLAGS_T)
	-$(TDIR)/$@.o
	mv *.g* $(TDIR)

.PHONY: test_client
test_client: $(SDIR)/axc.c $(SDIR)/axc_crypto.c  $(SDIR)/axc_store.c $(TDIR)/test_client.c
	$(CC) $(TESTFLAGS) -o $(TDIR)/$@.o $(SDIR)/axc_crypto.c $(TDIR)/test_client.c $(LDFLAGS_T)
	-$(TDIR)/$@.o
	mv *.g* $(TDIR)

.PHONY: coverage
coverage: test
	gcovr -r . --html --html-details -o $@.html
	gcovr -r . -s
	$(MKDIR_P) $@
	mv $@.* $@

.PHONY: clean
clean:
	rm -f $(TDIR)/*.o
	rm -f $(TDIR)/*.gcno $(TDIR)/*.gcda $(TDIR)/*.sqlite
	
.PHONY: clean-all
clean-all: clean
	rm -rf client $(BDIR) $(CDIR) $(AX_DIR)/build


