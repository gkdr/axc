SDIR = src
LDIR = lib
BDIR = build
TDIR = test
TFN = test_all
CDIR = coverage

CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -Wstrict-overflow -fno-strict-aliasing -funsigned-char -D_XOPEN_SOURCE=700 -D_BSD_SOURCE -fno-builtin-memset
LFLAGS = -pthread -ldl -laxolotl-c -lm -lcrypto -lsqlite3

all: client

$(BDIR):
	mkdir -p $@

client: $(SDIR)/message_client.c $(BDIR)/store.o $(BDIR)/crypto.o $(BDIR)/axc.o
	mkdir -p $@
	gcc -D_POSIX_SOURCE -D_XOPEN_SOURCE=700 $(CFLAGS) $^ -o $@/$@.o $(LFLAGS)
	
axc_store: $(SDIR)/axc_store.c $(BDIR)
	libtool --mode=compile gcc -c $< $(CFLAGS) -o $(BDIR)/$@.lo
	
axc_crypto: $(SDIR)/axc_crypto.c $(BDIR)
	libtool --mode=compile gcc -c $< $(CFLAGS) -o $(BDIR)/$@.lo
	
libaxc: $(SDIR)/axc.c axc_store axc_crypto
	libtool --mode=compile gcc -c $< $(CFLAGS) -o $(BDIR)/axc.lo
	libtool --mode=link gcc -o $(BDIR)/$@.la $(BDIR)/axc.lo $(BDIR)/axc_store.lo $(BDIR)/axc_crypto.lo
	
$(BDIR)/axc.o: $(SDIR)/axc.c $(BDIR)
	gcc -D_POSIX_SOURCE -D_GNU_SOURCE $(CFLAGS) -c $< -o $@
	
$(BDIR)/crypto.o: $(SDIR)/axc_crypto.c $(BDIR)
	gcc $(CFLAGS) -c $< -o $@

$(BDIR)/store.o: $(SDIR)/axc_store.c $(BDIR)
	gcc $(CFLAGS) -c $< -o $@
	
.PHONY: test
test: test_store.o test_client.o

.PHONY: test_store.o
test_store.o: $(SDIR)/axc_store.c $(SDIR)/axc_crypto.c $(TDIR)/test_store.c
	gcc --coverage -O0 -o $(TDIR)/$@  $(TDIR)/test_store.c $(SDIR)/axc_crypto.c -lcmocka $(LFLAGS)
	-$(TDIR)/$@
	mv *.g* $(TDIR)
	
test_store: test_store.o
	
.PHONY: test_client.o
test_client.o: $(SDIR)/axc.c $(SDIR)/axc_crypto.c  $(SDIR)/axc_store.c $(TDIR)/test_client.c
	gcc --coverage -O0 -o $(TDIR)/$@ $(SDIR)/axc_crypto.c $(TDIR)/test_client.c -lcmocka $(LFLAGS)
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
	rm -rf client $(BDIR) $(CDIR)
	rm -f $(TDIR)/*.o
	rm -f $(TDIR)/*.gcno $(TDIR)/*.gcda $(TDIR)/*.sqlite
	
	
