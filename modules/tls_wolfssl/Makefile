include ../../Makefile.defs
auto_gen=
NAME=tls_wolfssl.so

DEFS+=-DWOLFSSL_QT

ifeq ($(WOLFSSL_FIPS_ENABLED),)
	LIBS=-L./lib/lib/ -lwolfssl -lm
	DEFS+=-I./lib/include/
	DEPS+=lib/lib/libwolfssl.a

	_makefile_path := $(lastword $(MAKEFILE_LIST))
	MOD_DIR ?= $(shell realpath `dirname $(_makefile_path)`)/modules/tls_wolfssl
else
	ifeq ($(CROSS_COMPILE),)
		SSL_BUILDER=$(shell \
		if pkg-config --exists wolfssl; then \
			echo 'pkg-config wolfssl'; \
		fi)
	endif

	ifneq ($(SSL_BUILDER),)
		DEFS += $(shell $(SSL_BUILDER) --cflags)
		LIBS += $(shell $(SSL_BUILDER) --libs) -lm
	else
		DEFS += -I$(LOCALBASE)/include
		LIBS += -L$(LOCALBASE)/lib -lm
	endif
endif

include ../../Makefile.modules

lib/wolfssl/configure:
ifeq ($(WOLFSSL_FIPS_ENABLED),)
	$(Q)cd ./lib/wolfssl && ./autogen.sh
endif

lib/wolfssl/Makefile: lib/wolfssl/configure
ifeq ($(WOLFSSL_FIPS_ENABLED),)
	$(Q)cd ./lib/wolfssl && \
		env -u DEFS -u CFLAGS -u LDFLAGS -u LIBS ./configure \
		--enable-all --disable-fpecc --disable-examples -disable-aligndata \
		--enable-writedup --enable-tlsv10 --disable-shared --enable-static \
		--disable-jni --disable-crl-monitor \
		--prefix=$(MOD_DIR)/lib \
		--exec-prefix=$(MOD_DIR)/lib C_EXTRA_FLAGS="-fPIC" CFLAGS="-DWOLFSSL_STATIC_RSA";
endif

PATCHED_FILES = lib/wolfssl/src/internal.c lib/wolfssl/src/ssl.c

lib/lib/libwolfssl.a: lib/wolfssl/Makefile $(PATCHED_FILES)
ifeq ($(WOLFSSL_FIPS_ENABLED),)
	$(Q)$(MAKE) -C ./lib/wolfssl install
endif

lib/wolfssl/src/internal.c: lib/patches/wolfssl-internal-memleak-fix.patched

lib/patches/wolfssl-internal-memleak-fix.patched: lib/patches/wolfssl-internal-memleak-fix.patch
ifeq ($(WOLFSSL_FIPS_ENABLED),)
	 $(Q)patch -sNR -p1 -d lib/wolfssl --dry-run < $< || patch -N -p1 -d lib/wolfssl  < $< && cp $< $@
endif

clean:	clean-wolfssl-lib

.PHONY: clean-wolfssl-lib
clean-wolfssl-lib:
ifeq ($(WOLFSSL_FIPS_ENABLED),)
	-@if [ -f ./lib/wolfssl/Makefile ]; then \
		$(MAKE) -C ./lib/wolfssl clean; \
	fi;
	-@patch -stNR -p1 -d lib/wolfssl < lib/patches/wolfssl-internal-memleak-fix.patch
	-@rm -rf ./lib/bin ./lib/include ./lib/lib ./lib/share \
	./lib/wolfssl/Makefile ./lib/wolfssl/configure \
	lib/patches/wolfssl-internal-memleak-fix.patched
endif
