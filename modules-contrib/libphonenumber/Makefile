# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=libphonenumber.so

_makefile_path := $(lastword $(MAKEFILE_LIST))
MOD_DIR ?= $(shell realpath `dirname $(_makefile_path)`)/modules-contrib/libphonenumber

# The C++ compiler follows the C one (gcc[-N] -> g++[-N], clang[-N] ->
# clang++[-N], also through ccache), unless explicitly set
ifeq ($(origin CXX),default)
CXX := $(shell echo '$(CC)' | sed -e 's/gcc\(-[0-9.]*\)\{0,1\}$$/g++\1/' \
	-e 's/clang\(-[0-9.]*\)\{0,1\}$$/clang++\1/' -e 's/\bcc$$/c++/')
endif

# the C++ wrapper is not picked up by the generic (.c only) rules
override extra_objs+=pn_lib.o

# the wrapper is only called from within the module: export nothing from it
LPN_CXXFLAGS=-std=c++17 -fPIC -Wall -fvisibility=hidden -fvisibility-inlines-hidden

ifneq ($(LPN_USE_SYSTEM),yes)
#
# Default: build the bundled libphonenumber (lib/libphonenumber submodule)
# as a static, position independent library and link it into the module.
# The bundled abseil (lib/abseil-cpp, the LTS version pinned by
# libphonenumber) is always used, offline, so that every build is identical
# whatever abseil the system has; it lives in its own versioned namespace and
# is not exported, so it cannot clash with a system abseil loaded by another
# library. Build requirements: cmake, pkg-config, protobuf (library + protoc)
# and ICU development files.
#
# libphonenumber builds itself with "-Wall -Werror": its (and abseil's) own
# warnings are silenced (-w), so that newer compilers flagging third party
# code cannot break the module build.
#
LPN_SRC_DIR   = lib/libphonenumber/cpp
LPN_ABSL_DIR  = $(MOD_DIR)/lib/abseil-cpp
LPN_BUILD_DIR = lib/build
LPN_PREFIX    = $(MOD_DIR)/lib/install
LPN_LIB       = lib/install/lib/libphonenumber.a
LPN_LINK_RSP  = lib/install/link.rsp
# parallelism of the bundled build, unless already run under "make -j"
LPN_JOBS     ?= $(shell nproc 2>/dev/null || echo 2)

LPN_CMAKE_FLAGS = \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_C_COMPILER="$(CC)" \
	-DCMAKE_CXX_COMPILER="$(CXX)" \
	-DCMAKE_CXX_STANDARD=17 \
	-DCMAKE_C_FLAGS=-w \
	-DCMAKE_CXX_FLAGS=-w \
	-DCMAKE_POSITION_INDEPENDENT_CODE=ON \
	-DCMAKE_INSTALL_PREFIX=$(LPN_PREFIX) \
	-DCMAKE_INSTALL_LIBDIR=lib \
	-DBUILD_SHARED_LIBS=OFF \
	-DBUILD_STATIC_LIB=ON \
	-DBUILD_TESTING=OFF \
	-DBUILD_GEOCODER=OFF \
	-DREGENERATE_METADATA=OFF \
	-DUSE_BOOST=OFF \
	-DUSE_STDMUTEX=ON \
	-DUSE_ICU_REGEXP=ON \
	-DABSL_PROPAGATE_CXX_STD=ON \
	-DABSL_BUILD_TESTING=OFF \
	-DCMAKE_DISABLE_FIND_PACKAGE_absl=ON \
	-DFETCHCONTENT_FULLY_DISCONNECTED=ON \
	-DFETCHCONTENT_SOURCE_DIR_ABSEIL-CPP=$(LPN_ABSL_DIR) \
	-Wno-dev

# the bundled headers must see the same threading backend as the library
LPN_CXXFLAGS += -I$(LPN_PREFIX)/include -DI18N_PHONENUMBERS_USE_STDMUTEX

# the link flags are only known once the library is built, so they are
# passed through a response file which is read at link time; the static
# libraries' symbols are not exported by the module
LIBS += @$(LPN_LINK_RSP)
DEPS += $(LPN_LINK_RSP)

else
#
# LPN_USE_SYSTEM=yes: link against an installed libphonenumber (>= 8.12),
# optionally from a custom prefix (e.g. LPN_PREFIX=/opt/libphonenumber)
#
LPN_PREFIX ?= $(LOCALBASE)
LPN_CXXFLAGS += -I$(LPN_PREFIX)/include
LIBS += -L$(LPN_PREFIX)/lib -lphonenumber -lstdc++
endif

include ../../Makefile.modules

ifneq ($(LPN_USE_SYSTEM),yes)
$(LPN_SRC_DIR)/CMakeLists.txt:
	@echo "ERROR: $(MOD_DIR)/lib/libphonenumber is missing, run:" \
		"git submodule update --init --recursive" >&2
	@false

$(LPN_LIB): $(LPN_SRC_DIR)/CMakeLists.txt
	$(Q)cmake -S $(LPN_SRC_DIR) -B $(LPN_BUILD_DIR) $(LPN_CMAKE_FLAGS)
	$(Q)cmake --build $(LPN_BUILD_DIR) --target install \
		$(if $(findstring jobserver,$(MAKEFLAGS)),,--parallel $(LPN_JOBS)) \
		-- $(if $(FASTER),-s)
	$(Q)touch $@

# libphonenumber's link dependencies: the bundled (static) abseil, protobuf
# and ICU, all resolved through pkg-config
$(LPN_LINK_RSP): $(LPN_LIB)
	$(Q)set -e; \
	export PKG_CONFIG_PATH="$(LPN_PREFIX)/lib/pkgconfig$${PKG_CONFIG_PATH:+:$$PKG_CONFIG_PATH}"; \
	{ \
		echo "-Wl,--exclude-libs,ALL"; \
		echo "-Wl,--start-group"; \
		echo "$(MOD_DIR)/$(LPN_LIB)"; \
		pkg-config --libs absl_node_hash_set absl_strings absl_synchronization; \
		echo "-Wl,--end-group"; \
		pkg-config --libs protobuf icu-i18n icu-uc; \
		echo "-lstdc++ -lpthread"; \
	} > $@.tmp; \
	mv $@.tmp $@

pn_lib.o: $(LPN_LIB)
endif

pn_lib.o: pn_lib.cpp pn_lib.h $(ALLDEP)
ifeq (,$(FASTER))
	@echo "Compiling $<"
endif
	$(Q)$(CXX) $(CXXFLAGS) $(LPN_CXXFLAGS) $(DEBUGSYM) -c $< -o $@

clean: clean-pn-lib

.PHONY: clean-pn-lib
clean-pn-lib:
	-@rm -f pn_lib.o
	-@rm -rf lib/build lib/install
