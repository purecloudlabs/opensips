include ../../Makefile.defs

NAME=crypto.so

$NAME:
	-@MAKE_DEFS="$$(echo "$${DEFS}" | xargs) " \
		zig build -Doptimize=ReleaseFast
	-@cp zig-out/lib/libcrypto.so ${NAME}

include ../../Makefile.modules
