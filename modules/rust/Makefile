include ../../Makefile.defs

auto_gen=
RUST_LIB_NAME=rust
NAME=${RUST_LIB_NAME}.so

$NAME:
	-@echo "Compiling $<"
	-@cargo build --release
	-@cp target/release/lib${RUST_LIB_NAME}.so ${NAME}

mod-clean:
	-@cargo clean

clean clean-modules: mod-clean

include ../../Makefile.modules
