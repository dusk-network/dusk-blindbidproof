ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

CARGO = cargo

clean:
	rm -rf ./src/target
	rm ./Cargo.lock
	# rm ./go/libblindbid*

build:
	$(CARGO) build --release
	#needed?
	export CGO_LDFLAGS="-L$(pwd)/target/release" 
	export LD_LIBRARY_PATH="$(pwd)/target/release"

	cp target/release/libblindbid.pc ./go/libblindbid.pc
	# cp target/release/libblindbid.h ./go/libblindbid.h
	cp target/release/libblindbid.dylib ./go/libblindbid.dylib

cpy:

# 	go build -ldflags="-r $(ROOT_DIR)lib" -o go-rust

all: clean build
