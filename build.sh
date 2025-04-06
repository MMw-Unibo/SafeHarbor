#!/bin/bash

# CMD values:
#   - main (default): build the main program 
#   - deps: build dependencies
#   - clean: clean the build directory
#   - clean-deps: clean the dependencies directory
#   - all: build all
usage() {
    echo "Usage: $0 [main|deps|clean|clean-deps|all]"
}

help() {
    usage
    echo "Commands:"
    echo "  main: build the main program and ebpfs programs"
    echo "  only-main: build only the main program"
    echo "  ebpfs: build only ebpf programs"
    echo "  deps: build dependencies"
    echo "  clean: clean the build directory"
    echo "  clean-deps: clean the dependencies directory"
    echo "  all: build all"
}

COMMANDS="main deps clean clean-deps all ebpfs only-main"
COMMAND=all

if [ -n "$1" ]; then
    COMMAND=$1
fi

if [[ ! " $COMMANDS " =~ " $COMMAND " ]]; then
    echo "Invalid command: $COMMAND"
    help 
    exit 1
fi

# -----------------------------------------------------------------------------
# VARIABLES
# 
CC=clang
CFLAGS="-g -O2"
PROJECT_FOLDER=$(pwd)
DEPS_DIR="deps"
BUILD_DIR="build"
BUILD_DEPS_DIR="build-deps"
# libbpf variables
LIBBPF_SOURCE_DIR="$DEPS_DIR/libbpf/src"
LIBBPF_BUILD_DIR="$BUILD_DEPS_DIR/libbpf"

# -----------------------------------------------------------------------------
# FUNCTIONS
#

build_ebpfs() {
    if [ ! -d "$BUILD_DIR" ]; then
        mkdir "$BUILD_DIR"
    fi

    ARCH=$(uname -m)
    TARGET_ARCH=
    if [ "$ARCH" == "x86_64" ]; then
        TARGET_ARCH="x86"
    else
        echo "Unsupported architecture: $ARCH"
        exit 1
    fi

    ### Build eBPF program(s)
    # get all files in the eBPF folder
    EBPF_SOURCE_DIR="$PROJECT_FOLDER/ebpf"
    EBPF_OBJ_DIR="$BUILD_DIR/ebpf"
    EBPF_CONFIG_DIR="$BUILD_DIR/config"
    EBPF_INCLUDES="-I/usr/include/$ARCH-linux-gnu -I$PROJECT_FOLDER/includes -I$PROJECT_FOLDER/$LIBBPF_BUILD_DIR/include"
    EBPF_FILES=$(find ebpf -name "*.bpf.c" -exec basename {} \;)

    if [ ! -d "$EBPF_OBJ_DIR" ]; then
        mkdir "$EBPF_OBJ_DIR"
    fi

    if [ ! -d "$EBPF_CONFIG_DIR" ]; then
        mkdir "$EBPF_CONFIG_DIR"
    fi

    cd "$EBPF_OBJ_DIR" || exit
    for EBPF_FILE in $EBPF_FILES; do
        PROGRAM=$(basename $EBPF_FILE .bpf.c)
        echo "Building eBPF program: $PROGRAM"
        $CC -g -O2 -target bpf -D__TARGET_ARCH_${TARGET_ARCH} $EBPF_INCLUDES -c $EBPF_SOURCE_DIR/$PROGRAM.bpf.c -o $PROGRAM.bpf.o
        llvm-strip -g $PROGRAM.bpf.o # remove debug info, not needed for eBPF
    done
    cd "$PROJECT_FOLDER" || exit
}

build_main() {
    if [ ! -d "$BUILD_DIR" ]; then
        mkdir "$BUILD_DIR"
    fi

    ### Build main program
    INCLUDES="-I$PROJECT_FOLDER/$LIBBPF_BUILD_DIR/include -I$PROJECT_FOLDER/includes -I$PROJECT_FOLDER/deps"
    LIBS_DIR="$PROJECT_FOLDER/$LIBBPF_BUILD_DIR/lib64"
    DEFINES="-DDEBUG=1 -DTABLE_PRINTOUT=1"
    
    echo "Building main program"
    cd "$BUILD_DIR" || exit
    $CC $CFLAGS ../main.c $INCLUDES -L$LIBS_DIR -lbpf -lelf -lz $DEFINES -o main
    mv main $PROJECT_FOLDER/main
    cd "$PROJECT_FOLDER" || exit
    echo "Done"
}

clean_main() {
    echo "Cleaning main program"
    rm -rf build
    echo "Done"
}

build_deps() {
    echo "Building dependencies"
    if [ ! -d "build-deps" ]; then
        mkdir build-deps
    fi

    # build libbpf
   
    if [ ! -d "$LIBBPF_BUILD_DIR" ]; then
        mkdir -p "$LIBBPF_BUILD_DIR"
    fi 

    cd "$LIBBPF_SOURCE_DIR" || exit
    BUILD_STATIC_ONLY=y PREFIX="" OBJDIR=$PROJECT_FOLDER/$LIBBPF_BUILD_DIR/out DESTDIR=$PROJECT_FOLDER/$LIBBPF_BUILD_DIR make install 
    cd "$PROJECT_FOLDER" || exit

    echo "Done"
}

clean_deps() {
    echo "Cleaning dependencies"
    rm -rf build-deps
    echo "Done"
}

echo "Running command: $COMMAND"
case $COMMAND in
    main)
        build_ebpfs
        build_main
        ;;
    deps)
        build_deps
        ;;
    clean)
        clean_main
        ;;
    clean-deps)
        clean_deps
        ;;
    all)
        build_deps
        build_main
        ;;
    clean-all)
        clean_main
        clean_deps
        ;;
    ebpfs)
        build_ebpfs
        ;;
    only-main)
        build_main
        ;;
    *)
        echo "Invalid command: $1"
        help
        exit 1
        ;;
esac
