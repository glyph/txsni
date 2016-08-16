#!/bin/bash

set -e
set -x

if [[ -v OPENSSL_VERSION ]]; then
    OPENSSL_DIR="${HOME}/ossl"

    export PATH="$HOME/$OPENSSL_DIR/bin:$PATH"
    export CFLAGS="-I$HOME/$OPENSSL_DIR/include"
    # rpath on linux will cause it to use an absolute path so we don't need to do LD_LIBRARY_PATH
    export LDFLAGS="-L$HOME/$OPENSSL_DIR/lib -Wl,-rpath=$HOME/$OPENSSL_DIR/lib"
fi

tox
