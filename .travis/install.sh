#!/bin/bash

set -e
set -x

# Upgrade packaging tools separately, so that other installations are
# performed with the upgraded tools.
pip install -U pip setuptools wheel
pip install tox codecov

if [ "${TOXENV::5}" == "pypy-" ]; then
    git clone --depth 1 https://github.com/yyuu/pyenv.git ~/.pyenv
    PYENV_ROOT="$HOME/.pyenv"
    PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init -)"
    pyenv install pypy-4.0.1
    pyenv global pypy-4.0.1
fi

if [[ -v OPENSSL_VERSION ]]; then
    OPENSSL_DIR="${HOME}/ossl"
    mkdir -p "${OPENSSL_DIR}"
    curl -O https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz
    tar zxf openssl-$OPENSSL_VERSION.tar.gz
    cd openssl-$OPENSSL_VERSION
    ./config shared no-asm no-ssl2 -fPIC --prefix="${OPENSSL_DIR}"
    # modify the shlib version to a unique one to make sure the dynamic
    # linker doesn't load the system one.
    sed -i "s/^SHLIB_MAJOR=.*/SHLIB_MAJOR=100/" Makefile
    sed -i "s/^SHLIB_MINOR=.*/SHLIB_MINOR=0.0/" Makefile
    sed -i "s/^SHLIB_VERSION_NUMBER=.*/SHLIB_VERSION_NUMBER=100.0.0/" Makefile
    make depend
    make install
fi
