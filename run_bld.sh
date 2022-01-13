#!/bin/sh

git checkout dev.v1.9.1
git submodule init
git submodule update

path="dev19"
rm -f build
ln -s $path build

mkdir -p $path
cd $path || exit 1

cmake -DCMAKE_BUILD_TYPE=Release ..
make -j4

cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j4

rm -f openssl
ln -s _deps/opensslquic-build/openssl

exit 0
