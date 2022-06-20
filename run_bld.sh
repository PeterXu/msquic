#!/bin/sh
# 1). svn checkout or git clone
# 2). if svn, then decompress "submodules/openssl/fuzz/corpora.tgz" to "submodules/openssl/fuzz/corpora"
# 3). if git, then switch and update to specific branch 
#		git checkout dev.v1.9.1
#		git submodule init
#		git submodule update

ROOT=`pwd`

path="dev19"
rm -f build
ln -s $path build

mkdir -p $path
cd $path || exit 1

cmake -DCMAKE_BUILD_TYPE=Release -DQUIC_ENABLE_LOGGING=OFF ..
make -j4

cmake -DCMAKE_BUILD_TYPE=Debug -DQUIC_ENABLE_LOGGING=OFF ..
make -j4

rm -f openssl
ln -s _deps/opensslquic-build/openssl

cd ../../
rm -f openssl_mms
ln -s $ROOT/build/_deps/opensslquic-build/openssl openssl_mms

exit 0
