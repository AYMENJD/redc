#!/usr/bin/env bash

CURL_VERSION="8.14.1"

# deps
yum install wget gcc make libpsl-devel libidn-devel zlib-devel libnghttp2-devel perl-IPC-Cmd -y

# openssl from source
git clone --depth 1 https://github.com/openssl/openssl
cd openssl
./Configure
make -j100
make install
ldconfig
cd .. && rm -rf openssl

# curl from source
wget https://curl.se/download/curl-$CURL_VERSION.tar.gz
tar -xzvf curl-$CURL_VERSION.tar.gz
rm curl-$CURL_VERSION.tar.gz

cd curl-$CURL_VERSION
./configure --with-openssl --enable-cookies --with-zlib --enable-threaded-resolver --enable-ipv6 --enable-proxy --with-ca-fallback --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt
make -j100
make install
ldconfig
curl --version

cd ..
rm -rf curl-$CURL_VERSION
