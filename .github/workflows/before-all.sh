#!/usr/bin/env bash

CURL_VERSION="8.18.0"

# deps
yum install wget gcc make libpsl-devel libidn2-devel zlib-devel perl-IPC-Cmd perl-Time-Piece -y

# Brotili from source
git clone --depth 1 https://github.com/google/brotli
cd brotli/
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j100
make install
ldconfig
cd ../.. && rm -rf brotli

# zstd from source
git clone --depth 1 https://github.com/facebook/zstd
cd zstd/
cmake -S . -B build-cmake
cmake --build build-cmake -j
cmake --install build-cmake
ldconfig
cd .. && rm -rf zstd

# zlib from source
git clone --depth 1 https://github.com/madler/zlib
cd zlib/
./configure
make -j100
make install
ldconfig
cd .. && rm -rf zlib

# openssl from source
git clone --depth 1 https://github.com/openssl/openssl
cd openssl
./Configure
make -j100
make install_sw
ldconfig
cd .. && rm -rf openssl

# nghttp2 from source
git clone --depth 1 https://github.com/nghttp2/nghttp2
cd nghttp2
git submodule update --init
autoreconf -i
automake
autoconf
./configure --enable-lib-only --with-openssl
make -j100
make install
ldconfig
cd .. && rm -rf nghttp2

# nghttp3 from source
git clone --depth 1 https://github.com/ngtcp2/nghttp3
cd nghttp3
git submodule update --init
autoreconf -fi
./configure --enable-lib-only --with-openssl
make -j100
make install
ldconfig
cd .. && rm -rf nghttp3

# ngtcp2 from source
git clone --depth 1 https://github.com/ngtcp2/ngtcp2
cd ngtcp2
autoreconf -fi
./configure --enable-lib-only --with-openssl
make -j100
make install
ldconfig
cd .. && rm -rf ngtcp2

# curl from source
wget https://curl.se/download/curl-$CURL_VERSION.tar.gz
tar -xzvf curl-$CURL_VERSION.tar.gz
rm curl-$CURL_VERSION.tar.gz

cd curl-$CURL_VERSION
./configure --enable-shared \
--with-openssl \
--disable-static \
--enable-optimize \
--disable-debug \
--disable-curldebug \
--disable-dependency-tracking \
--enable-silent-rules \
--enable-symbol-hiding \
--enable-http \
--enable-websockets \
--with-nghttp2 \
--with-openssl-quic \
--with-brotli \
--with-zstd \
--with-zlib \
--enable-threaded-resolver \
--enable-ipv6 \
--enable-cookies \
--enable-mime \
--enable-dateparse \
--enable-hsts \
--enable-alt-svc \
--enable-headers-api \
--enable-proxy \
--enable-file \
--disable-ftp \
--disable-ldap \
--disable-ldaps \
--disable-rtsp \
--disable-dict \
--disable-telnet \
--disable-tftp \
--disable-pop3 \
--disable-imap \
--disable-smb \
--disable-smtp \
--disable-gopher \
--disable-mqtt \
--disable-manual \
--disable-docs
make -j100
make install
ldconfig
curl --version
cd ..
rm -rf curl-$CURL_VERSION
