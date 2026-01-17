#!/usr/bin/env bash
set -euo pipefail

CURL_VERSION="8.18.0"
OPENSSL_VERSION="3.6.0"
BROTLI_VERSION="1.2.0"
ZSTD_VERSION="1.5.7"
ZLIB_VERSION="1.3.1"
NGHTTP2_VERSION="1.68.0"
NGHTTP3_VERSION="1.14.0"
NGTCP2_VERSION="1.19.0"

# deps
yum install wget gcc make libpsl-devel libidn2-devel zlib-devel perl-IPC-Cmd perl-Time-Piece -y

# Brotili from source
wget -O brotli.tar.gz https://github.com/google/brotli/archive/refs/tags/v$BROTLI_VERSION.tar.gz
tar -xzvf brotli.tar.gz
rm brotli.tar.gz
mv brotli-$BROTLI_VERSION brotli

cd brotli/
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j100
make install
ldconfig
cd ../.. && rm -rf brotli

# zstd from source
wget -O zstd.tar.gz https://github.com/facebook/zstd/archive/refs/tags/v$ZSTD_VERSION.tar.gz
tar -xzvf zstd.tar.gz
rm zstd.tar.gz
mv zstd-$ZSTD_VERSION zstd

cd zstd/
cmake -S build/cmake -B build-cmake
cmake --build build-cmake -j
cmake --install build-cmake
ldconfig
cd .. && rm -rf zstd

# zlib from source
wget -O zlib.tar.gz https://github.com/madler/zlib/archive/refs/tags/v$ZLIB_VERSION.tar.gz
tar -xzvf zlib.tar.gz
rm zlib.tar.gz
mv zlib-$ZLIB_VERSION zlib

cd zlib/
./configure
make -j100
make install
ldconfig
cd .. && rm -rf zlib

# openssl from source
wget -O openssl.tar.gz https://github.com/openssl/openssl/archive/refs/tags/openssl-$OPENSSL_VERSION.tar.gz
tar -xzvf openssl.tar.gz
rm openssl.tar.gz
mv openssl-openssl-$OPENSSL_VERSION openssl
cd openssl

./Configure
make -j100
make install_sw
ldconfig
cd .. && rm -rf openssl

export OPENSSL_PREFIX=/usr/local
export PKG_CONFIG_PATH="$OPENSSL_PREFIX/lib64/pkgconfig:$OPENSSL_PREFIX/lib/pkgconfig"
export CPPFLAGS="-I$OPENSSL_PREFIX/include"
export LDFLAGS="-Wl,-rpath,$OPENSSL_PREFIX/lib64 -L$OPENSSL_PREFIX/lib64"

# nghttp2 from source
wget -O nghttp2.tar.gz https://github.com/nghttp2/nghttp2/releases/download/v$NGHTTP2_VERSION/nghttp2-$NGHTTP2_VERSION.tar.gz
tar -xzvf nghttp2.tar.gz
rm nghttp2.tar.gz
mv nghttp2-$NGHTTP2_VERSION nghttp2

cd nghttp2
autoreconf -i && automake && autoconf
./configure --enable-lib-only --with-openssl
make -j100
make install
ldconfig
cd .. && rm -rf nghttp2

# nghttp3 from source
wget -O nghttp3.tar.gz https://github.com/ngtcp2/nghttp3/releases/download/v$NGHTTP3_VERSION/nghttp3-$NGHTTP3_VERSION.tar.gz
tar -xzvf nghttp3.tar.gz
rm nghttp3.tar.gz
mv nghttp3-$NGHTTP3_VERSION nghttp3

cd nghttp3
autoreconf -fi
./configure --enable-lib-only
make -j100
make install
ldconfig
cd .. && rm -rf nghttp3

# ngtcp2 from source
wget -O ngtcp2.tar.gz https://github.com/ngtcp2/ngtcp2/releases/download/v$NGTCP2_VERSION/ngtcp2-$NGTCP2_VERSION.tar.gz
tar -xzvf ngtcp2.tar.gz
rm ngtcp2.tar.gz
mv ngtcp2-$NGTCP2_VERSION ngtcp2

cd ngtcp2
autoreconf -fi
./configure --enable-lib-only --with-openssl
make -j100
make install
ldconfig
cd .. && rm -rf ngtcp2

# curl from source
wget -O curl.tar.gz https://curl.se/download/curl-$CURL_VERSION.tar.gz
tar -xzvf curl.tar.gz
rm curl.tar.gz
mv curl-$CURL_VERSION curl

cd curl
./configure \
  --enable-shared \
  --disable-static \
  --enable-optimize \
  --disable-debug \
  --disable-curldebug \
  --disable-dependency-tracking \
  --enable-silent-rules \
  --enable-symbol-hiding \
  --without-ca-bundle \
  --without-ca-path \
  --without-ca-fallback \
  --with-openssl \
  --with-ngtcp2 \
  --with-nghttp2 \
  --with-nghttp3 \
  --with-brotli \
  --with-zstd \
  --with-zlib \
  --enable-http \
  --enable-websockets \
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
rm -rf curl
