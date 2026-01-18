#!/usr/bin/env bash
set -euo pipefail

# deps
yum install wget gcc make perl-IPC-Cmd perl-Time-Piece -y

# libunistring
wget -O libunistring.tar.gz https://ftp.gnu.org/gnu/libunistring/libunistring-1.4.tar.gz
tar -xzvf libunistring.tar.gz
rm libunistring.tar.gz

cd libunistring-1.4
./configure
make -j
make install
cd .. && rm -rf libunistring-1.4

# libidn2
wget -O libidn2.tar.gz https://ftp.gnu.org/gnu/libidn/libidn2-2.3.8.tar.gz
tar -xzvf libidn2.tar.gz
rm libidn2.tar.gz

cd libidn2-2.3.8
./configure
make -j
make install
ldconfig
cd .. && rm -rf libidn2-2.3.8

# libpsl
wget -O libpsl.tar.gz https://github.com/rockdaboot/libpsl/releases/download/$PSL_VERSION/libpsl-$PSL_VERSION.tar.gz
tar -xzvf libpsl.tar.gz
rm libpsl.tar.gz
mv libpsl-$PSL_VERSION libpsl

cd libpsl
./configure
make -j
make install
ldconfig
cd .. && rm -rf libpsl

# c-ares from source
wget -O c-ares.tar.gz https://github.com/c-ares/c-ares/releases/download/v$CARES_VERSION/c-ares-$CARES_VERSION.tar.gz
tar -xzvf c-ares.tar.gz
rm c-ares.tar.gz
mv c-ares-$CARES_VERSION c-ares

cd c-ares
./configure
make -j
make install
ldconfig
cd .. && rm -rf c-ares

# Brotili from source
wget -O brotli.tar.gz https://github.com/google/brotli/archive/refs/tags/v$BROTLI_VERSION.tar.gz
tar -xzvf brotli.tar.gz
rm brotli.tar.gz
mv brotli-$BROTLI_VERSION brotli

cd brotli/
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j
make install
ldconfig
cd ../.. && rm -rf brotli

# zstd from source
wget -O zstd.tar.gz https://github.com/facebook/zstd/archive/refs/tags/v$ZSTD_VERSION.tar.gz
tar -xzvf zstd.tar.gz
rm zstd.tar.gz
mv zstd-$ZSTD_VERSION zstd

cd zstd/
mkdir build-cmake && cd build-cmake
cmake -S ../build/cmake -B . -DZSTD_BUILD_PROGRAMS=OFF -DZSTD_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release --target install -j
ldconfig
cd ../.. && rm -rf zstd

# zlib from source
wget -O zlib.tar.gz https://github.com/madler/zlib/archive/refs/tags/v$ZLIB_VERSION.tar.gz
tar -xzvf zlib.tar.gz
rm zlib.tar.gz
mv zlib-$ZLIB_VERSION zlib

cd zlib/
./configure
make -j
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
make -j
make install_sw
ldconfig
cd .. && rm -rf openssl

export OPENSSL_PREFIX=/usr/local
export PKG_CONFIG_PATH="$OPENSSL_PREFIX/lib64/pkgconfig:$OPENSSL_PREFIX/lib/pkgconfig"
export CPPFLAGS="-I$OPENSSL_PREFIX/include"
export LDFLAGS="-Wl,-rpath,$OPENSSL_PREFIX/lib64 -L$OPENSSL_PREFIX/lib64"

# ngtcp2 from source
wget -O ngtcp2.tar.gz https://github.com/ngtcp2/ngtcp2/releases/download/v$NGTCP2_VERSION/ngtcp2-$NGTCP2_VERSION.tar.gz
tar -xzvf ngtcp2.tar.gz
rm ngtcp2.tar.gz
mv ngtcp2-$NGTCP2_VERSION ngtcp2

cd ngtcp2
autoreconf -fi
./configure --enable-lib-only --with-openssl
make -j
make install
ldconfig
cd .. && rm -rf ngtcp2

# nghttp3 from source
wget -O nghttp3.tar.gz https://github.com/ngtcp2/nghttp3/releases/download/v$NGHTTP3_VERSION/nghttp3-$NGHTTP3_VERSION.tar.gz
tar -xzvf nghttp3.tar.gz
rm nghttp3.tar.gz
mv nghttp3-$NGHTTP3_VERSION nghttp3

cd nghttp3
autoreconf -fi
./configure --enable-lib-only
make -j
make install
ldconfig
cd .. && rm -rf nghttp3

# nghttp2 from source
wget -O nghttp2.tar.gz https://github.com/nghttp2/nghttp2/releases/download/v$NGHTTP2_VERSION/nghttp2-$NGHTTP2_VERSION.tar.gz
tar -xzvf nghttp2.tar.gz
rm nghttp2.tar.gz
mv nghttp2-$NGHTTP2_VERSION nghttp2

cd nghttp2
autoreconf -i && automake && autoconf
./configure --enable-lib-only --with-openssl
make -j
make install
ldconfig
cd .. && rm -rf nghttp2

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
  --enable-ares \
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

make -j
make install
ldconfig
curl --version
cd ..
rm -rf curl
