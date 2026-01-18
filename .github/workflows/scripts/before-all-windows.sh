#!/usr/bin/env bash
set -euo pipefail

export PATH="C:\deps\bin:$PATH"
export CMAKE_PREFIX_PATH="C:\deps"
export CMAKE_INSTALL_PREFIX="C:\deps"

echo "Building c-ares..."
curl -L -o c-ares.tar.gz https://github.com/c-ares/c-ares/releases/download/v$CARES_VERSION/c-ares-$CARES_VERSION.tar.gz
/c/Windows/System32/tar.exe -xf c-ares.tar.gz
rm c-ares.tar.gz
mv c-ares-$CARES_VERSION c-ares

cd c-ares
mkdir build && cd build
cmake -A x64 -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release --target install -j
cd ../.. && rm -rf c-ares

echo "Building brotli..."
curl -L -o brotli.tar.gz https://github.com/google/brotli/archive/refs/tags/v$BROTLI_VERSION.tar.gz
/c/Windows/System32/tar.exe -xf brotli.tar.gz
rm brotli.tar.gz
mv brotli-$BROTLI_VERSION brotli

cd brotli/
mkdir build && cd build
cmake -A x64 -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release --target install -j
cd ../.. && rm -rf brotli

echo "Building zstd..."
curl -L -o zstd.tar.gz https://github.com/facebook/zstd/archive/refs/tags/v$ZSTD_VERSION.tar.gz
/c/Windows/System32/tar.exe -xf zstd.tar.gz
rm zstd.tar.gz
mv zstd-$ZSTD_VERSION zstd

cd zstd/
mkdir build-cmake && cd build-cmake
cmake -S ../build/cmake -B . -A x64 -DZSTD_BUILD_PROGRAMS=OFF -DZSTD_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release --target install -j
cd ../.. && rm -rf zstd

echo "Building zlib..."
curl -L -o zlib.tar.gz https://github.com/madler/zlib/archive/refs/tags/v$ZLIB_VERSION.tar.gz
/c/Windows/System32/tar.exe -xf zlib.tar.gz
rm zlib.tar.gz
mv zlib-$ZLIB_VERSION zlib

cd zlib/
mkdir build && cd build
cmake -A x64 -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release --target install -j
cd ../.. && rm -rf zlib

echo "Building ngtcp2..."
curl -L -o ngtcp2.tar.gz https://github.com/ngtcp2/ngtcp2/releases/download/v$NGTCP2_VERSION/ngtcp2-$NGTCP2_VERSION.tar.gz
/c/Windows/System32/tar.exe -xf ngtcp2.tar.gz
rm ngtcp2.tar.gz
mv ngtcp2-$NGTCP2_VERSION ngtcp2

cd ngtcp2
mkdir build && cd build
cmake -A x64 -DENABLE_LIB_ONLY=ON -DENABLE_OPENSSL=ON -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release --target install -j
cd ../.. && rm -rf ngtcp2

echo "Building nghttp3..."
curl -L -o nghttp3.tar.gz https://github.com/ngtcp2/nghttp3/releases/download/v$NGHTTP3_VERSION/nghttp3-$NGHTTP3_VERSION.tar.gz
/c/Windows/System32/tar.exe -xf nghttp3.tar.gz
rm nghttp3.tar.gz
mv nghttp3-$NGHTTP3_VERSION nghttp3

cd nghttp3
mkdir build && cd build
cmake -A x64 -DENABLE_LIB_ONLY=ON -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release --target install -j
cd ../.. && rm -rf nghttp3

echo "Building nghttp2..."
curl -L -o nghttp2.tar.gz https://github.com/nghttp2/nghttp2/releases/download/v$NGHTTP2_VERSION/nghttp2-$NGHTTP2_VERSION.tar.gz
/c/Windows/System32/tar.exe -xf nghttp2.tar.gz
rm nghttp2.tar.gz
mv nghttp2-$NGHTTP2_VERSION nghttp2

cd nghttp2
mkdir build && cd build
cmake -A x64 -DENABLE_LIB_ONLY=ON -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release --target install -j
cd ../.. && rm -rf nghttp2

echo "Building curl..."
curl -L -o curl.tar.gz https://curl.se/download/curl-$CURL_VERSION.tar.gz
/c/Windows/System32/tar.exe -xf curl.tar.gz
rm curl.tar.gz
mv curl-$CURL_VERSION curl

cd curl
mkdir build
cd build
cmake .. \
    -A x64 \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DCURL_USE_OPENSSL=ON \
    -DUSE_LIBIDN2=OFF \
    -DUSE_WIN32_IDN=ON \
    -DUSE_NGHTTP2=ON \
    -DUSE_NGHTTP3=ON \
    -DUSE_NGTCP2=ON \
    -DCURL_BROTLI=ON \
    -DCURL_ZSTD=ON \
    -DCURL_ZLIB=ON \
    -DCURL_USE_LIBPSL=OFF \
    -DENABLE_WEBSOCKETS=ON \
    -DENABLE_ARES=ON \
    -DENABLE_IPV6=ON \
    -DCURL_DISABLE_FTP=ON \
    -DCURL_DISABLE_LDAP=ON \
    -DCURL_DISABLE_RTSP=ON \
    -DCURL_DISABLE_DICT=ON \
    -DCURL_DISABLE_TELNET=ON \
    -DCURL_DISABLE_TFTP=ON \
    -DCURL_DISABLE_POP3=ON \
    -DCURL_DISABLE_IMAP=ON \
    -DCURL_DISABLE_SMTP=ON \
    -DCURL_DISABLE_GOPHER=ON \
    -DCURL_DISABLE_MQTT=ON
cmake --build . --target install --config Release -j
cd ../.. && rm -rf curl

ls /c/deps/bin/
