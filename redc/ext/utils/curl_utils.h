#ifndef CURL_UTILS_H
#define CURL_UTILS_H

#include <curl/curl.h>

struct CurlSlist {
  curl_slist *slist = nullptr;

  CurlSlist() = default;

  ~CurlSlist() {
    if (slist) {
      curl_slist_free_all(slist);
    }
  }

  CurlSlist(const CurlSlist &) = delete;
  CurlSlist &operator=(const CurlSlist &) = delete;

  CurlSlist(CurlSlist &&other) noexcept : slist(other.slist) {
    other.slist = nullptr;
  }

  CurlSlist &operator=(CurlSlist &&other) noexcept {
    if (this != &other) {
      if (slist) {
        curl_slist_free_all(slist);
      }
      slist = other.slist;
      other.slist = nullptr;
    }
    return *this;
  }
};

struct CurlMime {
  curl_mime *mime = nullptr;

  CurlMime() = default;

  ~CurlMime() {
    if (mime) {
      curl_mime_free(mime);
    }
  }

  CurlMime(const CurlMime &) = delete;
  CurlMime &operator=(const CurlMime &) = delete;

  CurlMime(CurlMime &&other) noexcept : mime(other.mime) {
    other.mime = nullptr;
  }

  CurlMime &operator=(CurlMime &&other) noexcept {
    if (this != &other) {
      if (mime) {
        curl_mime_free(mime);
      }
      mime = other.mime;
      other.mime = nullptr;
    }
    return *this;
  }
};

class CurlGlobalInit {
 public:
  CurlGlobalInit() {
#if LIBCURL_VERSION_NUM >= 0x070800
    curl_global_init(CURL_GLOBAL_DEFAULT);
#endif
  }

  ~CurlGlobalInit() {
#if LIBCURL_VERSION_NUM >= 0x070800
    curl_global_cleanup();
#endif
  }

  CurlGlobalInit(const CurlGlobalInit &) = delete;
  CurlGlobalInit &operator=(const CurlGlobalInit &) = delete;
};

#endif  // CURL_UTILS_H
