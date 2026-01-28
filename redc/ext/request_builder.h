#ifndef REQUEST_BUILDER_H
#define REQUEST_BUILDER_H

#include "redc.h"
#include <curl/curl.h>
#include <nanobind/nanobind.h>

class RequestBuilder {
public:
  static void set_cookies(CURL *easy, const py_object &cookies);

  static void set_auth(CURL *easy, const py_object &auth);

  static void set_params(CURL *easy, const char *url, const py_object &params);

  static void set_payload(CURL *easy, Request *req, const py_object &raw_data,
                          const py_object &data, const py_object &files);

private:
  static void handle_mime_content(Request *req, curl_mimepart *part,
                                  const nanobind::handle &content);
};

#endif // REQUEST_BUILDER_H
