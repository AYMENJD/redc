#ifndef REDC_H
#define REDC_H

#include <algorithm>
#include <atomic>
#include <cstring>
#include <list>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include <curl/curl.h>

#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/tuple.h>

#include "utils/readerwriterqueue.h"

#include "utils/curl_utils.h"

namespace nb = nanobind;
using namespace nb::literals;

using acq_gil = nb::gil_scoped_acquire;
using rel_gil = nb::gil_scoped_release;

using py_object = nb::object;
using py_str = nb::str;
using py_bytes = nb::bytes;
using py_tuple = nb::tuple;
using py_list = nb::list;
using py_dict = nb::dict;
using arg = nb::arg;
using string = std::string;

constexpr size_t MAX_RESPONSE_SIZE =
    16 * 1024 * 1024; // 16MB, max response size for non streamed responses

constexpr bool isNullOrEmpty(const char *str) { return !str || !*str; }

class RequestBuilder;

struct Request {
  Request() {
    headers.reserve(1024);
    response.reserve(4096);
  }

  // Delete copy, allow move
  Request(const Request &) = delete;
  Request &operator=(const Request &) = delete;
  Request(Request &&) = default;
  Request &operator=(Request &&) = default;

  ~Request() = default;

  py_object future;
  py_object loop;
  py_object stream_callback{nb::none()};
  py_object progress_callback{nb::none()};

  py_object body_stream{nb::none()};
  py_bytes raw_data;

  std::list<py_object> mime_streams;
  std::list<string> mime_data_store;

  bool has_stream_callback{false};
  bool has_progress_callback{false};

  std::vector<char> headers;
  CurlSlist request_headers;
  CurlMime curl_mime_;

  string post_data_buffer;

  std::vector<char> response;
  char errbuf[CURL_ERROR_SIZE]{0};
};

struct PendingRequest {
  CURL *easy;
  std::unique_ptr<Request> request;
};

struct Result {
  std::unique_ptr<Request> request;
  CURLcode curl_code;

  long response_code;
  char *url;
  long http_version;
  long redirect_count;

  curl_off_t dns_time;
  curl_off_t connect_time;
  curl_off_t tls_time;
  curl_off_t download_size;
  curl_off_t upload_size;
  curl_off_t elapsed;
};

class RedC {
public:
  RedC(const long &read_buffer_size, const bool &session);
  ~RedC();

  bool is_running();
  void close();

  py_list get_cookies(bool netscape);
  void clear_cookies();

  py_object request(const char *method, const char *url,
                    const py_object &params, const py_object &raw_data,
                    const py_object &data, const py_object &files,
                    const py_object &headers, const py_object &cookies,
                    const char *http_version, const long &timeout_ms,
                    const long &connect_timeout_ms, const bool &allow_redirects,
                    const char *proxy_url, const py_object &auth,
                    const bool &verify, const char *cert,
                    const py_object &stream_callback,
                    const py_object &progress_callback, const bool &verbose);

  string redc_curl_version();

private:
  int still_running_{0};
  long buffer_size_;
  bool session_enabled_;

  py_object asyncio_;
  py_object loop_;
  py_object call_soon_threadsafe_;

  CURLM *multi_handle_{nullptr};
  CURLSH *share_handle_{nullptr};

  std::thread worker_thread_;
  std::atomic<bool> running_{false};

  std::mutex share_mutex_;

  moodycamel::ReaderWriterQueue<CURL *> handle_pool_;
  moodycamel::ReaderWriterQueue<PendingRequest> queue_;

  void worker_loop();
  void CHECK_RUNNING();

  CURL *get_handle();
  void release_handle(CURL *easy);

  static size_t read_callback(char *buffer, size_t size, size_t nitems,
                              Request *clientp);
  static size_t mime_read_callback(char *buffer, size_t size, size_t nitems,
                                   void *arg);
  static size_t header_callback(char *buffer, size_t size, size_t nitems,
                                Request *clientp);
  static size_t progress_callback(Request *clientp, curl_off_t dltotal,
                                  curl_off_t dlnow, curl_off_t ultotal,
                                  curl_off_t ulnow);
  static size_t write_callback(char *data, size_t size, size_t nmemb,
                               Request *clientp);

  static void share_lock_cb(CURL *handle, curl_lock_data data,
                            curl_lock_access access, RedC *self);
  static void share_unlock_cb(CURL *handle, curl_lock_data data, RedC *self);

  py_dict parse_cookie_string(const char *cookie_line);

  friend class RequestBuilder;

  friend int redc_tp_traverse(PyObject *, visitproc, void *);
  friend int redc_tp_clear(PyObject *);
};

#endif // REDC_H
