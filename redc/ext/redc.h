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

size_t MAX_RESPONSE_SIZE =
    16 * 1024 * 1024; // 16MB, max response size for non streamed responses

inline bool isNullOrEmpty(const char *str) { return !str || !*str; }

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

  void clear() {
    future = {};
    loop = {};
    stream_callback = {};
    progress_callback = {};
    body_stream = {};
    raw_data = {};

    mime_streams.clear();
    mime_data_store.clear();

    headers.clear();
    response.clear();

    request_headers = {};
    curl_mime_ = {};
    post_data_buffer.clear();
  }

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
};

struct PendingRequest {
  CURL *easy;
  std::unique_ptr<Request> request;
};

struct Result {
  std::unique_ptr<Request> request;
  CURLcode res;
  long response_code;
};

class RedC {
public:
  RedC(const long &buffer = 16384, const bool &session = false);
  ~RedC();

  bool is_running();
  void close();

  py_list get_cookies(bool netscape = false);
  void clear_cookies();

  py_object request(
      const char *method, const char *url, const py_object &params = nb::none(),
      const py_object &raw_data = nb::none(),
      const py_object &data = nb::none(), const py_object &files = nb::none(),
      const py_object &headers = nb::none(),
      const py_object &cookies = nb::none(), const long &timeout_ms = 60 * 1000,
      const long &connect_timeout_ms = 0, const bool &allow_redirect = true,
      const char *proxy_url = "", const py_object &auth = nb::none(),
      const bool &verify = true, const char *cert = "",
      const py_object &stream_callback = nb::none(),
      const py_object &progress_callback = nb::none(),
      const bool &verbose = false);

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

  friend int redc_tp_traverse(PyObject *, visitproc, void *);
  friend int redc_tp_clear(PyObject *);
};

#endif // REDC_H
