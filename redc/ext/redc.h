#ifndef REDC_H
#define REDC_H

#include <atomic>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <curl/curl.h>

#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/tuple.h>

#include "utils/concurrentqueue.h"
#include "utils/curl_utils.h"

namespace nb = nanobind;
using namespace nb::literals;

using string = std::string;
using py_object = nb::object;
using acq_gil = nb::gil_scoped_acquire;
using arg = nb::arg;
using py_bytes = nb::bytes;
using dict = nb::dict;

struct Data {
  py_object future;
  py_object loop;
  py_object stream_callback = nb::none();

  std::vector<char> headers;
  CurlSlist request_headers;
  CurlMime curl_mime_;

  std::vector<char> response;
};

class RedC {
 public:
  RedC(const long &buffer = 16384);
  ~RedC();

  bool is_running();
  void close();

  py_object request(const string &method, const string &url, const char *raw_data = "",
                    const py_object &data = nb::none(), const py_object &files = nb::none(),
                    const py_object &headers = nb::none(), const long &timeout_ms = 60 * 1000,
                    const long &connect_timeout_ms = 0, const bool &allow_redirect = true, const string &proxy_url = "",
                    const bool &verify = true, const py_object &stream_callback = nb::none(),
                    const bool &verbose = false);

 private:
  int still_running_ = 0;
  long buffer_size_;
  py_object loop_;
  py_object builtins_;

  CURLM *multi_handle_;

  std::map<CURL *, Data> transfers_;
  std::mutex mutex_;
  std::thread worker_thread_;
  std::atomic<bool> running_ = false;

  moodycamel::ConcurrentQueue<CURL *> queue_;

  void worker_loop();
  void cleanup();
  void CHECK_RUNNING();

  static size_t header_callback(char *buffer, size_t size, size_t nitems, Data *clientp);
  static size_t write_callback(char *data, size_t size, size_t nmemb, Data *clientp);
};

#endif  // REDC_H