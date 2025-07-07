#ifndef REDC_H
#define REDC_H

#include <atomic>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include <curl/curl.h>

#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/tuple.h>

#include "utils/concurrentqueue.h"
#include "utils/curl_utils.h"

namespace nb = nanobind;
using namespace nb::literals;

using acq_gil = nb::gil_scoped_acquire;
using rel_gil = nb::gil_scoped_release;

using py_object = nb::object;
using py_bytes = nb::bytes;
using arg = nb::arg;
using dict = nb::dict;

bool isNullOrEmpty(const char *str) {
  return !str || !*str;
}

struct Data {
  Data() = default;

  Data(const Data &) = delete;
  Data &operator=(const Data &) = delete;

  Data(Data &&) = default;
  Data &operator=(Data &&) = default;

  py_object future;
  py_object loop;
  py_object stream_callback{nb::none()};
  py_object progress_callback{nb::none()};
  py_object file_stream{nb::none()};

  bool has_stream_callback{false};
  bool has_progress_callback{false};

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

  py_object request(const char *method, const char *url, const char *raw_data = "",
                    const py_object &file_stream = nb::none(), const long &file_size = 0,
                    const py_object &data = nb::none(), const py_object &files = nb::none(),
                    const py_object &headers = nb::none(), const long &timeout_ms = 60 * 1000,
                    const long &connect_timeout_ms = 0, const bool &allow_redirect = true, const char *proxy_url = "",
                    const bool &verify = true, const char *ca_cert_path = "",
                    const py_object &stream_callback = nb::none(), const py_object &progress_callback = nb::none(),
                    const bool &verbose = false);

 private:
  int still_running_{0};
  long buffer_size_;
  py_object loop_;
  py_object call_soon_threadsafe_;

  CURLM *multi_handle_;

  std::unordered_map<CURL *, Data> transfers_;
  std::mutex mutex_;
  std::thread worker_thread_;
  std::atomic<bool> running_{false};

  moodycamel::ConcurrentQueue<CURL *> queue_;

  void worker_loop();
  void cleanup();
  void CHECK_RUNNING();

  static size_t read_callback(char *buffer, size_t size, size_t nitems, Data *clientp);
  static size_t header_callback(char *buffer, size_t size, size_t nitems, Data *clientp);
  static size_t progress_callback(Data *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal,
                                  curl_off_t ulnow);
  static size_t write_callback(char *data, size_t size, size_t nmemb, Data *clientp);

  friend int redc_tp_traverse(PyObject *, visitproc, void *);
  friend int redc_tp_clear(PyObject *);
};

#endif  // REDC_H
