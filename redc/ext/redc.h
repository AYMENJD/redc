#ifndef REDC_H
#define REDC_H

#include <algorithm>
#include <atomic>
#include <cstring>
#include <list>
#include <mutex>
#include <thread>
#include <vector>

#include <curl/curl.h>

#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/tuple.h>

#include "utils/readerwriterqueue.h"
#include "utils/unordered_dense.h"

#include "utils/curl_utils.h"

namespace nb = nanobind;
using namespace nb::literals;

using acq_gil = nb::gil_scoped_acquire;
using rel_gil = nb::gil_scoped_release;

using py_object = nb::object;
using py_bool = nb::bool_;
using py_int = nb::int_;
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
  string url;
  long http_version;
  long redirect_count;

  curl_off_t dns_time;
  curl_off_t connect_time;
  curl_off_t tls_time;
  curl_off_t download_size;
  curl_off_t download_speed;
  curl_off_t upload_size;
  curl_off_t upload_speed;
  curl_off_t elapsed;
};

struct SocketChange {
  curl_socket_t socket;
  int what;
};

class RedC {
public:
  RedC(const long &read_buffer_size, const bool &persist_cookies,
       const long &max_total_connections, const long &max_host_connections,
       const long &max_idle_connections, const long &max_concurrent_streams,
       const long &pool_min_size, const long &pool_max_size,
       const bool &threaded);
  ~RedC();

  bool is_running();
  void close();
  string redc_curl_version();

  py_list get_cookies(bool netscape);
  void clear_cookies();

  py_object request(const char *method, const char *url,
                    const py_object &params, const py_object &raw_data,
                    const py_object &data, const py_object &files,
                    const py_object &headers, const py_object &cookies,
                    const char *http_version, const long &timeout_ms,
                    const long &connect_timeout_ms,
                    const py_object &allow_redirects, const char *proxy_url,
                    const py_object &auth, const bool &verify, const char *cert,
                    const py_object &stream_callback,
                    const py_object &progress_callback, const bool &verbose);

  friend class RequestBuilder;
  friend int redc_tp_traverse(PyObject *, visitproc, void *);
  friend int redc_tp_clear(PyObject *);

private:
  static int socket_callback(CURL *e, curl_socket_t s, int what, void *userp,
                             void *socketp);
  static int timer_callback(CURLM *multi, long timeout_ms, void *userp);

  static size_t read_callback(char *buffer, size_t size, size_t nitems,
                              Request *clientp);
  static size_t mime_read_callback(char *buffer, size_t size, size_t nitems,
                                   void *arg);
  static size_t header_callback(char *buffer, size_t size, size_t nitems,
                                Request *clientp);
  static size_t write_callback(char *data, size_t size, size_t nmemb,
                               Request *clientp);
  static size_t progress_callback(Request *clientp, curl_off_t dltotal,
                                  curl_off_t dlnow, curl_off_t ultotal,
                                  curl_off_t ulnow);

  static void share_lock_cb(CURL *handle, curl_lock_data data,
                            curl_lock_access access, RedC *self);
  static void share_unlock_cb(CURL *handle, curl_lock_data data, RedC *self);

  void worker_loop();
  void CHECK_RUNNING();

  CURL *create_handle();
  CURL *get_handle();
  void release_handle(CURL *easy);

  Result create_result(CURL *easy, CURLcode result_code,
                       std::unique_ptr<Request> req);
  void complete_request_future(Result &res);
  void process_completed_transfers();

  void on_socket_event(int fd, int action);
  void on_timer_event();
  void apply_socket_changes();
  void process_all_socket_events();

  py_dict parse_cookie_string(const char *cookie_line);

  std::atomic<bool> running_{false};
  int still_running_{0};
  long buffer_size_;
  bool session_enabled_;
  long pool_max_size_;
  bool threaded_mode_;

  py_object asyncio_;
  py_object loop_;
  py_object call_soon_threadsafe_;
  py_object loop_add_reader_;
  py_object loop_remove_reader_;
  py_object loop_add_writer_;
  py_object loop_remove_writer_;
  py_object loop_call_later_;

  py_object timer_handle_{nb::none()};
  py_object socket_event_callback_;
  py_object timer_event_callback_;
  py_object process_events_callback_;

  CURLM *multi_handle_{nullptr};
  CURLSH *share_handle_{nullptr};

  std::thread worker_thread_;
  std::mutex share_mutex_;
  moodycamel::ReaderWriterQueue<CURL *> handle_pool_;
  moodycamel::ReaderWriterQueue<PendingRequest> queue_;

  bool process_scheduled_{false};
  ankerl::unordered_dense::map<curl_socket_t, int> socket_map_;
  ankerl::unordered_dense::map<CURL *, std::unique_ptr<Request>>
      active_requests_;
  std::vector<Result> completed_batch_;
  std::vector<std::pair<int, int>> pending_socket_events_;
  std::unordered_map<curl_socket_t, int> pending_socket_changes_;
};

#endif // REDC_H
