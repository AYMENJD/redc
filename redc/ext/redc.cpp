#include "redc.h"
#include "utils/curl_utils.h"
#include "utils/memoryview.h"
#include <iostream>
#include <stdexcept>

static CurlGlobalInit g;

RedC::RedC(const long &buffer) {
  {
    acq_gil gil;
    loop_ = nb::module_::import_("asyncio").attr("get_event_loop")();
    call_soon_threadsafe_ = loop_.attr("call_soon_threadsafe");
  }

  buffer_size_ = buffer;
  multi_handle_ = curl_multi_init();

  if (!multi_handle_) {
    throw std::runtime_error("Failed to create CURL multi handle");
  }

  curl_multi_setopt(multi_handle_, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  curl_multi_setopt(multi_handle_, CURLMOPT_MAX_TOTAL_CONNECTIONS, 1024L);
  curl_multi_setopt(multi_handle_, CURLMOPT_MAX_HOST_CONNECTIONS, 64L);
  curl_multi_setopt(multi_handle_, CURLMOPT_MAXCONNECTS, 2048L);
  curl_multi_setopt(multi_handle_, CURLMOPT_MAX_CONCURRENT_STREAMS, 100L);

  handle_pool_.reserve(1024);
  transfers_.reserve(1024);

  try {
    running_ = true;
    worker_thread_ = std::thread(&RedC::worker_loop, this);
  } catch (...) {
    curl_multi_cleanup(multi_handle_);
    throw;
  }
}

RedC::~RedC() { this->close(); }

bool RedC::is_running() { return running_; }

CURL *RedC::get_handle() {
  if (!handle_pool_.empty()) {
    CURL *easy = handle_pool_.back();
    handle_pool_.pop_back();
    curl_easy_reset(easy);
    return easy;
  }

  CURL *easy = curl_easy_init();
  if (!easy) {
    throw std::runtime_error("Failed to create CURL easy handle");
  }

  return easy;
}

void RedC::release_handle(CURL *easy) { handle_pool_.push_back(easy); }

void RedC::close() {
  if (running_) {
    running_ = false;

    if (worker_thread_.joinable()) {
      curl_multi_wakeup(multi_handle_);
      worker_thread_.join();
    }

    cleanup();

    curl_multi_cleanup(multi_handle_);
  }
}

py_object RedC::request(const char *method, const char *url,
                        const char *raw_data, const py_object &file_stream,
                        const long &file_size, const py_object &data,
                        const py_object &files, const py_object &headers,
                        const long &timeout_ms, const long &connect_timeout_ms,
                        const bool &allow_redirect, const char *proxy_url,
                        const bool &verify, const char *ca_cert_path,
                        const py_object &stream_callback,
                        const py_object &progress_callback,
                        const bool &verbose) {
  CHECK_RUNNING();

  if (isNullOrEmpty(method) || isNullOrEmpty(url)) {
    throw std::invalid_argument("method or url must be non-empty");
  }

  std::unique_lock<std::mutex> lock(mutex_);
  CURL *easy = get_handle();
  lock.unlock();

  bool is_nobody =
      (strcmp(method, "HEAD") == 0 || strcmp(method, "OPTIONS") == 0);

  try {
    curl_easy_setopt(easy, CURLOPT_BUFFERSIZE, buffer_size_);
    curl_easy_setopt(easy, CURLOPT_URL, url);
    curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_3);
    curl_easy_setopt(easy, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(easy, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(easy, CURLOPT_TCP_KEEPINTVL, 30L);
    curl_easy_setopt(easy, CURLOPT_PIPEWAIT, 1L);

    curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, timeout_ms);
    curl_easy_setopt(easy, CURLOPT_HEADERFUNCTION, &RedC::header_callback);

    if (verbose) {
      curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
    }

    if (connect_timeout_ms > 0) {
      curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, connect_timeout_ms);
    }

    if (is_nobody) {
      curl_easy_setopt(easy, CURLOPT_NOBODY, 1L);
    } else {
      curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &RedC::write_callback);
    }

    if (allow_redirect) {
      curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);
      curl_easy_setopt(easy, CURLOPT_MAXREDIRS, 30L);
    }

    if (!isNullOrEmpty(proxy_url)) {
      curl_easy_setopt(easy, CURLOPT_PROXY, proxy_url);
    }

    if (!verify) {
      curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0);
      curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 0);
    } else if (!isNullOrEmpty(ca_cert_path)) {
      curl_easy_setopt(easy, CURLOPT_CAINFO, ca_cert_path);
    }

    CurlMime curl_mime_;
    if (!isNullOrEmpty(raw_data)) {
      curl_easy_setopt(easy, CURLOPT_POSTFIELDS, raw_data);
      curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE_LARGE,
                       (curl_off_t)strlen(raw_data));
    } else if (!data.is_none() || !files.is_none()) {
      curl_mime_.mime = curl_mime_init(easy);

      if (!data.is_none()) {
        dict dict_obj;
        try {
          dict_obj = nb::cast<dict>(data);
        } catch (...) {
          throw std::runtime_error("Expected \"data\" to be a dictionary");
        }

        for (auto const &it : dict_obj) {
          curl_mimepart *part = curl_mime_addpart(curl_mime_.mime);
          curl_mime_data(part, nb::str(it.second).c_str(),
                         CURL_ZERO_TERMINATED);
          curl_mime_name(part, nb::str(it.first).c_str());
        }
      }

      if (!files.is_none()) {
        dict dict_obj;
        try {
          dict_obj = nb::cast<dict>(files);
        } catch (...) {
          throw std::runtime_error("Expected \"files\" to be a dictionary");
        }

        for (auto const &it : dict_obj) {
          curl_mimepart *part = curl_mime_addpart(curl_mime_.mime);
          curl_mime_name(part, nb::str(it.first).c_str());
          curl_mime_filedata(part, nb::str(it.second).c_str());
        }
      }
      curl_easy_setopt(easy, CURLOPT_MIMEPOST, curl_mime_.mime);
    }

    CurlSlist slist_headers;
    if (!headers.is_none()) {
      for (auto const &it : headers) {
        slist_headers.slist =
            curl_slist_append(slist_headers.slist, nb::str(it).c_str());
      }
      curl_easy_setopt(easy, CURLOPT_HTTPHEADER, slist_headers.slist);
    }

    py_object future{loop_.attr("create_future")()};

    {
      lock.lock();
      auto [it, inserted] = transfers_.emplace(easy, Data{});
      Data &d = it->second;

      d.future = future;
      d.loop = loop_;
      d.stream_callback = stream_callback;
      d.progress_callback = progress_callback;
      d.file_stream = file_stream;
      d.has_stream_callback = !stream_callback.is_none() && !is_nobody;
      d.has_progress_callback = !progress_callback.is_none() && !is_nobody;
      d.request_headers = std::move(slist_headers);
      d.curl_mime_ = std::move(curl_mime_);

      curl_easy_setopt(easy, CURLOPT_HEADERDATA, &d);
      if (!is_nobody) {
        curl_easy_setopt(easy, CURLOPT_WRITEDATA, &d);
        if (d.has_progress_callback) {
          curl_easy_setopt(easy, CURLOPT_XFERINFODATA, &d);
          curl_easy_setopt(easy, CURLOPT_NOPROGRESS, 0L);
          curl_easy_setopt(easy, CURLOPT_XFERINFOFUNCTION,
                           &RedC::progress_callback);
        } else {
          curl_easy_setopt(easy, CURLOPT_NOPROGRESS, 1L);
        }
        if (!file_stream.is_none()) {
          curl_easy_setopt(easy, CURLOPT_UPLOAD, 1L);
          curl_easy_setopt(easy, CURLOPT_READDATA, &d);
          curl_easy_setopt(easy, CURLOPT_READFUNCTION, &RedC::read_callback);
          curl_easy_setopt(easy, CURLOPT_INFILESIZE_LARGE,
                           (curl_off_t)file_size);
        }
      }
      lock.unlock();
    }

    queue_.enqueue(easy);
    curl_multi_wakeup(multi_handle_); // thread-safe
    return future;

  } catch (...) {
    {
      std::lock_guard<std::mutex> lk(mutex_);
      transfers_.erase(easy);
      release_handle(easy);
    }
    throw;
  }
}

void RedC::worker_loop() {
  while (running_) {
    CURL *e;
    while (queue_.try_dequeue(e)) {
      CURLMcode res = curl_multi_add_handle(multi_handle_, e);
      if (res != CURLM_OK) {
        std::unique_lock<std::mutex> lock(mutex_);
        auto node = transfers_.extract(e);
        lock.unlock();

        if (!node.empty()) {
          Data &data = node.mapped();
          acq_gil gil;

          call_soon_threadsafe_(
              nb::cpp_function([data = std::move(data), res]() {
                data.future.attr("set_result")(
                    nb::make_tuple(-1, nb::none(), nb::none(), (int)res,
                                   curl_multi_strerror(res)));
              }));
        }

        {
          std::lock_guard<std::mutex> lk(mutex_);
          release_handle(e);
        }
      }
    }

    int numfds;
    curl_multi_poll(multi_handle_, nullptr, 0, 100, &numfds);

    if (!running_)
      return;

    curl_multi_perform(multi_handle_, &still_running_);

    CURLMsg *msg;
    int msgs_left;
    while ((msg = curl_multi_info_read(multi_handle_, &msgs_left))) {
      if (msg->msg == CURLMSG_DONE) {
        CURL *easy_handle = msg->easy_handle;

        std::unique_lock<std::mutex> lock(mutex_);
        auto node = transfers_.extract(easy_handle);

        curl_multi_remove_handle(multi_handle_, easy_handle);
        release_handle(easy_handle);

        lock.unlock();

        if (!node.empty()) {
          Data &data = node.mapped();
          CURLcode res = msg->data.result;

          long response_code = 0;
          if (res == CURLE_OK) {
            curl_easy_getinfo(easy_handle, CURLINFO_RESPONSE_CODE,
                              &response_code);
          }

          /*
           * Result is allways Tuple:
           *
           * 0: HTTP response status code.
           *    If the value is -1, it indicates a cURL error occurred
           *
           * 1: Response headers as bytes; can be null
           *
           * 2: The actual response data as bytes; can be null
           *
           * 3: cURL return code. This indicates the result code of the cURL
           * operation. See: https://curl.se/libcurl/c/libcurl-errors.html
           *
           * 4: cURL error message string; can be null
           */
          acq_gil gil;
          auto callback =
              nb::cpp_function([data = std::move(data), res, response_code]() {
                py_object result;
                if (res == CURLE_OK) {
                  result = nb::make_tuple(
                      response_code,
                      py_bytes(data.headers.data(), data.headers.size()),
                      py_bytes(data.response.data(), data.response.size()),
                      (int)res, nb::none());
                } else {
                  result = nb::make_tuple(-1, nb::none(), nb::none(), (int)res,
                                          curl_easy_strerror(res));
                }
                data.future.attr("set_result")(std::move(result));
              });

          call_soon_threadsafe_(callback);
        }
      }
    }
  }
}

void RedC::cleanup() {
  std::unique_lock<std::mutex> lock(mutex_);
  acq_gil gil;

  std::vector<py_object> futures;
  futures.reserve(transfers_.size());

  for (auto &[easy, data] : transfers_) {
    futures.push_back(data.future);
    curl_multi_remove_handle(multi_handle_, easy);
    curl_easy_cleanup(easy);
  }
  transfers_.clear();

  for (CURL *easy : handle_pool_) {
    curl_easy_cleanup(easy);
  }
  handle_pool_.clear();

  lock.unlock();

  for (auto &future : futures) {
    call_soon_threadsafe_(future.attr("cancel"));
  }
}

void RedC::CHECK_RUNNING() {
  if (!running_) {
    throw std::runtime_error("RedC can't be used after being closed");
  }
}

size_t RedC::read_callback(char *buffer, size_t size, size_t nitems,
                           Data *clientp) {
  acq_gil gil;
  auto memview = nb::memoryview::from_memory(buffer, size * nitems);
  auto result = clientp->file_stream.attr("readinto")(memview);
  return nb::cast<curl_off_t>(result);
}

size_t RedC::header_callback(char *buffer, size_t size, size_t nitems,
                             Data *clientp) {
  size_t total_size = size * nitems;
  clientp->headers.insert(clientp->headers.end(), buffer, buffer + total_size);
  return total_size;
}

size_t RedC::progress_callback(Data *clientp, curl_off_t dltotal,
                               curl_off_t dlnow, curl_off_t ultotal,
                               curl_off_t ulnow) {
  if (clientp->has_progress_callback) {
    try {
      acq_gil gil;
      clientp->progress_callback(dltotal, dlnow, ultotal, ulnow);
    } catch (const std::exception &e) {
      std::cerr << "Error in progress_callback: " << e.what() << std::endl;
    }
  }
  return 0;
}

size_t RedC::write_callback(char *data, size_t size, size_t nmemb,
                            Data *clientp) {
  size_t total_size = size * nmemb;

  if (clientp->has_stream_callback) {
    try {
      acq_gil gil;
      clientp->stream_callback(py_bytes(data, total_size), total_size);
    } catch (const std::exception &e) {
      std::cerr << "Error in stream_callback: " << e.what() << std::endl;
    }
  } else {
    clientp->response.insert(clientp->response.end(), data, data + total_size);
  }

  return total_size;
}

int redc_tp_traverse(PyObject *self, visitproc visit, void *arg) {
  Py_VISIT(Py_TYPE(self));
  if (!nb::inst_ready(self))
    return 0;
  RedC *me = nb::inst_ptr<RedC>(self);
  Py_VISIT(me->loop_.ptr());
  Py_VISIT(me->call_soon_threadsafe_.ptr());
  return 0;
}

int redc_tp_clear(PyObject *self) {
  RedC *c = nb::inst_ptr<RedC>(self);
  c->loop_ = {};
  c->call_soon_threadsafe_ = {};
  return 0;
}

PyType_Slot slots[] = {{Py_tp_traverse, (void *)redc_tp_traverse},
                       {Py_tp_clear, (void *)redc_tp_clear},
                       {0, 0}};

NB_MODULE(redc_ext, m) {
  nb::class_<RedC>(m, "RedC", nb::type_slots(slots))
      .def(nb::init<const long &>())
      .def("is_running", &RedC::is_running)
      .def("request", &RedC::request, arg("method"), arg("url"),
           arg("raw_data") = "", arg("file_stream") = nb::none(),
           arg("file_size") = 0, arg("data") = nb::none(),
           arg("files") = nb::none(), arg("headers") = nb::none(),
           arg("timeout_ms") = 60 * 1000, arg("connect_timeout_ms") = 0,
           arg("allow_redirect") = true, arg("proxy_url") = "",
           arg("verify") = true, arg("ca_cert_path") = "",
           arg("stream_callback") = nb::none(),
           arg("progress_callback") = nb::none(), arg("verbose") = false)
      .def("close", &RedC::close, nb::call_guard<nb::gil_scoped_release>());
}
