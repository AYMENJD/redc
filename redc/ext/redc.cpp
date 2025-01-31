#include "redc.h"
#include "utils/curl_utils.h"
#include <iostream>
#include <stdexcept>

RedC::RedC(const long &buffer) {
  {
    acq_gil gil;
    loop_ = nb::module_::import_("asyncio").attr("get_event_loop")();
  }

  static CurlGlobalInit g;

  buffer_size_ = buffer;
  multi_handle_ = curl_multi_init();

  if (!multi_handle_) {
    throw std::runtime_error("Failed to create CURL multi handle");
  }

  try {
    running_ = true;
    worker_thread_ = std::thread(&RedC::worker_loop, this);
  } catch (...) {
    curl_multi_cleanup(multi_handle_);
    throw;
  }
}

RedC::~RedC() {
  this->close();
}

bool RedC::is_running() {
  return running_;
}

void RedC::close() {
  if (running_) {
    running_ = false;
    curl_multi_wakeup(multi_handle_);

    if (worker_thread_.joinable()) {
      worker_thread_.join();
    }

    cleanup();
    curl_multi_cleanup(multi_handle_);
  }
}

py_object RedC::request(const string &method, const string &url, const char *raw_data, const py_object &data,
                        const py_object &files, const py_object &headers, const long &timeout_ms,
                        const long &connect_timeout_ms, const bool &allow_redirect, const string &proxy_url,
                        const bool &verify, const py_object &stream_callback, const bool &verbose) {
  CHECK_RUNNING();

  if (method.empty() || url.empty()) {
    throw std::invalid_argument("method or url must be non-empty");
  }

  CURL *easy = curl_easy_init();
  if (!easy) {
    throw std::runtime_error("Failed to create CURL easy handle");
  }

  try {
    curl_easy_setopt(easy, CURLOPT_BUFFERSIZE, buffer_size_);
    curl_easy_setopt(easy, CURLOPT_URL, url.c_str());
    curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, method.c_str());

    curl_easy_setopt(easy, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, timeout_ms);

    curl_easy_setopt(easy, CURLOPT_HEADERFUNCTION, &RedC::header_callback);

    if (verbose) {
      curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
    }

    if (connect_timeout_ms > 0) {
      curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, connect_timeout_ms);
    }

    if (method == "HEAD" || method == "OPTIONS") {
      curl_easy_setopt(easy, CURLOPT_NOBODY, 1L);
    } else {
      curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &RedC::write_callback);
    }

    if (allow_redirect) {
      curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);
      curl_easy_setopt(easy, CURLOPT_MAXREDIRS, 30L);
    }

    if (!proxy_url.empty()) {
      curl_easy_setopt(easy, CURLOPT_PROXY, proxy_url.c_str());
    }

    if (!verify) {
      curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0);
      curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 0);
    }

    CurlMime curl_mime_;
    if (raw_data && *raw_data) {
      curl_easy_setopt(easy, CURLOPT_POSTFIELDS, raw_data);
      curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(raw_data));
    } else if (!data.is_none() || !files.is_none()) {
      curl_mime_.mime = curl_mime_init(easy);

      if (!data.is_none()) {
        dict dict_obj;
        try {
          dict_obj = nb::cast<dict>(data);
        } catch (...) {
          throw std::runtime_error("Expected \"data\" to be a dictionary of strings");
        }

        for (auto const &it : dict_obj) {
          curl_mimepart *part = curl_mime_addpart(curl_mime_.mime);
          curl_mime_name(part, nb::str(it.first).c_str());
          curl_mime_data(part, nb::str(it.second).c_str(), CURL_ZERO_TERMINATED);
        }
      }

      if (!files.is_none()) {
        dict dict_obj;
        try {
          dict_obj = nb::cast<dict>(files);
        } catch (...) {
          throw std::runtime_error("Expected \"files\" to be a dictionary of strings");
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
        slist_headers.slist = curl_slist_append(slist_headers.slist, nb::str(it).c_str());
      }
      curl_easy_setopt(easy, CURLOPT_HTTPHEADER, slist_headers.slist);
    }

    py_object future;
    {
      acq_gil gil;
      future = loop_.attr("create_future")();
    }

    {
      std::unique_lock<std::mutex> lock(mutex_);
      auto &d = transfers_[easy];
      lock.unlock();

      d.future = future;
      d.request_headers = std::move(slist_headers);
      d.curl_mime_ = std::move(curl_mime_);

      if (!stream_callback.is_none()) {
        d.stream_callback = stream_callback;
      }

      curl_easy_setopt(easy, CURLOPT_HEADERDATA, &d);
      if (method != "HEAD" || method != "OPTIONS") {
        curl_easy_setopt(easy, CURLOPT_WRITEDATA, &d);
      }
    }

    queue_.enqueue(easy);

    curl_multi_wakeup(multi_handle_);  // thread-safe
    return future;
  } catch (...) {
    curl_easy_cleanup(easy);
    throw;
  }
}

void RedC::worker_loop() {
  while (running_) {
    if (!running_)
      break;

    CURL *e;
    if (queue_.try_dequeue(e)) {
      CURLMcode res = curl_multi_add_handle(multi_handle_, e);
      if (res != CURLM_OK) {
        std::unique_lock<std::mutex> lock(mutex_);
        auto it = transfers_.find(e);
        if (it != transfers_.end()) {
          Data data = std::move(it->second);
          transfers_.erase(it);
          lock.unlock();
          {
            acq_gil gil;
            loop_.attr("call_soon_threadsafe")(nb::cpp_function([data = std::move(data), res]() {
              data.future.attr("set_result")(nb::make_tuple(-1, NULL, NULL, (int)res, curl_multi_strerror(res)));
            }));
          }
        }
        curl_easy_cleanup(e);
      }
    } else {
      int numfds;
      curl_multi_poll(multi_handle_, nullptr, 0, 30000, &numfds);
    }

    curl_multi_perform(multi_handle_, &still_running_);

    CURLMsg *msg;
    int msgs_left;
    while ((msg = curl_multi_info_read(multi_handle_, &msgs_left))) {
      if (msg->msg == CURLMSG_DONE) {
        std::unique_lock<std::mutex> lock(mutex_);
        auto it = transfers_.find(msg->easy_handle);
        if (it != transfers_.end()) {
          Data data = std::move(it->second);
          transfers_.erase(it);
          lock.unlock();

          {
            acq_gil gil;

            CURLcode res = msg->data.result;

            /*
            * Result is allways Tuple:

            * 0: HTTP response status code.
            *    If the value is -1, it indicates a cURL error occurred
            *
            * 1: Response headers as bytes; can be null
            *
            * 2: The actual response data as bytes; can be null
            *
            * 3: cURL return code. This indicates the result code of the cURL operation.
            *    See: https://curl.se/libcurl/c/libcurl-errors.html
            *
            * 4: cURL error message string; can be null
            */
            py_object result;
            if (res == CURLE_OK) {
              short status_code = 0;
              curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE, &status_code);
              result = nb::make_tuple(status_code, py_bytes(data.headers.data(), data.headers.size()),
                                      py_bytes(data.response.data(), data.response.size()), (int)res, NULL);
            } else {
              result = nb::make_tuple(-1, NULL, NULL, (int)res, curl_easy_strerror(res));
            }

            loop_.attr("call_soon_threadsafe")(nb::cpp_function([data = std::move(data), result = std::move(result)]() {
              data.future.attr("set_result")(std::move(result));
            }));
          }

          curl_multi_remove_handle(multi_handle_, msg->easy_handle);
          curl_easy_cleanup(msg->easy_handle);
        }
      }
    }
  }
}

void RedC::cleanup() {
  std::unique_lock<std::mutex> lock(mutex_);
  acq_gil gil;
  for (auto &[easy, data] : transfers_) {
    loop_.attr("call_soon_threadsafe")(nb::cpp_function([data = std::move(data)]() { data.future.attr("cancel")(); }));
    curl_multi_remove_handle(multi_handle_, easy);
    curl_easy_cleanup(easy);
  }
  transfers_.clear();
}

void RedC::CHECK_RUNNING() {
  if (!running_) {
    throw std::runtime_error("RedC can't be used after being closed");
  }
}

size_t RedC::header_callback(char *buffer, size_t size, size_t nitems, Data *clientp) {
  size_t total_size = size * nitems;
  clientp->headers.insert(clientp->headers.end(), buffer, buffer + total_size);

  return total_size;
}

size_t RedC::write_callback(char *data, size_t size, size_t nmemb, Data *clientp) {
  size_t total_size = size * nmemb;

  if (!clientp->stream_callback.is_none()) {
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

NB_MODULE(redc_ext, m) {
  nb::class_<RedC>(m, "RedC")
      .def(nb::init<const long &>())
      .def("request", &RedC::request, arg("method"), arg("url"), arg("raw_data") = "", arg("data") = nb::none(),
           arg("files") = nb::none(), arg("headers") = nb::none(), arg("timeout_ms") = 60 * 1000,
           arg("connect_timeout_ms") = 0, arg("allow_redirect") = true, arg("proxy_url") = "", arg("verify") = true,
           arg("stream_callback") = nb::none(), arg("verbose") = false)
      .def("close", &RedC::close);
}