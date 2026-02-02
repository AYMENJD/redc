#include "redc.h"
#include "request_builder.h"
#include "utils/curl_utils.h"
#include "utils/memoryview.h"
#include "utils/py_utils.h"
#include <iostream>
#include <sstream>
#include <stdexcept>

static CurlGlobalInit g;

static long get_http_version_bit(const char *version) {
  if (version == nullptr || version[0] == '\0') {
    return CURL_HTTP_VERSION_NONE;
  }

  switch (version[0]) {
  case '3':
    return CURL_HTTP_VERSION_3;
  case '2':
    return CURL_HTTP_VERSION_2_0;
  case '1':
    if (version[1] == '.' && version[2] == '1') {
      return CURL_HTTP_VERSION_1_1;
    }

    return CURL_HTTP_VERSION_1_0;
  default:
    return CURL_HTTP_VERSION_NONE;
  }
}

static const char *get_http_version_from_bit(long version) {
  switch (version) {
  case CURL_HTTP_VERSION_1_0:
    return "1";
  case CURL_HTTP_VERSION_1_1:
    return "1.1";
  case CURL_HTTP_VERSION_2_0:
    return "2";
  case CURL_HTTP_VERSION_3:
    return "3";
  default:
    return nullptr;
  }
}

RedC::RedC(const long &read_buffer_size, const bool &session)
    : session_enabled_(session), handle_pool_(1024), queue_(1024) {
  {
    acq_gil gil;
    asyncio_ = nb::module_::import_("asyncio");
    loop_ = asyncio_.attr("get_event_loop")();
    call_soon_threadsafe_ = loop_.attr("call_soon_threadsafe");
  }

  buffer_size_ = read_buffer_size;
  multi_handle_ = curl_multi_init();

  if (!multi_handle_) {
    throw std::runtime_error("Failed to create CURL multi handle");
  }

  curl_multi_setopt(multi_handle_, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  curl_multi_setopt(multi_handle_, CURLMOPT_MAX_TOTAL_CONNECTIONS, 1024L);
  curl_multi_setopt(multi_handle_, CURLMOPT_MAX_HOST_CONNECTIONS, 64L);
  curl_multi_setopt(multi_handle_, CURLMOPT_MAXCONNECTS, 2048L);
  curl_multi_setopt(multi_handle_, CURLMOPT_MAX_CONCURRENT_STREAMS, 100L);

  if (session_enabled_) {
    share_handle_ = curl_share_init();
    if (share_handle_) {
      curl_share_setopt(share_handle_, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
      curl_share_setopt(share_handle_, CURLSHOPT_LOCKFUNC, RedC::share_lock_cb);
      curl_share_setopt(share_handle_, CURLSHOPT_UNLOCKFUNC,
                        RedC::share_unlock_cb);
      curl_share_setopt(share_handle_, CURLSHOPT_USERDATA, this);
    } else {
      curl_multi_cleanup(multi_handle_);
      throw std::runtime_error("Failed to create CURL share handle");
    }
  }

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
  CURL *easy = nullptr;
  if (handle_pool_.try_dequeue(easy)) {
    curl_easy_reset(easy);
    return easy;
  }

  easy = curl_easy_init();
  if (!easy) {
    throw std::runtime_error("Failed to create CURL easy handle");
  }

  return easy;
}

void RedC::release_handle(CURL *easy) { handle_pool_.enqueue(easy); }

void RedC::close() {
  if (running_) {
    running_ = false;

    if (worker_thread_.joinable()) {
      curl_multi_wakeup(multi_handle_);
      worker_thread_.join();
    }
    curl_multi_cleanup(multi_handle_);
  }
}

void RedC::share_lock_cb(CURL *handle, curl_lock_data data,
                         curl_lock_access access, RedC *self) {
  if (data == CURL_LOCK_DATA_COOKIE) {
    self->share_mutex_.lock();
  }
}

void RedC::share_unlock_cb(CURL *handle, curl_lock_data data, RedC *self) {
  if (data == CURL_LOCK_DATA_COOKIE) {
    self->share_mutex_.unlock();
  }
}

py_dict RedC::parse_cookie_string(const char *cookie_line) {
  // 0: Domain (string)
  // 1: Include subdomains (boolean: TRUE/FALSE)
  // 2: Path (string)
  // 3: Secure (boolean: TRUE/FALSE)
  // 4: Expires (number: seconds since epoch)
  // 5: Name (string)
  // 6: Value (string)

  std::vector<string> parts;
  std::stringstream ss(cookie_line);
  string item;

  while (std::getline(ss, item, '\t')) {
    parts.push_back(item);
  }

  py_dict cookie;
  if (parts.size() >= 6) {
    cookie["domain"] = parts[0];
    cookie["include_subdomains"] = (parts[1] == "TRUE");
    cookie["path"] = parts[2];
    cookie["secure"] = (parts[3] == "TRUE");

    try {
      cookie["expires"] = std::stoll(parts[4]);
    } catch (...) {
      cookie["expires"] = 0;
    }

    cookie["name"] = parts[5];

    if (parts.size() > 6) {
      cookie["value"] = parts[6];
    } else {
      cookie["value"] = "";
    }
  }

  return cookie;
}

py_list RedC::get_cookies(bool netscape) {
  if (!session_enabled_ || !share_handle_) {
    return nb::list();
  }

  CURL *easy = get_handle();
  struct curl_slist *cookies = nullptr;
  py_list result;

  try {
    curl_easy_setopt(easy, CURLOPT_SHARE, share_handle_);

    CURLcode res = curl_easy_getinfo(easy, CURLINFO_COOKIELIST, &cookies);
    if (res == CURLE_OK && cookies) {
      struct curl_slist *nc = cookies;
      while (nc) {
        if (netscape) {
          result.append(nc->data);
        } else {
          result.append(parse_cookie_string(nc->data));
        }
        nc = nc->next;
      }
    }

    if (cookies) {
      curl_slist_free_all(cookies);
    }
  } catch (...) {
    release_handle(easy);
    throw;
  }

  release_handle(easy);
  return result;
}

void RedC::clear_cookies() {
  if (!session_enabled_ || !share_handle_) {
    return;
  }

  CURL *easy = get_handle();

  try {
    curl_easy_setopt(easy, CURLOPT_SHARE, share_handle_);
    curl_easy_setopt(easy, CURLOPT_COOKIELIST, "ALL");
  } catch (...) {
    release_handle(easy);
    throw;
  }

  release_handle(easy);
}

py_object RedC::request(const char *method, const char *url,
                        const py_object &params, const py_object &raw_data,
                        const py_object &data, const py_object &files,
                        const py_object &headers, const py_object &cookies,
                        const char *http_version, const long &timeout_ms,
                        const long &connect_timeout_ms,
                        const py_object &allow_redirects, const char *proxy_url,
                        const py_object &auth, const bool &verify,
                        const char *cert, const py_object &stream_callback,
                        const py_object &progress_callback,
                        const bool &verbose) {
  CHECK_RUNNING();

  if (isNullOrEmpty(method) || isNullOrEmpty(url)) {
    throw std::invalid_argument("method or url must be non-empty");
  }

  CURL *easy = get_handle();

  const bool is_head = (strcmp(method, "HEAD") == 0);
  const bool is_nobody = is_head || (strcmp(method, "OPTIONS") == 0);

  try {
    if (session_enabled_ && share_handle_) {
      curl_easy_setopt(easy, CURLOPT_SHARE, share_handle_);
      curl_easy_setopt(easy, CURLOPT_COOKIEFILE, "");
    }

    curl_easy_setopt(easy, CURLOPT_URL, url);
    curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(easy, CURLOPT_HTTP_VERSION,
                     get_http_version_bit(http_version));

    curl_easy_setopt(easy, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(easy, CURLOPT_TCP_KEEPINTVL, 30L);
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(easy, CURLOPT_PIPEWAIT, 1L);
    curl_easy_setopt(easy, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(easy, CURLOPT_BUFFERSIZE, buffer_size_);

    curl_easy_setopt(easy, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);

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

    if (!allow_redirects.is_none()) {
      bool follow;
      long max_redirs;

      if (nb::try_cast(allow_redirects, follow)) {
        curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, follow ? 1L : 0L);
        curl_easy_setopt(easy, CURLOPT_MAXREDIRS, follow ? 30L : 0L);
      } else if (nb::try_cast(allow_redirects, max_redirs)) {
        if (max_redirs > 0) {
          curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);
          curl_easy_setopt(easy, CURLOPT_MAXREDIRS, max_redirs);
        } else {
          curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 0L);
        }
      } else {
        throw std::invalid_argument("allow_redirects must be bool or int");
      }
    }

    if (!isNullOrEmpty(proxy_url)) {
      curl_easy_setopt(easy, CURLOPT_PROXY, proxy_url);
    }

    if (!isNullOrEmpty(cert)) {
      curl_easy_setopt(easy, CURLOPT_CAINFO, cert);
    }

    if (!verify) {
      curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    RequestBuilder::set_cookies(easy, cookies);
    RequestBuilder::set_auth(easy, auth);
    RequestBuilder::set_params(easy, url, params);

    py_object future{loop_.attr("create_future")()};

    auto req = std::make_unique<Request>();
    req->future = future;
    req->loop = loop_;
    req->stream_callback = stream_callback;
    req->progress_callback = progress_callback;
    req->has_stream_callback = !stream_callback.is_none() && !is_nobody;
    req->has_progress_callback = !progress_callback.is_none() && !is_nobody;

    curl_easy_setopt(easy, CURLOPT_ERRORBUFFER, req->errbuf);

    RequestBuilder::set_headers(easy, headers, req->request_headers);
    RequestBuilder::set_payload(easy, req.get(), raw_data, data, files);

    curl_easy_setopt(easy, CURLOPT_HEADERDATA, req.get());

    if (!is_nobody) {
      curl_easy_setopt(easy, CURLOPT_WRITEDATA, req.get());

      if (req->has_progress_callback) {
        curl_easy_setopt(easy, CURLOPT_XFERINFODATA, req.get());
        curl_easy_setopt(easy, CURLOPT_NOPROGRESS, 0L);
        curl_easy_setopt(easy, CURLOPT_XFERINFOFUNCTION,
                         &RedC::progress_callback);
      } else {
        curl_easy_setopt(easy, CURLOPT_NOPROGRESS, 1L);
      }
    }

    queue_.enqueue(PendingRequest{easy, std::move(req)});

    curl_multi_wakeup(multi_handle_);

    return future;
  } catch (...) {
    release_handle(easy);
    throw;
  }
}

static py_tuple make_result_tuple(const Result &r) {
  const bool success = (r.curl_code == CURLE_OK);

  const int status_code = success ? r.response_code : -1;

  const auto headers =
      py_bytes(r.request->headers.data(), r.request->headers.size());

  const auto body =
      py_bytes(r.request->response.data(), r.request->response.size());

  const py_object curl_error =
      success ? nb::str("")
              : nb::str(r.request->errbuf[0] ? r.request->errbuf
                                             : curl_easy_strerror(r.curl_code));

  return nb::make_tuple(status_code, headers, body, r.url,
                        get_http_version_from_bit(r.http_version),
                        r.redirect_count, r.dns_time, r.connect_time,
                        r.tls_time, r.download_size, r.download_speed,
                        r.upload_size, r.upload_speed, r.elapsed,
                        static_cast<int>(r.curl_code), curl_error);
}

void RedC::worker_loop() {
  std::unordered_map<CURL *, std::unique_ptr<Request>> active;

  std::vector<std::pair<CURL *, CURLcode>> done_handles;
  std::vector<Result> result_batch;

  while (running_) {
    bool added_any = false;

    PendingRequest pending;
    while (queue_.try_dequeue(pending)) {
      CURL *easy = pending.easy;

      const CURLMcode mcurl_code = curl_multi_add_handle(multi_handle_, easy);
      if (mcurl_code != CURLM_OK) {
        acq_gil gil;
        call_soon_threadsafe_(nb::cpp_function(
            [request = std::move(pending.request), mcurl_code]() {
              const char *err = curl_multi_strerror(mcurl_code);

              request->future.attr("set_exception")(std::runtime_error(
                  "CURLM " + std::to_string((int)mcurl_code) + ": " +
                  (err ? err : "unknown error")));
            }));

        release_handle(easy);
        continue;
      }

      active.emplace(easy, std::move(pending.request));
      added_any = true;
    }

    if (added_any) {
      curl_multi_perform(multi_handle_, &still_running_);
    }

    long timeout_ms = -1;
    curl_multi_timeout(multi_handle_, &timeout_ms);

    if (timeout_ms < 0 || (active.empty() && !added_any)) {
      timeout_ms = 100;
    }

    int numfds = 0;
    curl_multi_poll(multi_handle_, nullptr, 0, (int)timeout_ms, &numfds);

    if (!running_) {
      break;
    }

    curl_multi_perform(multi_handle_, &still_running_);

    done_handles.clear();

    CURLMsg *msg;
    int msgs_left;
    while ((msg = curl_multi_info_read(multi_handle_, &msgs_left))) {
      if (msg->msg == CURLMSG_DONE) {
        done_handles.emplace_back(msg->easy_handle, msg->data.result);
      }
    }

    if (done_handles.empty()) {
      continue;
    }

    result_batch.clear();
    result_batch.reserve(done_handles.size());

    for (auto &[easy, curl_code] : done_handles) {
      long response_code = -1, http_version = 0, redirect_count = 0;
      char *url = nullptr;

      curl_off_t dns_time = 0, connect_time = 0, tls_time = 0,
                 download_size = 0, download_speed = 0, upload_size = 0,
                 upload_speed = 0, elapsed = 0;

      if (curl_code == CURLE_OK) {
        curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &response_code);
        curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &url);
        curl_easy_getinfo(easy, CURLINFO_HTTP_VERSION, &http_version);
        curl_easy_getinfo(easy, CURLINFO_REDIRECT_COUNT, &redirect_count);

        curl_easy_getinfo(easy, CURLINFO_NAMELOOKUP_TIME_T, &dns_time);
        curl_easy_getinfo(easy, CURLINFO_CONNECT_TIME_T, &connect_time);
        curl_easy_getinfo(easy, CURLINFO_APPCONNECT_TIME_T, &tls_time);
        curl_easy_getinfo(easy, CURLINFO_SIZE_DOWNLOAD_T, &download_size);
        curl_easy_getinfo(easy, CURLINFO_SPEED_DOWNLOAD_T, &download_speed);
        curl_easy_getinfo(easy, CURLINFO_SIZE_UPLOAD_T, &upload_size);
        curl_easy_getinfo(easy, CURLINFO_SPEED_UPLOAD_T, &upload_speed);
        curl_easy_getinfo(easy, CURLINFO_TOTAL_TIME_T, &elapsed);
      }

      curl_multi_remove_handle(multi_handle_, easy);

      auto it = active.find(easy);
      if (it != active.end()) {
        auto req = std::move(it->second);
        active.erase(it);

        result_batch.push_back(Result{
            std::move(req),
            curl_code,
            response_code,
            url,
            http_version,
            redirect_count,
            dns_time,
            connect_time,
            tls_time,
            download_size,
            download_speed,
            upload_size,
            upload_speed,
            elapsed,
        });
      }

      release_handle(easy);
    }

    if (!result_batch.empty()) {
      acq_gil gil;

      call_soon_threadsafe_(
          nb::cpp_function([batch = std::make_unique<std::vector<Result>>(
                                std::move(result_batch))]() {
            for (auto &req : *batch) {
              auto result = make_result_tuple(req);
              req.request->future.attr("set_result")(std::move(result));
            }
          }));
    }
  }

  // clean up
  acq_gil gil;

  for (auto &[easy, request] : active) {
    curl_multi_remove_handle(multi_handle_, easy);
    curl_easy_cleanup(easy);

    call_soon_threadsafe_(request->future.attr("cancel"));
  }
  active.clear();

  CURL *easy;
  while (handle_pool_.try_dequeue(easy)) {
    curl_easy_cleanup(easy);
  }
}

void RedC::CHECK_RUNNING() {
  if (!running_) {
    throw std::runtime_error("RedC can't be used after being closed");
  }
}

size_t RedC::read_callback(char *buffer, size_t size, size_t nitems,
                           Request *clientp) {
  acq_gil gil;
  if (clientp->body_stream.is_none()) {
    return 0;
  }

  auto memview = nb::memoryview::from_memory(buffer, size * nitems);
  auto result = clientp->body_stream.attr("readinto")(memview);
  return nb::cast<curl_off_t>(result);
}

size_t RedC::mime_read_callback(char *buffer, size_t size, size_t nitems,
                                void *arg) {
  py_object *stream = static_cast<py_object *>(arg);
  acq_gil gil;
  try {
    auto memview = nb::memoryview::from_memory(buffer, size * nitems);
    auto result = stream->attr("readinto")(memview);
    return nb::cast<size_t>(result);
  } catch (...) {
    return CURL_READFUNC_ABORT;
  }
}

size_t RedC::header_callback(char *buffer, size_t size, size_t nitems,
                             Request *clientp) {
  size_t total_size = size * nitems;
  clientp->headers.insert(clientp->headers.end(), buffer, buffer + total_size);
  return total_size;
}

size_t RedC::progress_callback(Request *clientp, curl_off_t dltotal,
                               curl_off_t dlnow, curl_off_t ultotal,
                               curl_off_t ulnow) {
  if (clientp->has_progress_callback) {
    try {
      acq_gil gil;
      clientp->progress_callback(dltotal, dlnow, ultotal, ulnow);
    } catch (const std::exception &e) {
      std::cerr << "Error in progress_callback: " << e.what() << std::endl;
      return 1; // abort transfer
    }
  }
  return 0;
}

size_t RedC::write_callback(char *data, size_t size, size_t nmemb,
                            Request *clientp) {
  size_t total_size = size * nmemb;

  if (clientp->has_stream_callback) {
    try {
      acq_gil gil;
      clientp->stream_callback(py_bytes(data, total_size), total_size);
    } catch (const std::exception &e) {
      std::cerr << "Error in stream_callback: " << e.what() << std::endl;
      return 0; // abort transfer
    }
  } else {
    if (clientp->response.size() + total_size > MAX_RESPONSE_SIZE) {
      std::cerr << "Response exceeded maximum allowed size of "
                << MAX_RESPONSE_SIZE << " bytes. "
                << "Use a stream callback instead" << std::endl;
      return 0; // abort transfer
    }

    clientp->response.insert(clientp->response.end(), data, data + total_size);
  }

  return total_size;
}

string RedC::redc_curl_version() {
  std::ostringstream version_str;

  version_str << curl_version() << "\n";

  curl_version_info_data *info = curl_version_info(CURLVERSION_NOW);

#ifdef LIBCURL_TIMESTAMP
  version_str << "Release-Date: " << LIBCURL_TIMESTAMP << "\n";
#endif

  if (info->protocols && info->protocols[0]) {
    version_str << "Protocols:";
    for (const char *const *p = info->protocols; *p; ++p)
      version_str << " " << *p;
    version_str << "\n";
  }

  if (info->feature_names && info->feature_names[0]) {
    std::vector<std::string> feats;
    for (const char *const *f = info->feature_names; *f; ++f)
      feats.emplace_back(*f);

    std::sort(feats.begin(), feats.end(),
              [](const std::string &a, const std::string &b) { return a < b; });

    version_str << "Features:";
    for (auto &f : feats)
      version_str << " " << f;
    version_str << "\n";
  }

  return version_str.str();
}

int redc_tp_traverse(PyObject *self, visitproc visit, void *arg) {
  Py_VISIT(Py_TYPE(self));
  if (!nb::inst_ready(self))
    return 0;
  RedC *me = nb::inst_ptr<RedC>(self);
  Py_VISIT(me->asyncio_.ptr());
  Py_VISIT(me->loop_.ptr());
  Py_VISIT(me->call_soon_threadsafe_.ptr());
  return 0;
}

int redc_tp_clear(PyObject *self) {
  RedC *c = nb::inst_ptr<RedC>(self);
  c->asyncio_ = {};
  c->loop_ = {};
  c->call_soon_threadsafe_ = {};
  return 0;
}

PyType_Slot slots[] = {{Py_tp_traverse, (void *)redc_tp_traverse},
                       {Py_tp_clear, (void *)redc_tp_clear},
                       {0, 0}};

NB_MODULE(redc_ext, m) {
  nb::class_<RedC>(m, "RedC", nb::type_slots(slots))
      .def(nb::init<const long &, const bool &>(), arg("buffer_size") = 16384,
           arg("persist_cookies") = false)
      .def("is_running", &RedC::is_running)
      .def("request", &RedC::request, arg("method"), arg("url"),
           arg("params") = nb::none(), arg("raw_data") = nb::none(),
           arg("data") = nb::none(), arg("files") = nb::none(),
           arg("headers") = nb::none(), arg("cookies") = nb::none(),
           arg("http_version") = "3", arg("timeout_ms") = 60 * 1000,
           arg("connect_timeout_ms") = 0, arg("allow_redirects") = true,
           arg("proxy_url") = "", arg("auth") = nb::none(),
           arg("verify") = true, arg("cert") = "",
           arg("stream_callback") = nb::none(),
           arg("progress_callback") = nb::none(), arg("verbose") = false)
      .def("get_cookies", &RedC::get_cookies, arg("netscape") = false)
      .def("clear_cookies", &RedC::clear_cookies)
      .def("curl_version", &RedC::redc_curl_version,
           nb::call_guard<nb::gil_scoped_release>())
      .def("close", &RedC::close, nb::call_guard<nb::gil_scoped_release>());
}
