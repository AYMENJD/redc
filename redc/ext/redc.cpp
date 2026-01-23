#include "redc.h"
#include "utils/curl_utils.h"
#include "utils/memoryview.h"
#include <iostream>
#include <sstream>
#include <stdexcept>

static CurlGlobalInit g;

RedC::RedC(const long &buffer, const bool &session)
    : queue_(1024), handle_pool_(1024), session_enabled_(session) {
  {
    acq_gil gil;
    asyncio_ = nb::module_::import_("asyncio");
    loop_ = asyncio_.attr("get_event_loop")();
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

inline string get_as_string(const nb::handle &h) {
  if (nb::isinstance<py_str>(h)) {
    return nb::cast<string>(h);
  }

  if (nb::isinstance<py_bytes>(h)) {
    auto b = nb::cast<py_bytes>(h);
    return string(b.c_str(), b.size());
  }
  return nb::cast<string>(py_str(h));
}

py_object RedC::request(const char *method, const char *url,
                        const py_object &params, const py_object &raw_data,
                        const py_object &data, const py_object &files,
                        const py_object &headers, const py_object &cookies,
                        const long &timeout_ms, const long &connect_timeout_ms,
                        const bool &allow_redirect, const char *proxy_url,
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
    }

    curl_easy_setopt(easy, CURLOPT_URL, url);
    curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_3);

    curl_easy_setopt(easy, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(easy, CURLOPT_TCP_KEEPINTVL, 30L);
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(easy, CURLOPT_PIPEWAIT, 1L);
    curl_easy_setopt(easy, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(easy, CURLOPT_BUFFERSIZE, buffer_size_);

    curl_easy_setopt(easy, CURLOPT_COOKIEFILE, "");
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

    if (allow_redirect) {
      curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);
      curl_easy_setopt(easy, CURLOPT_MAXREDIRS, 30L);
    }

    if (!isNullOrEmpty(proxy_url)) {
      curl_easy_setopt(easy, CURLOPT_PROXY, proxy_url);
    }

    if (!verify) {
      curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 0L);
    } else if (!isNullOrEmpty(cert)) {
      curl_easy_setopt(easy, CURLOPT_CAINFO, cert);
    }

    if (!cookies.is_none()) {
      string cookie_buf;
      py_dict cookie_dict;

      if (nb::isinstance<py_dict>(cookies)) {
        cookie_dict = nb::borrow<py_dict>(cookies);
      } else {
        cookie_dict = nb::cast<py_dict>(cookies);
      }

      for (auto item : cookie_dict) {
        string k = get_as_string(item.first);
        string v = get_as_string(item.second);

        if (k.empty()) {
          continue;
        }
        if (!cookie_buf.empty()) {
          cookie_buf += "; ";
        }

        cookie_buf += k + "=" + v;
      }

      if (!cookie_buf.empty()) {
        curl_easy_setopt(easy, CURLOPT_COOKIE, cookie_buf.c_str());
      }
    }

    if (!auth.is_none()) {
      if (nb::isinstance<py_str>(auth)) {
        string token = nb::cast<string>(auth);
        curl_easy_setopt(easy, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
        curl_easy_setopt(easy, CURLOPT_XOAUTH2_BEARER, token.c_str());
      } else if (nb::isinstance<py_tuple>(auth)) {
        py_tuple auth_tuple = nb::cast<py_tuple>(auth);
        size_t auth_size = auth_tuple.size();

        if (auth_size < 2 || auth_size > 3) {
          throw std::invalid_argument("auth tuple must be ('user', 'pass') or "
                                      "('user', 'pass', 'type')");
        }

        string user = get_as_string(auth_tuple[0]);
        string pass = get_as_string(auth_tuple[1]);
        string userpwd = user + ":" + pass;

        curl_easy_setopt(easy, CURLOPT_USERPWD, userpwd.c_str());

        long auth_code = CURLAUTH_BASIC;

        if (auth_size == 3) {
          string type_str = get_as_string(auth_tuple[2]);
          std::transform(type_str.begin(), type_str.end(), type_str.begin(),
                         [](unsigned char c) { return std::tolower(c); });

          if (type_str == "basic") {
            auth_code = CURLAUTH_BASIC;
          } else if (type_str == "digest") {
            auth_code = CURLAUTH_DIGEST;
          } else if (type_str == "digest_ie") {
            auth_code = CURLAUTH_DIGEST_IE;
          } else if (type_str == "ntlm") {
            auth_code = CURLAUTH_NTLM;
          } else if (type_str == "any") {
            auth_code = CURLAUTH_ANY;
          } else {
            throw std::invalid_argument("Unknown auth type: " + type_str);
          }
        }

        curl_easy_setopt(easy, CURLOPT_HTTPAUTH, auth_code);

      } else {
        throw std::invalid_argument("auth must be a tuple or string");
      }
    }

    if (!params.is_none()) {
      CURLU *urlp = curl_url();
      if (!urlp) {
        throw std::runtime_error("curl_url(): failed");
      }

      curl_url_set(urlp, CURLUPART_URL, url, 0);

      auto append_pair = [&](const string &k, const string &v) {
        string pair = k + "=" + v;
        CURLUcode rc = curl_url_set(urlp, CURLUPART_QUERY, pair.c_str(),
                                    CURLU_APPENDQUERY | CURLU_URLENCODE);

        if (rc != CURLUE_OK) {
          curl_url_cleanup(urlp);
          throw std::runtime_error("curl_url(): Failed to append query param");
        }
      };

      auto handle_value = [&](const string &key, nb::handle value) {
        if (nb::isinstance<py_list>(value) || nb::isinstance<py_tuple>(value)) {
          for (auto v : value) {
            append_pair(key, get_as_string(v));
          }
        } else {
          append_pair(key, get_as_string(value));
        }
      };

      if (nb::isinstance<py_dict>(params)) {
        py_dict d = nb::borrow<py_dict>(params);
        for (auto item : d) {
          string k = get_as_string(item.first);
          handle_value(k, item.second);
        }

      } else if (nb::isinstance<py_list>(params) ||
                 nb::isinstance<py_tuple>(params)) {
        for (auto item : params) {
          py_tuple t = nb::cast<py_tuple>(item);
          if (t.size() != 2) {
            curl_url_cleanup(urlp);
            throw std::runtime_error(
                "curl_url(): params tuple must be (key, value)");
          }

          string k = get_as_string(t[0]);
          handle_value(k, t[1]);
        }

      } else if (nb::isinstance<py_bytes>(params) ||
                 nb::isinstance<py_str>(params)) {
        string raw = get_as_string(params);

        CURLUcode rc =
            curl_url_set(urlp, CURLUPART_QUERY, raw.c_str(), CURLU_APPENDQUERY);

        if (rc != CURLUE_OK) {
          curl_url_cleanup(urlp);
          throw std::runtime_error("curl_url(): Invalid raw query string");
        }

      } else {
        curl_url_cleanup(urlp);
        throw std::runtime_error(
            "curl_url(): params must be dict, list of tuples, or str/bytes");
      }

      char *final_url = nullptr;
      CURLUcode rc = curl_url_get(urlp, CURLUPART_URL, &final_url, 0);
      if (rc != CURLUE_OK) {
        curl_url_cleanup(urlp);
        throw std::runtime_error("curl_url(): Failed to build final URL");
      }

      curl_easy_setopt(easy, CURLOPT_URL, final_url);

      curl_free(final_url);
      curl_url_cleanup(urlp);
    }

    py_object future{loop_.attr("create_future")()};

    auto req = std::make_unique<Request>();
    req->future = future;
    req->loop = loop_;
    req->stream_callback = stream_callback;
    req->progress_callback = progress_callback;
    req->has_stream_callback = !stream_callback.is_none() && !is_nobody;
    req->has_progress_callback = !progress_callback.is_none() && !is_nobody;

    if (!raw_data.is_none()) {
      py_bytes raw_bytes = nb::cast<py_bytes>(raw_data);

      req->raw_data = raw_bytes;
      curl_easy_setopt(easy, CURLOPT_POSTFIELDS, raw_bytes.c_str());
      curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE_LARGE,
                       (curl_off_t)raw_bytes.size());
    } else if (!files.is_none()) {
      req->curl_mime_.mime = curl_mime_init(easy);

      if (!data.is_none()) {
        if (nb::isinstance<py_dict>(data)) {
          py_dict dict_data = nb::borrow<py_dict>(data);
          for (auto item : dict_data) {
            curl_mimepart *part = curl_mime_addpart(req->curl_mime_.mime);
            string k = get_as_string(item.first);

            string &v =
                req->mime_data_store.emplace_back(get_as_string(item.second));

            curl_mime_name(part, k.c_str());
            curl_mime_data(part, v.c_str(), CURL_ZERO_TERMINATED);
          }
        } else if (nb::isinstance<py_list>(data) ||
                   nb::isinstance<py_tuple>(data)) {
          for (auto item : data) {
            py_tuple t = nb::cast<py_tuple>(item);
            if (t.size() == 2) {
              curl_mimepart *part = curl_mime_addpart(req->curl_mime_.mime);
              string k = get_as_string(t[0]);

              string &v =
                  req->mime_data_store.emplace_back(get_as_string(t[1]));

              curl_mime_name(part, k.c_str());
              curl_mime_data(part, v.c_str(), CURL_ZERO_TERMINATED);
            }
          }
        }
      }

      auto handle_content = [&](curl_mimepart *part, nb::handle content) {
        if (nb::isinstance<py_bytes>(content)) {
          string &b_str =
              req->mime_data_store.emplace_back(get_as_string(content));
          curl_mime_data(part, b_str.c_str(), b_str.size());
        } else if (nb::isinstance<py_str>(content)) {
          string &s_str =
              req->mime_data_store.emplace_back(nb::cast<string>(content));
          curl_mime_data(part, s_str.c_str(), CURL_ZERO_TERMINATED);
        } else if (nb::hasattr(content, "readinto")) {
          req->mime_streams.push_back(nb::borrow<py_object>(content));
          py_object *stream_ptr = &req->mime_streams.back();

          curl_off_t size = -1;
          if (nb::hasattr(content, "__len__")) {
            try {
              size = nb::cast<size_t>(content.attr("__len__")());
            } catch (...) {
            }
          }
          curl_mime_data_cb(part, size, RedC::mime_read_callback, nullptr,
                            nullptr, stream_ptr);
        }
      };

      if (nb::isinstance<py_dict>(files)) {
        py_dict dict_files = nb::borrow<py_dict>(files);
        for (auto item : dict_files) {
          string field_name = get_as_string(item.first);
          nb::handle value = item.second;

          curl_mimepart *part = curl_mime_addpart(req->curl_mime_.mime);
          curl_mime_name(part, field_name.c_str());

          if (nb::isinstance<py_tuple>(value)) {
            py_tuple t = nb::cast<py_tuple>(value);
            size_t t_size = t.size();
            if (t_size >= 2) {
              string filename = get_as_string(t[0]);
              curl_mime_filename(part, filename.c_str());

              handle_content(part, t[1]);

              if (t_size >= 3) {
                string ctype = get_as_string(t[2]);
                curl_mime_type(part, ctype.c_str());
              }

              if (t_size >= 4) {
                nb::handle custom_headers = t[3];
                if (nb::isinstance<py_dict>(custom_headers)) {
                  struct curl_slist *part_headers = nullptr;
                  for (auto h_item : nb::borrow<py_dict>(custom_headers)) {
                    string h_str = get_as_string(h_item.first) + ": " +
                                   get_as_string(h_item.second);
                    part_headers =
                        curl_slist_append(part_headers, h_str.c_str());
                  }
                  curl_mime_headers(part, part_headers, 1);
                }
              }
            }
          } else if (nb::isinstance<py_str>(value)) {
            curl_mime_filedata(part, nb::cast<string>(value).c_str());
          } else if (nb::isinstance<py_bytes>(value)) {
            handle_content(part, value);
            curl_mime_filename(part, field_name.c_str());
          } else if (nb::hasattr(value, "readinto")) {
            if (nb::hasattr(value, "name")) {
              try {
                string fn = get_as_string(value.attr("name"));
                curl_mime_filename(part, fn.c_str());
              } catch (...) {
              }
            } else {
              curl_mime_filename(part, field_name.c_str());
            }
            handle_content(part, value);
          }
        }
      }
      curl_easy_setopt(easy, CURLOPT_MIMEPOST, req->curl_mime_.mime);
    } else if (!data.is_none()) {
      if (nb::hasattr(data, "readinto")) {
        req->body_stream = data;
        curl_easy_setopt(easy, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(easy, CURLOPT_READFUNCTION, &RedC::read_callback);
        curl_easy_setopt(easy, CURLOPT_READDATA, req.get());

        if (nb::hasattr(data, "__len__")) {
          size_t size = nb::cast<size_t>(data.attr("__len__")());
          curl_easy_setopt(easy, CURLOPT_INFILESIZE_LARGE, (curl_off_t)size);
        }
      } else if (nb::isinstance<py_dict>(data) ||
                 nb::isinstance<py_list>(data) ||
                 nb::isinstance<py_tuple>(data)) {
        string &buf = req->post_data_buffer;

        auto encode_append = [&](const string &k, const string &v) {
          if (!buf.empty()) {
            buf += "&";
          }
          char *ek = curl_easy_escape(easy, k.c_str(), (int)k.length());
          char *ev = curl_easy_escape(easy, v.c_str(), (int)v.length());
          if (ek) {
            buf += ek;
          }
          buf += "=";
          if (ev) {
            buf += ev;
          }
          if (ek) {
            curl_free(ek);
          }
          if (ev) {
            curl_free(ev);
          }
        };

        if (nb::isinstance<py_dict>(data)) {
          for (auto item : nb::borrow<py_dict>(data)) {
            encode_append(get_as_string(item.first),
                          get_as_string(item.second));
          }
        } else {
          for (auto item : data) {
            py_tuple t = nb::cast<py_tuple>(item);
            if (t.size() == 2) {
              encode_append(get_as_string(t[0]), get_as_string(t[1]));
            }
          }
        }

        curl_easy_setopt(easy, CURLOPT_POSTFIELDS, buf.c_str());
      } else {
        string raw = get_as_string(data);
        curl_easy_setopt(easy, CURLOPT_POSTFIELDS, raw.c_str());
      }
    }

    CurlSlist slist_headers;
    if (!headers.is_none()) {
      for (auto handle : headers) {
        string h = get_as_string(handle);
        slist_headers.slist = curl_slist_append(slist_headers.slist, h.c_str());
      }
      curl_easy_setopt(easy, CURLOPT_HTTPHEADER, slist_headers.slist);
    }

    req->request_headers = std::move(slist_headers);

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

void RedC::worker_loop() {
  std::unordered_map<CURL *, std::unique_ptr<Request>> active;

  std::vector<std::pair<CURL *, CURLcode>> done_handles;
  std::vector<Result> result_batch;

  while (running_) {
    bool added_any = false;

    PendingRequest pending;
    while (queue_.try_dequeue(pending)) {
      CURL *easy = pending.easy;

      const CURLMcode mres = curl_multi_add_handle(multi_handle_, easy);
      if (mres != CURLM_OK) {
        acq_gil gil;
        call_soon_threadsafe_(
            nb::cpp_function([request = std::move(pending.request), mres]() {
              request->future.attr("set_result")(
                  nb::make_tuple(-1, nb::none(), nb::none(), (int)mres,
                                 curl_multi_strerror(mres)));
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

    int numfds = 0;
    curl_multi_poll(multi_handle_, nullptr, 0, 100, &numfds);

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

    for (auto &[easy, res] : done_handles) {
      long response_code = 0;
      if (res == CURLE_OK) {
        curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &response_code);
      }

      curl_multi_remove_handle(multi_handle_, easy);

      auto it = active.find(easy);
      if (it != active.end()) {
        auto req = std::move(it->second);
        active.erase(it);

        result_batch.push_back(Result{std::move(req), res, response_code});
      }

      release_handle(easy);
    }

    if (!result_batch.empty()) {
      acq_gil gil;

      for (auto &req : result_batch) {
        call_soon_threadsafe_(
            nb::cpp_function([request = std::move(req.request), res = req.res,
                              response_code = req.response_code]() {
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
               * 3: cURL return code. This indicates the result code of the
               cURL
               * operation. See:
               https://curl.se/libcurl/c/libcurl-errors.html
               *
               * 4: cURL error message string; can be null
               */

              py_object result;

              if (res == CURLE_OK) {
                result = nb::make_tuple(
                    response_code,
                    py_bytes(request->headers.data(), request->headers.size()),
                    py_bytes(request->response.data(),
                             request->response.size()),
                    (int)res, nb::none());
              } else {
                result = nb::make_tuple(-1, nb::none(), nb::none(), (int)res,
                                        curl_easy_strerror(res));
              }

              request->future.attr("set_result")(std::move(result));
            }));
      }
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
      .def(nb::init<const long &, const bool &>(), arg("buffer_size"),
           arg("persist_cookies") = false)
      .def("is_running", &RedC::is_running)
      .def("request", &RedC::request, arg("method"), arg("url"),
           arg("params") = nb::none(), arg("raw_data") = nb::none(),
           arg("data") = nb::none(), arg("files") = nb::none(),
           arg("headers") = nb::none(), arg("cookies") = nb::none(),
           arg("timeout_ms") = 60 * 1000, arg("connect_timeout_ms") = 0,
           arg("allow_redirect") = true, arg("proxy_url") = "",
           arg("auth") = nb::none(), arg("verify") = true, arg("cert") = "",
           arg("stream_callback") = nb::none(),
           arg("progress_callback") = nb::none(), arg("verbose") = false)
      .def("get_cookies", &RedC::get_cookies, arg("netscape") = false)
      .def("clear_cookies", &RedC::clear_cookies)
      .def("curl_version", &RedC::redc_curl_version,
           nb::call_guard<nb::gil_scoped_release>())
      .def("close", &RedC::close, nb::call_guard<nb::gil_scoped_release>());
}
