#include "request_builder.h"
#include "utils/py_utils.h"
#include <algorithm>
#include <stdexcept>

namespace nb = nanobind;

void RequestBuilder::set_cookies(CURL *easy, const py_object &cookies) {
  if (cookies.is_none()) {
    return;
  }

  py_dict cookie_dict;
  if (!nb::try_cast(cookies, cookie_dict)) {
    throw std::invalid_argument("cookies must be a dict");
  }

  string cookie_buf;

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
    curl_easy_setopt(easy, CURLOPT_COOKIE,
                     cookie_buf.c_str()); // curl does copy the cookie_buf
  }
}

void RequestBuilder::set_auth(CURL *easy, const py_object &auth) {
  if (auth.is_none()) {
    return;
  }

  string token;
  py_tuple auth_tuple;

  if (nb::try_cast(auth, token)) {
    curl_easy_setopt(easy, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
    curl_easy_setopt(easy, CURLOPT_XOAUTH2_BEARER, token.c_str());

  } else if (nb::try_cast(auth, auth_tuple)) {
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

void RequestBuilder::set_params(CURL *easy, const char *url,
                                const py_object &params) {
  if (params.is_none()) {
    return;
  }

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
    py_list val_list;
    py_tuple val_tuple;

    if (nb::try_cast(value, val_list)) {
      for (auto v : val_list)
        append_pair(key, get_as_string(v));
    } else if (nb::try_cast(value, val_tuple)) {
      for (auto v : val_tuple)
        append_pair(key, get_as_string(v));
    } else {
      append_pair(key, get_as_string(value));
    }
  };

  py_dict d;
  py_list l;
  py_tuple t;
  string s_raw;
  py_bytes b_raw;

  if (nb::try_cast(params, d)) {
    for (auto item : d) {
      string k = get_as_string(item.first);
      handle_value(k, item.second);
    }

  } else if (nb::try_cast(params, l) || nb::try_cast(params, t)) {

    for (auto item : params) {
      py_tuple entry;
      if (!nb::try_cast(item, entry) || entry.size() != 2) {
        curl_url_cleanup(urlp);
        throw std::runtime_error(
            "curl_url(): params tuple must be (key, value)");
      }

      string k = get_as_string(entry[0]);
      handle_value(k, entry[1]);
    }

  } else if (nb::try_cast(params, s_raw)) {
    if (curl_url_set(urlp, CURLUPART_QUERY, s_raw.c_str(), CURLU_APPENDQUERY) !=
        CURLUE_OK) {
      curl_url_cleanup(urlp);
      throw std::runtime_error("curl_url(): Invalid raw query string");
    }

  } else if (nb::try_cast(params, b_raw)) {
    string b_str = get_as_string(params);
    if (curl_url_set(urlp, CURLUPART_QUERY, b_str.c_str(), CURLU_APPENDQUERY) !=
        CURLUE_OK) {
      curl_url_cleanup(urlp);
      throw std::runtime_error("curl_url(): Invalid raw query string");
    }

  } else {
    curl_url_cleanup(urlp);
    throw std::runtime_error(
        "curl_url(): params must be dict, list of tuples, or str/bytes");
  }

  char *final_url = nullptr;
  if (curl_url_get(urlp, CURLUPART_URL, &final_url, 0) != CURLUE_OK) {
    curl_url_cleanup(urlp);
    throw std::runtime_error("curl_url(): Failed to build final URL");
  }

  curl_easy_setopt(easy, CURLOPT_URL, final_url);

  curl_free(final_url);
  curl_url_cleanup(urlp);
}

void RequestBuilder::set_payload(CURL *easy, Request *req,
                                 const py_object &raw_data,
                                 const py_object &data,
                                 const py_object &files) {

  py_bytes raw_bytes;
  if (!raw_data.is_none() && nb::try_cast(raw_data, raw_bytes)) {
    req->raw_data = raw_bytes;

    curl_easy_setopt(easy, CURLOPT_POSTFIELDS, raw_bytes.c_str());
    curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE_LARGE,
                     (curl_off_t)raw_bytes.size());
    return;
  }

  if (!files.is_none()) {
    req->curl_mime_.mime = curl_mime_init(easy);

    py_dict data_dict;
    py_list data_list;
    py_tuple data_tuple;

    if (!data.is_none()) {
      if (nb::try_cast(data, data_dict)) {
        for (auto item : data_dict) {
          curl_mimepart *part = curl_mime_addpart(req->curl_mime_.mime);
          string k = get_as_string(item.first);
          string &v =
              req->mime_data_store.emplace_back(get_as_string(item.second));

          curl_mime_name(part, k.c_str());
          curl_mime_data(part, v.c_str(), CURL_ZERO_TERMINATED);
        }
      } else if (nb::try_cast(data, data_list) ||
                 nb::try_cast(data, data_tuple)) {
        for (auto item : data) {
          py_tuple t;
          if (nb::try_cast(item, t) && t.size() == 2) {
            curl_mimepart *part = curl_mime_addpart(req->curl_mime_.mime);
            string k = get_as_string(t[0]);
            string &v = req->mime_data_store.emplace_back(get_as_string(t[1]));

            curl_mime_name(part, k.c_str());
            curl_mime_data(part, v.c_str(), CURL_ZERO_TERMINATED);
          }
        }
      }
    }

    py_dict dict_files;
    if (nb::try_cast(files, dict_files)) {
      for (auto item : dict_files) {
        string field_name = get_as_string(item.first);
        nb::handle value = item.second;

        curl_mimepart *part = curl_mime_addpart(req->curl_mime_.mime);
        curl_mime_name(part, field_name.c_str());

        py_tuple t_file;
        string s_file;

        if (nb::try_cast(value, t_file)) {
          if (t_file.size() >= 2) {
            curl_mime_filename(part, get_as_string(t_file[0]).c_str());
            handle_mime_content(req, part, t_file[1]);

            if (t_file.size() >= 3) {
              curl_mime_type(part, get_as_string(t_file[2]).c_str());
            }

            py_dict t_headers;
            if (t_file.size() >= 4 && nb::try_cast(t_file[3], t_headers)) {
              struct curl_slist *part_headers = nullptr;
              for (auto h : t_headers) {
                string hs =
                    get_as_string(h.first) + ": " + get_as_string(h.second);
                part_headers = curl_slist_append(part_headers, hs.c_str());
              }
              curl_mime_headers(part, part_headers, 1);
            }
          }
        } else if (nb::try_cast(value, s_file)) {
          curl_mime_filedata(part, s_file.c_str());
        } else {
          handle_mime_content(req, part, value);
          curl_mime_filename(part, field_name.c_str());
        }
      }
    }
    curl_easy_setopt(easy, CURLOPT_MIMEPOST, req->curl_mime_.mime);
    return;
  }

  if (!data.is_none() && nb::hasattr(data, "readinto")) {
    req->body_stream = data;
    curl_easy_setopt(easy, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(easy, CURLOPT_READFUNCTION, &RedC::read_callback);
    curl_easy_setopt(easy, CURLOPT_READDATA, req);

    if (nb::hasattr(data, "__len__")) {
      size_t len_val;
      if (nb::try_cast(data.attr("__len__")(), len_val)) {
        curl_easy_setopt(easy, CURLOPT_INFILESIZE_LARGE, (curl_off_t)len_val);
      }
    }
    return;
  }

  py_dict d_data;
  py_list l_data;
  py_tuple t_data;

  bool is_dict = nb::try_cast(data, d_data);
  bool is_seq =
      !is_dict && (nb::try_cast(data, l_data) || nb::try_cast(data, t_data));

  if (!data.is_none() && (is_dict || is_seq)) {
    string &buf = req->post_data_buffer;

    auto encode = [&](const string &k, const string &v) {
      if (!buf.empty())
        buf += "&";
      char *ek = curl_easy_escape(easy, k.c_str(), 0);
      char *ev = curl_easy_escape(easy, v.c_str(), 0);
      buf += ek ? ek : "";
      buf += "=";
      buf += ev ? ev : "";
      if (ek)
        curl_free(ek);
      if (ev)
        curl_free(ev);
    };

    if (is_dict) {
      for (auto item : d_data) {
        encode(get_as_string(item.first), get_as_string(item.second));
      }
    } else {
      for (auto item : data) {
        py_tuple t_pair;
        if (nb::try_cast(item, t_pair) && t_pair.size() == 2) {
          encode(get_as_string(t_pair[0]), get_as_string(t_pair[1]));
        }
      }
    }

    curl_easy_setopt(easy, CURLOPT_POSTFIELDS, buf.c_str());
    return;
  }

  if (!data.is_none()) {
    string raw = get_as_string(data);
    req->post_data_buffer = raw;
    curl_easy_setopt(easy, CURLOPT_POSTFIELDS, req->post_data_buffer.c_str());
  }
}

void RequestBuilder::handle_mime_content(Request *req, curl_mimepart *part,
                                         const nb::handle &content) {
  py_bytes b_val;
  string s_val;

  if (nb::try_cast(content, b_val)) {
    string b_str = get_as_string(content);
    string &b = req->mime_data_store.emplace_back(std::move(b_str));
    curl_mime_data(part, b.c_str(), b.size());

  } else if (nb::try_cast(content, s_val)) {
    string &s = req->mime_data_store.emplace_back(std::move(s_val));
    curl_mime_data(part, s.c_str(), CURL_ZERO_TERMINATED);

  } else if (nb::hasattr(content, "readinto")) {
    req->mime_streams.push_back(nb::borrow<py_object>(content));
    py_object *stream = &req->mime_streams.back();

    curl_mime_data_cb(part, -1, RedC::mime_read_callback, nullptr, nullptr,
                      stream);
  }
}
