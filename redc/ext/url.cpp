#include <curl/curl.h>
#include <nanobind/nanobind.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/string_view.h>
#include <optional>
#include <stdexcept>
#include <string_view>

namespace nb = nanobind;

static bool is_valid_url(const char *url) {
  CURLU *h = curl_url();
  if (!h)
    return false;

  CURLUcode rc = curl_url_set(h, CURLUPART_URL, url, 0);
  curl_url_cleanup(h);

  return rc == CURLUE_OK;
}

static CURLUPart part_from_string(std::string_view key) {
  switch (key.size()) {
  case 4:
    if (key == "user")
      return CURLUPART_USER;
    if (key == "host")
      return CURLUPART_HOST;
    if (key == "port")
      return CURLUPART_PORT;
    if (key == "path")
      return CURLUPART_PATH;
    break;

  case 5:
    if (key == "query")
      return CURLUPART_QUERY;
    break;

  case 6:
    if (key == "scheme")
      return CURLUPART_SCHEME;
    break;

  case 7:
    if (key == "zoneid")
      return CURLUPART_ZONEID;
    break;

  case 8:
    if (key == "password")
      return CURLUPART_PASSWORD;
    if (key == "options")
      return CURLUPART_OPTIONS;
    if (key == "fragment")
      return CURLUPART_FRAGMENT;
    break;
  }

  throw nb::key_error("Invalid URL part");
}

static const char *curlu_strerror(CURLUcode code) {
  switch (code) {
  case CURLUE_BAD_HANDLE:
    return "Bad handle";
  case CURLUE_MALFORMED_INPUT:
    return "Malformed input";
  case CURLUE_BAD_PORT_NUMBER:
    return "Bad port number";
  case CURLUE_UNSUPPORTED_SCHEME:
    return "Unsupported scheme";
  case CURLUE_URLDECODE:
    return "URL decode error";
  case CURLUE_OUT_OF_MEMORY:
    return "Out of memory";
  case CURLUE_UNKNOWN_PART:
    return "Unknown URL part";
  case CURLUE_NO_OPTIONS:
    return "No options";
  case CURLUE_NO_SCHEME:
    return "No scheme";
  case CURLUE_NO_USER:
    return "No user";
  case CURLUE_NO_PASSWORD:
    return "No password";
  case CURLUE_NO_HOST:
    return "No host";
  case CURLUE_NO_PORT:
    return "No port";
  case CURLUE_NO_QUERY:
    return "No query";
  case CURLUE_NO_FRAGMENT:
    return "No fragment";
  case CURLUE_NO_ZONEID:
    return "No zoneid";
  case CURLUE_BAD_HOSTNAME:
    return "Bad hostname";
#ifdef CURLUE_LACKS_IDN
  case CURLUE_LACKS_IDN:
    return "IDN support not available";
#endif
  default:
    return "URL error";
  }
}

static bool is_missing(CURLUcode rc) {
  return rc == CURLUE_NO_SCHEME || rc == CURLUE_NO_USER ||
         rc == CURLUE_NO_PASSWORD || rc == CURLUE_NO_OPTIONS ||
         rc == CURLUE_NO_HOST || rc == CURLUE_NO_PORT ||
         rc == CURLUE_NO_QUERY || rc == CURLUE_NO_FRAGMENT ||
         rc == CURLUE_NO_ZONEID;
}

static void throw_curl_error(CURLUcode code) {
  const char *msg = curlu_strerror(code);

  switch (code) {
  case CURLUE_BAD_HOSTNAME:
  case CURLUE_MALFORMED_INPUT:
  case CURLUE_BAD_PORT_NUMBER:
  case CURLUE_UNSUPPORTED_SCHEME:
  case CURLUE_URLDECODE:
  case CURLUE_NO_SCHEME:
    throw std::invalid_argument(msg);

#ifdef CURLUE_LACKS_IDN
  case CURLUE_LACKS_IDN:
    throw std::runtime_error(msg);
#endif

  case CURLUE_OUT_OF_MEMORY:
    throw std::bad_alloc();

  case CURLUE_UNKNOWN_PART:
    throw nb::key_error(msg);

  default:
    throw std::runtime_error(msg);
  }
}

struct CurlURL {
  CURLU *handle;

  CurlURL() {
    handle = curl_url();
    if (!handle)
      throw std::bad_alloc();
  }

  CurlURL(const char *url) {
    handle = curl_url();
    if (!handle)
      throw std::bad_alloc();

    CURLUcode rc = curl_url_set(handle, CURLUPART_URL, url, 0);
    if (rc != CURLUE_OK) {
      curl_url_cleanup(handle);
      throw_curl_error(rc);
    }
  }

  CurlURL(const CurlURL &) = delete;
  CurlURL &operator=(const CurlURL &) = delete;

  ~CurlURL() { curl_url_cleanup(handle); }

  nb::object get_impl(CURLUPart part, unsigned int flags) const {
    char *out = nullptr;

    CURLUcode rc = curl_url_get(handle, part, &out, flags);

    if (rc == CURLUE_OK && out) {
      if (part == CURLUPART_PORT) {
        int port = std::atoi(out);
        curl_free(out);
        return nb::int_(port);
      }

      nb::str result(out);
      curl_free(out);
      return result;
    }

    if (is_missing(rc))
      return nb::none();

    throw_curl_error(rc);
    return nb::none();
  }

  nb::object get_part(CURLUPart part) const {
    unsigned int flags = 0;
#ifdef CURLU_GET_EMPTY
    flags |= CURLU_GET_EMPTY;
#endif

    return get_impl(part, flags);
  }

  void set_part(CURLUPart part, std::optional<std::string_view> value) {
    const char *v = value ? value->data() : nullptr;
    CURLUcode rc = curl_url_set(handle, part, v, 0);
    if (rc != CURLUE_OK)
      throw_curl_error(rc);
  }

  nb::object get_port() const {
    char *out = nullptr;

    CURLUcode rc = curl_url_get(handle, CURLUPART_PORT, &out, 0);

    if (rc == CURLUE_OK && out) {
      int port = std::atoi(out);
      curl_free(out);
      return nb::int_(port);
    }

    if (is_missing(rc))
      return nb::none();

    throw_curl_error(rc);
    return nb::none();
  }

  void set_port(std::optional<int> port) {
    if (port) {
      set_part(CURLUPART_PORT, std::to_string(*port));
    } else {
      set_part(CURLUPART_PORT, std::nullopt);
    }
  }

  nb::object get(std::string_view key, bool decode = false, bool encode = false,
                 bool punycode = false, bool empty = false) const {
    unsigned int flags = 0;

    if (decode)
      flags |= CURLU_URLDECODE;
    if (encode)
      flags |= CURLU_URLENCODE;
    if (punycode)
      flags |= CURLU_PUNYCODE;

#ifdef CURLU_GET_EMPTY
    if (empty)
      flags |= CURLU_GET_EMPTY;
#endif

    return get_impl(part_from_string(key), flags);
  }

  void reset(const char *url) {
    CURLUcode rc = curl_url_set(handle, CURLUPART_URL, url, 0);
    if (rc != CURLUE_OK)
      throw_curl_error(rc);
  }

  nb::str str() const {
    char *out = nullptr;

    CURLUcode rc = curl_url_get(handle, CURLUPART_URL, &out, 0);

    if (rc == CURLUE_OK && out) {
      nb::str result(out);
      curl_free(out);
      return result;
    }

    throw_curl_error(rc);
    return nb::str();
  }

  nb::dict parts() const {
    nb::dict d;
    d["scheme"] = get_part(CURLUPART_SCHEME);
    d["user"] = get_part(CURLUPART_USER);
    d["password"] = get_part(CURLUPART_PASSWORD);
    d["options"] = get_part(CURLUPART_OPTIONS);
    d["host"] = get_part(CURLUPART_HOST);
    d["zoneid"] = get_part(CURLUPART_ZONEID);
    d["port"] = get_port();
    d["path"] = get_part(CURLUPART_PATH);
    d["query"] = get_part(CURLUPART_QUERY);
    d["fragment"] = get_part(CURLUPART_FRAGMENT);
    return d;
  }
};

static int curlurl_tp_traverse(PyObject *self, visitproc visit, void *arg) {
  return 0;
}

static int curlurl_tp_clear(PyObject *self) { return 0; }

#define BIND_URL_PART(name, CURL_PART)                                         \
  .def_prop_rw(                                                                \
      name, [](const CurlURL &u) { return u.get_part(CURL_PART); },            \
      [](CurlURL &u, std::optional<std::string_view> v) {                      \
        u.set_part(CURL_PART, v);                                              \
      })

static PyType_Slot curlurl_slots[] = {
    {Py_tp_traverse, (void *)curlurl_tp_traverse},
    {Py_tp_clear, (void *)curlurl_tp_clear},
    {0, nullptr}};

NB_MODULE(redc_ext_url, m) {
  nb::class_<CurlURL>(m, "CurlURL", nb::type_slots(curlurl_slots),
                      R"doc(
URL parser and builder backed by libcurl.

Example:
    .. code-block:: python

        >>> u = CurlURL("https://user:pass@example.com:8080/path?q=1#frag")
        >>> u.host
        'example.com'
        >>> u.port
        8080
        >>> u.path
        '/path'
        >>> u.query = None
        >>> u["port"] = 443
        >>> str(u)
        'https://user:pass@example.com:443/path#frag'

Attributes:
    scheme (``str``, *optional*):
        URL scheme (e.g. ``http``, ``https``). Returns ``None`` if missing

    user (``str``, *optional*):
        Username component of the URL. Returns ``None`` if missing

    password (``str``, *optional*):
        Password component of the URL. Returns ``None`` if missing

    options (``str``, *optional*):
        URL options component. Returns ``None`` if missing

    host (``str``, *optional*):
        Hostname or IP address. Returns ``None`` if missing

    zoneid (``str``, *optional*):
        IPv6 zone identifier. Returns ``None`` if missing

    port (``int``, *optional*):
        Port number. Returns ``None`` if missing

    path (``str``, *optional*):
        URL path. Returns ``None`` if missing

    query (``str``, *optional*):
        Query string without ``?``. Returns ``None`` if missing

    fragment (``str``, *optional*):
        Fragment without ``#``. Returns ``None`` if missing

Notes:
    - All components can be modified or removed by assigning ``None``
    - Dict-style access is supported via ``u["host"]`` and assignment via ``u["port"] = 443``
)doc")
      .def(nb::init<>(), R"doc(Create an empty URL object.)doc")
      .def(nb::init<const char *>(), nb::arg("url"),
           R"doc(
Create and parse a URL.

Args:
    url (``str``):
        URL to parse
)doc")

          BIND_URL_PART("scheme", CURLUPART_SCHEME)
              BIND_URL_PART("user", CURLUPART_USER)
                  BIND_URL_PART("password", CURLUPART_PASSWORD)
                      BIND_URL_PART("options", CURLUPART_OPTIONS)
                          BIND_URL_PART("host", CURLUPART_HOST)
                              BIND_URL_PART("zoneid", CURLUPART_ZONEID)
                                  BIND_URL_PART("path", CURLUPART_PATH)
                                      BIND_URL_PART("query", CURLUPART_QUERY)
                                          BIND_URL_PART("fragment",
                                                        CURLUPART_FRAGMENT)

      .def_prop_rw("port", &CurlURL::get_port, &CurlURL::set_port,
                   R"doc(
Port number.

Returns:
    ``int`` | ``None``:
        The port number if present
)doc")

      .def("get", &CurlURL::get, nb::arg("part"), nb::arg("decode") = false,
           nb::arg("encode") = false, nb::arg("punycode") = false,
           nb::arg("empty") = false,
           R"doc(
Get a URL component dynamically.

Example:
    .. code-block:: python

        >>> u.get("host")
        'example.com'
        >>> u.get("path", decode=True)

Args:
    part (``str``):
        One of: ``scheme``, ``user``, ``password``, ``options``,
        ``host``, ``zoneid``, ``port``, ``path``, ``query``, ``fragment``

    decode (``bool``, *optional*):
        Apply URL decoding. Default is ``False``

    encode (``bool``, *optional*):
        Apply URL encoding. Default is ``False``

    punycode (``bool``, *optional*):
        Convert host to punycode if applicable. Default is ``False``

    empty (``bool``, *optional*):
        Return empty strings instead of ``None`` when supported by libcurl. Default is ``False``

Returns:
    ``str`` | ``int`` | ``None``:
        The requested component
)doc")

      .def(
          "__getitem__",
          [](const CurlURL &u, std::string_view key) {
            CURLUPart part = part_from_string(key);
            if (part == CURLUPART_PORT)
              return u.get_port();
            return u.get_part(part);
          },
          R"doc(
Dict-style access to URL components.

Example:
    .. code-block:: python

        >>> u["host"]
        'example.com'
)doc")

      .def(
          "__setitem__",
          [](CurlURL &u, std::string_view key, nb::object v) {
            CURLUPart part = part_from_string(key);

            if (part == CURLUPART_PORT) {
              if (v.is_none()) {
                u.set_port(std::nullopt);
              } else {
                u.set_port(nb::cast<int>(v));
              }
              return;
            }

            if (v.is_none()) {
              u.set_part(part, std::nullopt);
              return;
            }

            std::string tmp = nb::cast<std::string>(v);
            u.set_part(part, std::string_view(tmp));
          },
          nb::arg("key"), nb::arg("value").none(),
          R"doc(
Dict-style assignment to URL components.

Example:
    .. code-block:: python

        >>> u["port"] = 443
        >>> u["query"] = None
)doc")

      .def("parts", &CurlURL::parts,
           R"doc(
Return all URL components as a dictionary.

Returns:
    ``dict``:
        Mapping of all URL parts to their values (``None`` if missing)
)doc")

      .def("reset", &CurlURL::reset, nb::arg("url"),
           R"doc(
Replace the current URL.

Args:
    url (``str``):
        New URL to parse
)doc")
      .def_static(
          "is_valid_url", [](const char *url) { return is_valid_url(url); },
          nb::arg("url"),
          R"doc(
Check if a URL is valid.

Args:
    url (``str``):
        URL to validate

Returns:
    ``bool``:
        ``True`` if the URL is valid, otherwise ``False``
)doc")
      .def("__str__", &CurlURL::str, R"doc(
Return the full URL string.

Returns:
    ``str``:
        The reconstructed URL
)doc")

      .def("__repr__", [](const CurlURL &u) {
        return nb::str("<CurlURL '") + u.str() + nb::str("'>");
      });
}
