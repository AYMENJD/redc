#pragma once

#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <string>

namespace nb = nanobind;

using py_str = nb::str;
using py_bytes = nb::bytes;
using string = std::string;

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
