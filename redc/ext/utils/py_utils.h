#pragma once

#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <string>

namespace nb = nanobind;

using py_str = nb::str;
using py_bytes = nb::bytes;
using string = std::string;

inline string get_as_string(const nb::handle &h) {
  string s_out;
  if (nb::try_cast(h, s_out)) {
    return s_out;
  }

  nb::bytes b_out;
  if (nb::try_cast(h, b_out)) {
    return string(b_out.c_str(), b_out.size());
  }

  return nb::cast<string>(nb::str(h));
}
