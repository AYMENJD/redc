#pragma once

#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <string>

namespace nb = nanobind;

inline std::string get_as_string(const nb::handle &h) {
  std::string s_out;

  if (h.is_none()) {
    return s_out;
  }

  if (nb::try_cast(h, s_out)) {
    return s_out;
  }

  nb::bytes b_out;
  if (nb::try_cast(h, b_out)) {
    return string(b_out.c_str(), b_out.size());
  }

  return nb::cast<std::string>(nb::str(h));
}
