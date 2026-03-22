#include <nanobind/nanobind.h>

namespace nb = nanobind;

inline nb::object mv_from_buffer(void *mem, Py_ssize_t size) {
  PyObject *ptr =
      PyMemoryView_FromMemory(reinterpret_cast<char *>(mem), size, PyBUF_WRITE);

  if (!ptr) {
    nb::detail::raise_python_error();
  }

  return nb::steal(ptr);
}
