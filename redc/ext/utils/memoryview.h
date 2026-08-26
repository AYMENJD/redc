#include <nanobind/nanobind.h>

namespace nb = nanobind;

#ifndef PyBUF_WRITE
#define PyBUF_WRITE 0x200
#endif

// nanobind's memoryview wrapper does not expose FromMemory (no owner /
// keep-alive). This is only used synchronously inside curl read callbacks,
// where `mem` is valid for the duration of the call.
inline nb::memoryview mv_from_buffer(void *mem, Py_ssize_t size) {
  PyObject *ptr =
      PyMemoryView_FromMemory(reinterpret_cast<char *>(mem), size, PyBUF_WRITE);

  if (!ptr) {
    nb::detail::raise_python_error();
  }

  return nb::steal<nb::memoryview>(ptr);
}
