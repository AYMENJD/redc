#include <nanobind/nanobind.h>

NAMESPACE_BEGIN(NB_NAMESPACE)

// https://github.com/lief-project/LIEF/blob/abcf929efb748c7846dd59007cbb807e108db311/api/python/src/nanobind/extra/memoryview.hpp
class memoryview : public object {
  using ssize_t = Py_ssize_t;

 public:
  NB_OBJECT(memoryview, object, "memoryview", PyMemoryView_Check)

  memoryview(const object &o)
      : object(check_(o) ? o.inc_ref().ptr() : PyMemoryView_FromObject(o.ptr()), detail::steal_t{}) {
    if (!m_ptr)
      detail::raise_python_error();
  }

  memoryview(object &&o) : object(check_(o) ? o.release().ptr() : PyMemoryView_FromObject(o.ptr()), detail::steal_t{}) {
    if (!m_ptr)
      detail::raise_python_error();
  }

  static memoryview from_memory(void *mem, ssize_t size, bool readonly = false) {
    PyObject *ptr = PyMemoryView_FromMemory(reinterpret_cast<char *>(mem), size, (readonly) ? PyBUF_READ : PyBUF_WRITE);
    if (!ptr) {
      detail::fail("Could not allocate memoryview object!");
    }
    return memoryview(object(ptr, detail::steal_t{}));
  }

  static memoryview from_memory(const void *mem, ssize_t size) {
    return memoryview::from_memory(const_cast<void *>(mem), size, true);
  }
};

NAMESPACE_END(NB_NAMESPACE)
