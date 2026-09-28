# Installation

RedC needs Python 3.10 or newer.

```bash
pip install redc
```

You do not install curl yourself. Certificates are checked with [trustifi](https://github.com/AYMENJD/trustifi), which is installed with RedC.

## From a checkout

A source install needs a C++ compiler, CMake, and curl’s development files.

```bash
pip install -e .
```

## This site

```bash
pip install "properdocs>=1.6.7" mkdocs-material
properdocs serve
```

Next: [Quick start](quickstart.md).
