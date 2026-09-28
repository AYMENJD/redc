"""Docs hooks: attach CurlURL, and render Sphinx examples as code windows.

Source docstrings stay Sphinx, which is what the IDE reads. The reference
parser speaks Google-style sections, so an ``Example:`` plus
``.. code-block:: python`` is shown as raw text. This rewrites that pattern
into an ``Examples:`` block of ``>>>`` lines, which the parser turns into a
highlighted code window. The files on disk are not changed.
"""

from __future__ import annotations

import re

import griffe

_EXAMPLE = re.compile(
    r"^Example:\n"
    r"(?:[ \t]*\.\. code-block::[ \t]*\w+[ \t]*\n)?"
    r"(?:[ \t]*\n)?"
    r"((?:[ \t]+(?:>>>|\.\.\.).*(?:\n|$))+)",
    re.MULTILINE,
)
# Parameter types are already shown in a code cell, so drop the Sphinx ticks.
_ARG_TYPE = re.compile(r"\(``([^`()]+)``(?:, \*optional\*)?\)")
_LITERAL = re.compile(r"``([^`]+)``")

# Inspection copies int.__doc__ onto every integer constant.
_BUILTIN_DOCS = {
    doc.strip()
    for doc in (
        int.__doc__,
        str.__doc__,
        bytes.__doc__,
        float.__doc__,
        bool.__doc__,
        list.__doc__,
        dict.__doc__,
        tuple.__doc__,
    )
    if doc
}


def _rewrite_tree(obj: griffe.Object) -> None:
    doc = obj.docstring
    if doc is not None:
        rewritten = _for_reference(doc.value)
        if rewritten != doc.value:
            doc.value = rewritten
            doc.__dict__.pop("parsed", None)
    for member in obj.members.values():
        _rewrite_tree(member)


class AttachNative(griffe.Extension):
    def on_package(self, *, pkg: griffe.Module, **kwargs) -> None:
        if pkg.canonical_path != "redc" or "redc_ext_url" in pkg.members:
            return
        native = griffe.inspect("redc.redc_ext_url")
        native.name = "redc_ext_url"
        native.parent = pkg
        pkg.members["redc_ext_url"] = native
        _rewrite_tree(native)


def _for_reference(text: str) -> str:
    def example(match: re.Match[str]) -> str:
        lines = ["    " + line.strip() for line in match.group(1).splitlines() if line.strip()]
        return "Examples:\n" + "\n".join(lines) + "\n"

    text = _EXAMPLE.sub(example, text)
    text = _ARG_TYPE.sub(lambda m: f"({m.group(1)}{', optional' if '*optional*' in m.group(0) else ''})", text)
    return _LITERAL.sub(r"`\1`", text)


class StripBuiltinDocs(griffe.Extension):
    def on_instance(self, *, obj: griffe.Object, **kwargs) -> None:
        doc = obj.docstring
        if doc is None:
            return
        rewritten = _for_reference(doc.value)
        if rewritten != doc.value:
            doc.value = rewritten

    def on_attribute(self, *, attr: griffe.Attribute, **kwargs) -> None:
        doc = attr.docstring
        if doc is not None and doc.value.strip() in _BUILTIN_DOCS:
            attr.docstring = None
