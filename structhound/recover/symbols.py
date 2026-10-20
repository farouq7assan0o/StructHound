"""Symbol sources: where structure *type* information comes from.

A :class:`SymbolSource` answers "what are the fields and types of struct S in module M at
build B?" The layout engine turns that into concrete offsets.

This milestone ships two sources:

- :class:`DictSymbolSource` — in-memory, used by tests and for registering known types.
- :func:`load_json` — reads a small type-description file (the format a real PDB/DIA
  extraction step would emit). A native PDB backend is a later drop-in: it only has to
  implement :class:`SymbolSource` and return :class:`~structhound.recover.types.Struct`
  objects, so nothing downstream changes.

The type file format::

    {
      "module": "example.dll",
      "build": "26100",
      "structs": {
        "EXAMPLE_STRUCT": {
          "pack": null,
          "fields": [
            {"name": "Flags",  "type": "u32"},
            {"name": "Handle", "type": "ptr"},
            {"name": "Sub",    "type": {"struct": "SUB"}},
            {"name": "Pad",    "type": {"array": "u8", "count": 16}}
          ]
        },
        "SUB": {"fields": [{"name": "Value", "type": "u64"}]}
      }
    }
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod

from structhound.recover.types import PRIMITIVES, Array, Pointer, Struct, Type


class SymbolError(Exception):
    """Raised when a struct/type cannot be resolved from a symbol source."""


class SymbolSource(ABC):
    """Abstract provider of struct type information."""

    @abstractmethod
    def get_struct(self, module: str, build: str, name: str) -> Struct:
        """Return the :class:`Struct` type for ``name`` in ``module`` at ``build``."""


class DictSymbolSource(SymbolSource):
    """Holds structs keyed by ``(module, build)`` in memory."""

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], dict[str, Struct]] = {}

    def register(self, module: str, build: str, struct: Struct) -> None:
        self._store.setdefault((module, build), {})[struct.name] = struct

    def get_struct(self, module: str, build: str, name: str) -> Struct:
        try:
            return self._store[(module, build)][name]
        except KeyError:
            raise SymbolError(
                f"no type info for {name!r} in {module!r} build {build!r}"
            ) from None


def _resolve_field_type(spec, structs: dict[str, Struct]) -> Type:
    """Turn a JSON field-type spec into a Type, resolving nested struct references."""
    if isinstance(spec, str):
        if spec == "ptr":
            return Pointer()
        if spec in PRIMITIVES:
            return PRIMITIVES[spec]
        raise SymbolError(f"unknown primitive type {spec!r}")
    if isinstance(spec, dict):
        if "struct" in spec:
            ref = spec["struct"]
            if ref not in structs:
                raise SymbolError(f"referenced struct {ref!r} not defined")
            return structs[ref]
        if "array" in spec:
            element = _resolve_field_type(spec["array"], structs)
            count = int(spec["count"])
            return Array(element, count)
    raise SymbolError(f"unrecognized type spec: {spec!r}")


def _build_structs(raw_structs: dict) -> dict[str, Struct]:
    """Two-pass build so structs can reference each other by name."""
    # Pass 1: create empty shells.
    structs: dict[str, Struct] = {
        name: Struct(name, [], pack=defn.get("pack")) for name, defn in raw_structs.items()
    }
    # Pass 2: fill fields (nested refs resolve against the shells).
    for name, defn in raw_structs.items():
        fields = [
            (f["name"], _resolve_field_type(f["type"], structs))
            for f in defn.get("fields", [])
        ]
        structs[name].fields = fields
    return structs


def load_json(path: str) -> DictSymbolSource:
    """Load a type-description file into a :class:`DictSymbolSource`."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    return source_from_doc(doc)


def source_from_doc(doc: dict) -> DictSymbolSource:
    module = doc["module"]
    build = str(doc["build"])
    structs = _build_structs(doc.get("structs", {}))
    src = DictSymbolSource()
    for struct in structs.values():
        src.register(module, build, struct)
    return src


def structs_from_doc(doc: dict) -> dict[str, Struct]:
    """Build the ``name -> Struct`` map from a type-description document."""
    return _build_structs(doc.get("structs", {}))
