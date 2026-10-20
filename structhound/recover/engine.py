"""Layout providers and provenance.

A :class:`LayoutProvider` answers "give me the layout of struct S in module M at build B
on architecture A" and tags the result with how it was obtained and how much to trust it.

- :class:`HardcodedLayoutProvider` is the baseline StructHound exists to replace: a static
  offset table keyed by build. It is exact *only* for builds explicitly in the table and
  silently useless (or wrong) elsewhere.
- :class:`SymbolLayoutProvider` computes the layout from type information via a
  :class:`~structhound.recover.symbols.SymbolSource`, so it adapts to unseen builds.

Both return a :class:`ResolvedLayout` carrying a :class:`Provenance`, so an analyst can
always see whether output is trustworthy.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from abc import ABC, abstractmethod

from structhound.recover.signatures import SignatureError, StructSignatureSet, recover_struct
from structhound.recover.symbols import SymbolError, SymbolSource
from structhound.recover.types import FieldInfo, StructLayout, arch_by_name


class Method(str, Enum):
    SYMBOL = "symbol"
    HARDCODED = "hardcoded"
    SIGNATURE = "signature"


@dataclass(frozen=True)
class Provenance:
    method: Method
    confidence: float  # 0.0 .. 1.0
    detail: str


@dataclass
class ResolvedLayout:
    layout: StructLayout
    provenance: Provenance


class LayoutUnavailable(Exception):
    """Raised when a provider cannot produce a layout for the request."""


class LayoutProvider:
    def layout(
        self, module: str, build: str, struct: str, arch: str = "x64"
    ) -> ResolvedLayout:  # pragma: no cover - abstract
        raise NotImplementedError


class HardcodedLayoutProvider(LayoutProvider):
    """Static offset tables keyed by (module, struct, build).

    ``table[(module, struct, build)] = {"total_size": int, "align": int,
    "fields": {name: (offset, size)}}``.
    """

    def __init__(self, table: dict[tuple[str, str, str], dict]):
        self._table = table

    def layout(self, module: str, build: str, struct: str, arch: str = "x64") -> ResolvedLayout:
        key = (module, struct, build)
        if key not in self._table:
            raise LayoutUnavailable(
                f"hardcoded table has no entry for {struct!r} at build {build!r} "
                f"(this is exactly how offset-table tools break on new builds)"
            )
        entry = self._table[key]
        fields = {
            name: FieldInfo(name, off, size)
            for name, (off, size) in entry["fields"].items()
        }
        resolved = StructLayout(
            name=struct,
            arch=arch,
            total_size=entry.get("total_size", 0),
            align=entry.get("align", 0),
            fields=fields,
        )
        return ResolvedLayout(
            resolved,
            Provenance(Method.HARDCODED, 1.0, f"static offset table entry for build {build}"),
        )


class SymbolLayoutProvider(LayoutProvider):
    """Computes layouts from a symbol source — adapts to builds not seen before."""

    def __init__(self, source: SymbolSource):
        self._source = source

    def layout(self, module: str, build: str, struct: str, arch: str = "x64") -> ResolvedLayout:
        try:
            struct_type = self._source.get_struct(module, build, struct)
        except SymbolError as exc:
            raise LayoutUnavailable(str(exc)) from exc
        computed = struct_type.layout(arch_by_name(arch))
        return ResolvedLayout(
            computed,
            Provenance(
                Method.SYMBOL,
                1.0,
                f"computed from type information for build {build}",
            ),
        )


class CodeSource(ABC):
    """Provides the module code bytes signature recovery scans over."""

    @abstractmethod
    def get_code(self, module: str, build: str) -> bytes:
        ...


class DictCodeSource(CodeSource):
    def __init__(self) -> None:
        self._store: dict[tuple[str, str], bytes] = {}

    def register(self, module: str, build: str, code: bytes) -> None:
        self._store[(module, build)] = code

    def get_code(self, module: str, build: str) -> bytes:
        try:
            return self._store[(module, build)]
        except KeyError:
            raise LayoutUnavailable(
                f"no code available for {module!r} build {build!r}"
            ) from None


class SignatureLayoutProvider(LayoutProvider):
    """Recovers offsets by scanning code for instruction signatures.

    Produces a *partial* layout (only the fields whose signatures matched) with
    confidence < 1.0. ``total_size`` is left as 0 because signatures reveal offsets, not
    the full structure extent. The layout's confidence is the weakest recovered field's.
    """

    def __init__(self, sigset: StructSignatureSet, code_source: CodeSource):
        self._sigset = sigset
        self._code = code_source

    def layout(self, module: str, build: str, struct: str, arch: str = "x64") -> ResolvedLayout:
        try:
            field_sigs = self._sigset.fields_for(struct)
        except SignatureError as exc:
            raise LayoutUnavailable(str(exc)) from exc

        code = self._code.get_code(module, build)  # may raise LayoutUnavailable
        resolved, unresolved = recover_struct(code, field_sigs)
        if not resolved:
            raise LayoutUnavailable(
                f"no signatures matched for {struct!r} in {module!r} build {build!r}"
            )

        fields = {
            name: FieldInfo(name, rf.offset, 0) for name, rf in resolved.items()
        }
        overall = min(rf.confidence for rf in resolved.values())
        detail_bits = [f"{n}@{rf.offset:#x} (conf {rf.confidence})" for n, rf in resolved.items()]
        detail = "; ".join(detail_bits)
        if unresolved:
            detail += f"; unresolved: {', '.join(unresolved)}"

        computed = StructLayout(
            name=struct,
            arch=arch,
            total_size=0,
            align=0,
            fields=fields,
        )
        return ResolvedLayout(computed, Provenance(Method.SIGNATURE, overall, detail))


class LayoutResolver:
    """Tries providers in order and returns the first that succeeds.

    Order expresses preference: symbol-driven first (exact and build-resilient), then the
    hardcoded fallback. Later milestones append a signature-based provider at the end.
    """

    def __init__(self, providers: list[LayoutProvider]):
        self._providers = providers

    def resolve(
        self, module: str, build: str, struct: str, arch: str = "x64"
    ) -> ResolvedLayout:
        errors: list[str] = []
        for provider in self._providers:
            try:
                return provider.layout(module, build, struct, arch)
            except LayoutUnavailable as exc:
                errors.append(f"{provider.__class__.__name__}: {exc}")
        raise LayoutUnavailable(
            "no provider could resolve the layout:\n  " + "\n  ".join(errors)
        )
