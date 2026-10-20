"""Demo: recovering offsets from code when no symbols exist, and the full fallback chain.

Builds a synthetic code blob containing two `mov`-style instructions that reference a
struct's fields, defines signatures for them, and shows the recovered offsets with their
confidence. Then it wires a resolver with all three providers and shows it falling
through symbol (none) -> hardcoded (none) -> signature.

Run:  python examples/demo_signature.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from structhound.recover import engine, signatures, symbols

MODULE = "example.dll"
BUILD = "99999"  # a build we have no symbols or table for
STRUCT = "EXAMPLE_STRUCT"


def _mov(modrm: int, disp: int) -> bytes:
    return bytes([0x48, 0x8B, modrm]) + disp.to_bytes(4, "little")


def _code() -> bytes:
    nop = b"\x90" * 6
    return (
        nop
        + _mov(0x81, 0x10)  # mov rax,[rcx+0x10]  -> Handle
        + nop
        + _mov(0x89, 0x18)  # mov rcx,[rcx+0x18]  -> Count
        + nop
        + bytes([0x4C, 0x8B, 0x81]) + (0x10).to_bytes(4, "little")  # corroborates Handle
    )


def _sigset() -> signatures.StructSignatureSet:
    doc = {
        "module": MODULE,
        "arch": "x64",
        "structs": {
            STRUCT: {
                "fields": {
                    "Handle": [
                        {"pattern": "48 8B 81 ?? ?? ?? ??", "disp_at": 3, "disp_size": 4},
                        {"pattern": "4C 8B 81 ?? ?? ?? ??", "disp_at": 3, "disp_size": 4},
                    ],
                    "Count": [
                        {"pattern": "48 8B 89 ?? ?? ?? ??", "disp_at": 3, "disp_size": 4},
                    ],
                }
            }
        },
    }
    return signatures.signatureset_from_doc(doc)


def main() -> None:
    code_source = engine.DictCodeSource()
    code_source.register(MODULE, BUILD, _code())
    sig_provider = engine.SignatureLayoutProvider(_sigset(), code_source)

    print("Signature recovery (no symbols available):\n")
    resolved = sig_provider.layout(MODULE, BUILD, STRUCT)
    for info in resolved.layout.fields.values():
        print(f"  {info.name:>7}  offset {info.offset:#x}")
    print(f"\n  method     : {resolved.provenance.method.value}")
    print(f"  confidence : {resolved.provenance.confidence}")
    print(f"  detail     : {resolved.provenance.detail}")

    print("\nFallback chain (symbol -> hardcoded -> signature):")
    resolver = engine.LayoutResolver(
        [
            engine.SymbolLayoutProvider(symbols.DictSymbolSource()),  # empty
            engine.HardcodedLayoutProvider({}),  # empty
            sig_provider,
        ]
    )
    chain = resolver.resolve(MODULE, BUILD, STRUCT)
    print(
        f"  resolved via '{chain.provenance.method.value}' "
        f"because symbols and the offset table had nothing for build {BUILD}."
    )


if __name__ == "__main__":
    main()
