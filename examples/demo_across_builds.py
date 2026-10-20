"""Before/after demo: why computing offsets beats a hardcoded offset table.

Scenario: between build 22621 and 26100, a new 8-byte field ("Extra") is inserted into
EXAMPLE_STRUCT. That shifts every field after it.

- The hardcoded provider only knows build 22621 (the common real-world case: the table
  was never updated for the new build). Asked about 26100, it fails outright.
- The symbol provider computes the layout from each build's type info, so it is correct
  on both — including the build it had never seen.

Run:  python examples/demo_across_builds.py
"""

from __future__ import annotations

import json
import os
import sys

# Allow running as a plain script (python examples/demo_across_builds.py) without
# installing the package first.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from structhound.recover import engine, symbols

HERE = os.path.dirname(__file__)
MODULE = "example.dll"
STRUCT = "EXAMPLE_STRUCT"


def _symbol_provider() -> engine.SymbolLayoutProvider:
    source = symbols.DictSymbolSource()
    for fname in ("example_build_22621.json", "example_build_26100.json"):
        with open(os.path.join(HERE, fname), encoding="utf-8") as fh:
            doc = json.load(fh)
        loaded = symbols.source_from_doc(doc)
        # Merge into one source so both builds are queryable.
        build = str(doc["build"])
        source.register(MODULE, build, loaded.get_struct(MODULE, build, STRUCT))
    return engine.SymbolLayoutProvider(source)


def _hardcoded_provider_knowing_only_22621() -> engine.HardcodedLayoutProvider:
    # A static table someone wrote for 22621 and never updated.
    table = {
        (MODULE, STRUCT, "22621"): {
            "total_size": 24,
            "align": 8,
            "fields": {"Flags": (0, 4), "Handle": (8, 8), "Count": (16, 4)},
        }
    }
    return engine.HardcodedLayoutProvider(table)


def _field_offset(provider, build: str, field: str) -> str:
    try:
        resolved = provider.layout(MODULE, build, STRUCT)
        return str(resolved.layout.offset(field))
    except engine.LayoutUnavailable:
        return "BROKEN (no layout)"


def main() -> None:
    hardcoded = _hardcoded_provider_knowing_only_22621()
    symbol = _symbol_provider()

    print(f"{'build':>8}  {'field':>7}  {'hardcoded':>18}  {'symbol-driven':>14}")
    for build in ("22621", "26100"):
        for field in ("Handle", "Count"):
            print(
                f"{build:>8}  {field:>7}  "
                f"{_field_offset(hardcoded, build, field):>18}  "
                f"{_field_offset(symbol, build, field):>14}"
            )
    print(
        "\nThe hardcoded table is correct on 22621 and useless on 26100.\n"
        "The symbol-driven engine is correct on both, including the build it never saw."
    )


if __name__ == "__main__":
    main()
