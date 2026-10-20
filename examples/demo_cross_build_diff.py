"""Demo: what moved between two builds.

Diffs the two committed example type files (same module, a field inserted between builds
22621 and 26100) and prints exactly what changed. This is the question a researcher asks
every patch cycle — "what moved?" — answered from recomputed offsets, no offset table in
sight.

With two real PDBs it is the same command:
    structhound diff --a old/ntdll.pdb --b new/ntdll.pdb --struct _SOME_STRUCT

Run:  python examples/demo_cross_build_diff.py
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from structhound import diff  # noqa: E402
from structhound.recover import symbols  # noqa: E402

HERE = os.path.dirname(__file__)


def _structs(filename: str):
    with open(os.path.join(HERE, filename), encoding="utf-8") as fh:
        return symbols.structs_from_doc(json.load(fh))


def main() -> None:
    old = _structs("example_build_22621.json")
    new = _structs("example_build_26100.json")
    result = diff.diff_structs(old, new, "x64")
    print("build 22621  ->  build 26100\n")
    print(diff.render(result))
    print(
        "\nA hardcoded offset table built for 22621 would read Handle and Count from the "
        "wrong place on 26100. StructHound recomputed both and reported the shift."
    )


if __name__ == "__main__":
    main()
