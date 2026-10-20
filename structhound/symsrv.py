"""Fetch a module's PDB from a symbol server.

Given a :class:`~structhound.pe.PdbRef` (GUID + age + name, read from a module's PE
debug directory), this builds the symbol-server URL Microsoft uses and downloads the
PDB. The default server is Microsoft's public store.

Downloaded PDBs are untrusted input: they are written into their own directory and only
ever handed to :func:`structhound.recover.pdb.parse_pdb` as a path.
"""

from __future__ import annotations

import os
import urllib.request

from structhound.pe import PdbRef

DEFAULT_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"
# Microsoft's symbol store historically gates on this User-Agent.
_USER_AGENT = "Microsoft-Symbol-Server/10.0.0.0"


class SymbolServerError(Exception):
    """Raised when a PDB cannot be fetched."""


def pdb_url(ref: PdbRef, server: str = DEFAULT_SYMBOL_SERVER) -> str:
    return f"{server.rstrip('/')}/{ref.pdb_name}/{ref.signature}/{ref.pdb_name}"


def download_pdb(
    ref: PdbRef,
    dest_dir: str,
    server: str = DEFAULT_SYMBOL_SERVER,
    timeout: float = 60.0,
) -> str:
    """Download the PDB for ``ref`` into ``dest_dir`` and return the local path.

    The file is stored under ``dest_dir/<signature>/<pdb_name>`` so multiple builds of
    the same PDB never collide.
    """
    url = pdb_url(ref, server)
    out_dir = os.path.join(dest_dir, ref.signature)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, ref.pdb_name)

    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
    except Exception as exc:  # network / HTTP errors
        raise SymbolServerError(f"failed to fetch {url}: {exc}") from exc

    if data[:4] not in (b"Micr", b"MSF\x20") and b"MSF" not in data[:64]:
        # msdl returns the raw .pdb (an MSF container); a short/HTML body means a miss.
        if len(data) < 256:
            raise SymbolServerError(f"unexpected response from {url} ({len(data)} bytes)")

    with open(out_path, "wb") as fh:
        fh.write(data)
    return out_path
