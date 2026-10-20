"""Layout recovery engine — the core differentiator.

Determines undocumented structure layouts for the target Windows build instead of
relying on a hardcoded offset table:

- symbol-driven path (preferred, exact)
- signature-based fallback (reported with a confidence level)

Every recovered layout carries provenance (which path, how confident).
"""
