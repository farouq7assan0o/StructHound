"""Human-readable console rendering of a Report."""

from __future__ import annotations

from structhound.recover.engine import ResolvedLayout
from structhound.report.schema import Report


def render(report: Report) -> str:
    lines: list[str] = []
    lines.append(f"Artifact : {report.artifact_path}")
    lines.append(f"Format   : {report.artifact_format} ({report.artifact_size} bytes)")

    if report.summary:
        lines.append("")
        lines.append("Summary:")
        for key, value in report.summary.items():
            lines.append(f"  {key:<18}: {value}")

    if report.modules:
        lines.append("")
        lines.append(f"Modules ({len(report.modules)}):")
        lines.append(f"  {'base':<18} {'size':>10}  {'version':<18} name")
        for m in report.modules:
            lines.append(
                f"  {m['base']:#018x} {m['size']:>10}  {m['file_version']:<18} {m['name']}"
            )

    registry = report.details.get("registry")
    if registry:
        lines.append("")
        lines.append("Registry tree:")
        _render_key(registry, lines, indent=1)

    if report.notes:
        lines.append("")
        lines.append("Notes:")
        for note in report.notes:
            lines.append(f"  - {note}")

    return "\n".join(lines)


def _render_key(node: dict, lines: list[str], indent: int) -> None:
    pad = "  " * indent
    lines.append(f"{pad}[{node['name']}]")
    for v in node["values"]:
        lines.append(f"{pad}  {v['name']} ({v['type']}) = {v['value']}")
    for sk in node["subkeys"]:
        _render_key(sk, lines, indent + 1)
    if node.get("truncated"):
        lines.append(f"{pad}  ... (truncated)")


def render_layout(resolved: ResolvedLayout) -> str:
    layout = resolved.layout
    prov = resolved.provenance
    lines: list[str] = []
    lines.append(f"Struct   : {layout.name}  [{layout.arch}]")
    lines.append(f"Size     : {layout.total_size} bytes (align {layout.align})")
    lines.append(
        f"Source   : {prov.method.value} "
        f"(confidence {prov.confidence:.2f}) - {prov.detail}"
    )
    lines.append("")
    lines.append(f"  {'offset':>8}  {'size':>6}  field")
    for info in layout.fields.values():
        lines.append(f"  {info.offset:>8}  {info.size:>6}  {info.name}")
    return "\n".join(lines)
