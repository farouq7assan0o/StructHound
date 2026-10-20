"""Human-readable console rendering of a Report."""

from __future__ import annotations

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

    if report.notes:
        lines.append("")
        lines.append("Notes:")
        for note in report.notes:
            lines.append(f"  - {note}")

    return "\n".join(lines)
