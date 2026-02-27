"""Output formatters for scan results."""

import json
import sys
from secretlens.scanner import Finding

# ANSI color codes
COLORS = {
    "critical": "\033[91m",  # bright red
    "high": "\033[31m",      # red
    "medium": "\033[33m",    # yellow
    "low": "\033[36m",       # cyan
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}

SEVERITY_ICONS = {
    "critical": "[!!]",
    "high": "[!]",
    "medium": "[~]",
    "low": "[.]",
}


def report_text(findings: list[Finding], *, no_color: bool = False) -> str:
    """Format findings as human-readable text."""
    if not findings:
        return _ok_message(no_color)

    lines: list[str] = []
    grouped = _group_by_file(findings)

    for filepath, file_findings in grouped.items():
        lines.append("")
        lines.append(_colorize(f"--- {filepath} ---", "bold", no_color))

        for f in sorted(file_findings, key=lambda x: x.line_number):
            icon = SEVERITY_ICONS.get(f.severity, "[?]")
            sev_color = f.severity

            prefix = _colorize(f"  {icon}", sev_color, no_color)
            location = _colorize(f"L{f.line_number}", "dim", no_color)
            sev_label = _colorize(f"[{f.severity.upper()}]", sev_color, no_color)

            lines.append(f"{prefix} {location} {sev_label} {f.secret_type}")
            lines.append(f"       Secret: {f.redacted_value}")
            lines.append(f"       {_colorize(f.description, 'dim', no_color)}")

    # Summary
    lines.append("")
    total = len(findings)
    by_sev = _count_by_severity(findings)
    summary_parts = []
    for sev in ["critical", "high", "medium", "low"]:
        count = by_sev.get(sev, 0)
        if count > 0:
            summary_parts.append(_colorize(f"{count} {sev}", sev, no_color))

    lines.append(
        _colorize(f"Found {total} secret(s): ", "bold", no_color)
        + ", ".join(summary_parts)
    )

    return "\n".join(lines)


def report_json(findings: list[Finding]) -> str:
    """Format findings as JSON."""
    results = []
    for f in findings:
        results.append({
            "file": f.file,
            "line": f.line_number,
            "type": f.secret_type,
            "severity": f.severity,
            "secret_redacted": f.redacted_value,
            "description": f.description,
        })

    output = {
        "total": len(findings),
        "by_severity": _count_by_severity(findings),
        "findings": results,
    }
    return json.dumps(output, indent=2)


def _ok_message(no_color: bool) -> str:
    check = _colorize("[OK]", "low", no_color)
    return f"\n{check} No secrets found.\n"


def _group_by_file(findings: list[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.file, []).append(f)
    return grouped


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _colorize(text: str, style: str, no_color: bool) -> str:
    if no_color or not sys.stdout.isatty():
        return text
    code = COLORS.get(style, "")
    reset = COLORS["reset"]
    if not code:
        return text
    return f"{code}{text}{reset}"
