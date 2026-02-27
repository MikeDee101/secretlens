"""Core scanning engine that ties together pattern matching and entropy analysis."""

import os
import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

from secretlens.patterns import PATTERNS, SecretPattern
from secretlens.entropy import find_high_entropy_strings


@dataclass
class Finding:
    file: str
    line_number: int
    line_content: str
    secret_type: str
    secret_value: str
    severity: str
    description: str

    @property
    def redacted_value(self) -> str:
        """Show only first 4 and last 4 characters of the secret."""
        v = self.secret_value
        if len(v) <= 12:
            return v[:3] + "..." + v[-3:]
        return v[:4] + "..." + v[-4:]


@dataclass
class ScanConfig:
    """Configuration for scanning."""
    exclude_patterns: list[str] = field(default_factory=lambda: [
        "*.lock", "*.min.js", "*.min.css", "*.map",
        "*.svg", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico",
        "*.woff", "*.woff2", "*.ttf", "*.eot",
        "*.pyc", "*.pyo", "*.so", "*.dll", "*.exe",
        "*.zip", "*.tar", "*.gz", "*.bz2", "*.7z",
        "*.pdf", "*.doc", "*.docx",
    ])
    exclude_dirs: list[str] = field(default_factory=lambda: [
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
        ".egg-info", ".eggs", "vendor", "third_party",
    ])
    max_file_size: int = 1_000_000  # 1 MB
    entropy_scan: bool = True
    severity_filter: str | None = None  # None = all severities


class Scanner:
    """Scans files and directories for secrets."""

    def __init__(self, config: ScanConfig | None = None):
        self.config = config or ScanConfig()

    def scan_path(self, path: str) -> list[Finding]:
        """Scan a file or directory and return all findings."""
        target = Path(path)
        if target.is_file():
            return self._scan_file(target)
        elif target.is_dir():
            return self._scan_directory(target)
        else:
            raise FileNotFoundError(f"Path not found: {path}")

    def _scan_directory(self, directory: Path) -> list[Finding]:
        """Recursively scan a directory."""
        findings: list[Finding] = []

        for root, dirs, files in os.walk(directory):
            # Prune excluded directories
            dirs[:] = [
                d for d in dirs
                if d not in self.config.exclude_dirs
                and not d.startswith(".")
            ]

            for filename in files:
                filepath = Path(root) / filename

                if self._should_skip_file(filepath):
                    continue

                findings.extend(self._scan_file(filepath))

        return findings

    def _should_skip_file(self, filepath: Path) -> bool:
        """Check if a file should be skipped based on configuration."""
        name = filepath.name

        for pattern in self.config.exclude_patterns:
            if fnmatch.fnmatch(name, pattern):
                return True

        try:
            if filepath.stat().st_size > self.config.max_file_size:
                return True
        except OSError:
            return True

        return False

    def _scan_file(self, filepath: Path) -> list[Finding]:
        """Scan a single file for secrets."""
        findings: list[Finding] = []

        if self._should_skip_file(filepath):
            return findings

        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            return findings

        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Pattern-based detection
            for pattern_def in PATTERNS:
                if self.config.severity_filter and pattern_def.severity != self.config.severity_filter:
                    continue

                match = pattern_def.pattern.search(line)
                if match:
                    secret_val = match.group("secret") if "secret" in match.groupdict() else match.group(0)
                    findings.append(Finding(
                        file=str(filepath),
                        line_number=line_num,
                        line_content=line.rstrip(),
                        secret_type=pattern_def.name,
                        secret_value=secret_val,
                        severity=pattern_def.severity,
                        description=pattern_def.description,
                    ))

            # Entropy-based detection
            if self.config.entropy_scan and (
                not self.config.severity_filter or self.config.severity_filter == "medium"
            ):
                for result in find_high_entropy_strings(line):
                    findings.append(Finding(
                        file=str(filepath),
                        line_number=line_num,
                        line_content=line.rstrip(),
                        secret_type="High Entropy String",
                        secret_value=result["value"],
                        severity="medium",
                        description=f"High entropy {result['encoding']} string (entropy: {result['entropy']})",
                    ))

        return findings


def scan(path: str, config: ScanConfig | None = None) -> list[Finding]:
    """Convenience function to scan a path for secrets."""
    scanner = Scanner(config)
    return scanner.scan_path(path)
