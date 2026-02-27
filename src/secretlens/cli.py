"""Command-line interface for secretlens."""

import argparse
import sys

from secretlens import __version__
from secretlens.scanner import ScanConfig, scan
from secretlens.reporter import report_text, report_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretlens",
        description="A fast, lightweight secret scanner for codebases.",
        epilog="Examples:\n"
               "  secretlens .                    Scan current directory\n"
               "  secretlens src/ --severity critical   Only critical findings\n"
               "  secretlens . --json             Output as JSON\n"
               "  secretlens . --no-entropy       Disable entropy scanning\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--version", action="version", version=f"secretlens {__version__}",
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--no-entropy", action="store_true",
        help="Disable Shannon entropy-based detection",
    )
    parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Only show findings of this severity level",
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=1_000_000,
        metavar="BYTES",
        help="Skip files larger than this (default: 1MB)",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        metavar="DIR",
        help="Additional directories to exclude (can be repeated)",
    )
    parser.add_argument(
        "--exclude-pattern",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Additional file patterns to exclude (can be repeated)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = ScanConfig(
        entropy_scan=not args.no_entropy,
        severity_filter=args.severity,
        max_file_size=args.max_file_size,
    )

    if args.exclude_dir:
        config.exclude_dirs.extend(args.exclude_dir)
    if args.exclude_pattern:
        config.exclude_patterns.extend(args.exclude_pattern)

    try:
        findings = scan(args.path, config)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    if args.json_output:
        print(report_json(findings))
    else:
        print(report_text(findings, no_color=args.no_color))

    # Exit code: 1 if secrets found, 0 if clean
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
