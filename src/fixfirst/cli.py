"""The fixfirst command line interface."""

import argparse
import io
import json
import sys
import unicodedata
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from fixfirst.assets import assign_assets, load_assets
from fixfirst.dedup import merge_findings
from fixfirst.errors import InputError
from fixfirst.ingest.trivy import parse_report
from fixfirst.models import IngestResult, Severity

EXIT_OK = 0
EXIT_INPUT_ERROR = 2

_LABEL_WIDTH = 22
_SEVERITY_WIDTH = 10
_MAX_WARNING_VALUE_LENGTH = 80


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    args = _build_parser().parse_args(argv)
    _make_output_encoding_safe()
    try:
        result, unrecognized_statuses = _ingest(args.reports, args.assets)
    except InputError as exc:
        print(f"error: {_sanitize(str(exc))}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    for status in sorted(unrecognized_statuses):
        print(
            f"warning: unrecognized fix status treated as unknown: {_shorten_and_sanitize(status)}",
            file=sys.stderr,
        )
    print(_render_json(result) if args.as_json else _render_text(result))
    return EXIT_OK


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fixfirst", description="Vulnerability triage.")
    commands = parser.add_subparsers(dest="command", required=True)
    ingest = commands.add_parser(
        "ingest", help="Normalize Trivy reports, map them to assets and summarize the findings."
    )
    ingest.add_argument(
        "reports", nargs="+", type=Path, metavar="REPORT.json", help="Trivy JSON report"
    )
    ingest.add_argument(
        "--assets", required=True, type=Path, metavar="assets.yaml", help="asset inventory file"
    )
    ingest.add_argument(
        "--json", action="store_true", dest="as_json", help="print the normalized findings as JSON"
    )
    return parser


def _make_output_encoding_safe() -> None:
    # Legacy Windows code pages cannot encode every character found in a report.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="backslashreplace")


def _ingest(report_paths: Sequence[Path], assets_path: Path) -> tuple[IngestResult, set[str]]:
    """Return the result and the distinct unrecognized status values across all reports."""
    assets = load_assets(assets_path)
    reports = [parse_report(path) for path in report_paths]
    findings, unassigned = assign_assets(reports, assets)
    result = IngestResult(findings=merge_findings(findings), unassigned_artifacts=unassigned)
    return result, {status for report in reports for status in report.unrecognized_fix_statuses}


def _render_json(result: IngestResult) -> str:
    # ASCII-only output cannot carry raw control characters and survives any console encoding.
    return json.dumps(result.model_dump(mode="json"), ensure_ascii=True, indent=2)


def _render_text(result: IngestResult) -> str:
    counts = Counter(finding.scanner_severity for finding in result.findings)
    affected_assets = {asset_id for finding in result.findings for asset_id in finding.asset_ids}

    lines = ["Findings by severity:"]
    lines += [
        f"  {severity.value:<{_SEVERITY_WIDTH}}{counts[severity]}"
        for severity in sorted(Severity, key=lambda s: s.rank, reverse=True)
    ]
    lines += [
        f"{'Unique findings:':<{_LABEL_WIDTH}}{len(result.findings)}",
        f"{'Assets affected:':<{_LABEL_WIDTH}}{len(affected_assets)}",
        f"{'Unassigned artifacts:':<{_LABEL_WIDTH}}{len(result.unassigned_artifacts)}",
    ]
    lines += [f"  {_sanitize(artifact)}" for artifact in result.unassigned_artifacts]
    return "\n".join(lines)


def _shorten_and_sanitize(value: str) -> str:
    if len(value) > _MAX_WARNING_VALUE_LENGTH:
        return f"{_sanitize(value[:_MAX_WARNING_VALUE_LENGTH])}..."
    return _sanitize(value)


def _sanitize(text: str) -> str:
    """Escape characters that could manipulate a terminal, such as ANSI or bidi sequences."""
    return "".join(_escape_char(char) for char in text)


def _escape_char(char: str) -> str:
    # Categories C* cover control and format characters; Zl and Zp are line and paragraph breaks.
    category = unicodedata.category(char)
    if category.startswith("C") or category in {"Zl", "Zp"}:
        return char.encode("unicode_escape").decode("ascii")
    return char
