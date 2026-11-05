"""The fixfirst command line interface."""

import argparse
import io
import json
import sys
import unicodedata
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel

from fixfirst.assets import assign_assets, load_assets
from fixfirst.dedup import merge_findings
from fixfirst.enrich import is_cve_id
from fixfirst.enrich.cache import Cache, default_cache_dir, utc_now
from fixfirst.enrich.epss import EpssData, load_epss
from fixfirst.enrich.fetcher import Fetcher, UrllibFetcher
from fixfirst.enrich.kev import KevData, load_kev
from fixfirst.errors import EnrichmentError, InputError
from fixfirst.ingest.trivy import parse_report
from fixfirst.models import Asset, EpssState, IngestResult, KevState, Severity
from fixfirst.rules import Priority
from fixfirst.triage import TriageDecision, TriageResult, limit_decisions, triage

EXIT_OK = 0
EXIT_INPUT_ERROR = 2
EXIT_ENRICHMENT_UNAVAILABLE = 3

_LABEL_WIDTH = 22
_SEVERITY_WIDTH = 10
_PRIORITY_WIDTH = 4
_MAX_WARNING_VALUE_LENGTH = 80


def main(
    argv: Sequence[str] | None = None,
    *,
    fetcher: Fetcher | None = None,
    now: Callable[[], datetime] = utc_now,
) -> int:
    """Run the CLI and return the process exit code. Tests can replace the network and the clock."""
    args = _build_parser().parse_args(argv)
    _make_output_encoding_safe()
    try:
        if args.command == "triage":
            return _run_triage(args, fetcher, now)
        return _run_ingest(args)
    except InputError as exc:
        print(f"error: {_sanitize(str(exc))}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except EnrichmentError as exc:
        print(f"error: {_sanitize(str(exc))}", file=sys.stderr)
        return EXIT_ENRICHMENT_UNAVAILABLE


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fixfirst", description="Vulnerability triage.")
    commands = parser.add_subparsers(dest="command", required=True)

    ingest = commands.add_parser(
        "ingest", help="Normalize Trivy reports, map them to assets and summarize the findings."
    )
    _add_common_arguments(ingest)
    ingest.add_argument(
        "--json", action="store_true", dest="as_json", help="print the normalized findings as JSON"
    )

    triage_command = commands.add_parser(
        "triage", help="Order findings by priority, with the rule and evidence behind each one."
    )
    _add_common_arguments(triage_command)
    triage_command.add_argument(
        "--cache-dir", type=Path, metavar="DIR", help="directory for downloaded enrichment data"
    )
    triage_command.add_argument(
        "--offline", action="store_true", help="use only cached enrichment data, with no network"
    )
    triage_command.add_argument(
        "--json", action="store_true", dest="as_json", help="print decisions and evidence as JSON"
    )
    triage_command.add_argument(
        "--top", type=_positive_int, metavar="N", help="list only the N highest priority findings"
    )
    return parser


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "reports", nargs="+", type=Path, metavar="REPORT.json", help="Trivy JSON report"
    )
    parser.add_argument(
        "--assets", required=True, type=Path, metavar="assets.yaml", help="asset inventory file"
    )


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _make_output_encoding_safe() -> None:
    # Legacy Windows code pages cannot encode every character found in a report.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="backslashreplace")


def _run_ingest(args: argparse.Namespace) -> int:
    result, unrecognized_statuses = _ingest(args.reports, args.assets)
    _warn_about_statuses(unrecognized_statuses)
    print(_render_json(result) if args.as_json else _render_ingest_text(result))
    return EXIT_OK


def _run_triage(
    args: argparse.Namespace, fetcher: Fetcher | None, now: Callable[[], datetime]
) -> int:
    # Input files are checked first, so that a bad file never causes a network request.
    assets = load_assets(args.assets)
    ingested, unrecognized_statuses = _ingest_with_assets(args.reports, assets)
    cve_ids = {f.vuln_id for f in ingested.findings if is_cve_id(f.vuln_id)}

    cache = Cache(args.cache_dir or default_cache_dir(), now)
    kev = KevData()
    epss = EpssData()
    if cve_ids:
        source = fetcher or UrllibFetcher()
        kev = load_kev(cache, source, offline=args.offline)
        epss = load_epss(cve_ids, cache, source, offline=args.offline)

    result = triage(ingested.findings, assets, ingested.unassigned_artifacts, kev, epss)
    _warn_about_statuses(unrecognized_statuses)
    for warning in cache.warnings:
        print(f"warning: {_sanitize(warning)}", file=sys.stderr)
    shown = limit_decisions(result, args.top) if args.top else result
    print(_render_json(shown) if args.as_json else _render_triage_text(shown))
    return EXIT_OK


def _ingest(report_paths: Sequence[Path], assets_path: Path) -> tuple[IngestResult, set[str]]:
    return _ingest_with_assets(report_paths, load_assets(assets_path))


def _ingest_with_assets(
    report_paths: Sequence[Path], assets: Sequence[Asset]
) -> tuple[IngestResult, set[str]]:
    """Return the result and the distinct unrecognized status values across all reports."""
    reports = [parse_report(path) for path in report_paths]
    findings, unassigned = assign_assets(reports, assets)
    result = IngestResult(findings=merge_findings(findings), unassigned_artifacts=unassigned)
    return result, {status for report in reports for status in report.unrecognized_fix_statuses}


def _warn_about_statuses(statuses: Iterable[str]) -> None:
    for status in sorted(statuses):
        print(
            f"warning: unrecognized fix status treated as unknown: {_shorten_and_sanitize(status)}",
            file=sys.stderr,
        )


def _render_json(result: BaseModel) -> str:
    # ASCII-only output cannot carry raw control characters and survives any console encoding.
    return json.dumps(result.model_dump(mode="json"), ensure_ascii=True, indent=2)


def _render_ingest_text(result: IngestResult) -> str:
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


def _render_triage_text(result: TriageResult) -> str:
    lines = [_render_decision(decision) for decision in result.decisions]
    if lines:
        lines.append("")
    lines.append("Priority summary:")
    lines += [
        f"  {priority.value:<{_PRIORITY_WIDTH}}{result.summary.by_priority[priority]}"
        for priority in sorted(Priority, key=lambda p: p.rank)
    ]
    shown = len(result.decisions)
    total = result.summary.total
    lines.append(f"Findings: {total}" + (f" (showing {shown})" if shown < total else ""))
    lines.append(f"Unassigned artifacts: {len(result.unassigned_artifacts)}")
    lines += [f"  {_sanitize(artifact)}" for artifact in result.unassigned_artifacts]
    return "\n".join(lines)


def _render_decision(decision: TriageDecision) -> str:
    finding = decision.finding
    assets = sorted(finding.asset_ids)
    if decision.has_unassigned_artifact:
        assets.append("unassigned")
    fields = [
        decision.priority.value,
        finding.vuln_id,
        finding.package,
        finding.installed_version or "unknown",
        f"fix:{','.join(finding.fixed_versions) or '-'}",
        f"assets:{','.join(assets)}",
        f"rule:{decision.rule_id.value}",
        *_notes(decision),
    ]
    return "  ".join(_sanitize(field) for field in fields)


def _notes(decision: TriageDecision) -> list[str]:
    notes: list[str] = []
    if decision.exposure_assumed:
        notes.append("[exposure assumed]")
    if decision.criticality_assumed:
        notes.append("[criticality assumed]")
    if decision.kev_state is KevState.NOT_APPLICABLE:
        notes.append("[no KEV/EPSS data]")
    elif decision.epss_state is EpssState.NOT_SCORED:
        notes.append("[no EPSS score]")
    return notes


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
