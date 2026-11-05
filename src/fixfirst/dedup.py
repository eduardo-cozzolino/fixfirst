"""Merge findings that describe the same vulnerability in the same package version."""

from collections import defaultdict
from collections.abc import Iterable, Sequence

from fixfirst.models import CvssScore, DedupKey, Finding

_PREFERRED_CVSS_SOURCE = "nvd"


def merge_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Return one finding per dedup key, independent of the input order.

    Findings are sorted by severity, highest first, and then by dedup key. Within the same
    vulnerability and package, an unknown installed version sorts after known ones, and unknown
    versions are ordered by artifact.
    """
    groups: defaultdict[DedupKey, list[Finding]] = defaultdict(list)
    for finding in findings:
        groups[finding.dedup_key].append(finding)
    merged = [_merge_group(group) for group in groups.values()]
    return sorted(merged, key=finding_sort_key)


def finding_sort_key(finding: Finding) -> tuple[int, str, str, str, bool, str, tuple[str, ...]]:
    """Return a key that orders findings by severity, highest first, and then by identity."""
    # None cannot be compared with str, so the unknown version gets its own sort position. The
    # scope keeps the order of unknown versions independent of the input order.
    vuln_id, ecosystem, package, version, scope = finding.dedup_key
    return (
        -finding.scanner_severity.rank,
        vuln_id,
        ecosystem,
        package,
        version is None,
        version or "",
        scope,
    )


def _best_cvss(findings: Iterable[Finding]) -> CvssScore | None:
    """Prefer nvd and then the highest score. The other two keys only make the choice unique."""
    scores = [finding.cvss for finding in findings if finding.cvss is not None]
    return max(
        scores,
        key=lambda c: (c.source == _PREFERRED_CVSS_SOURCE, c.score, c.source, c.version.value),
        default=None,
    )


def _merge_group(group: Sequence[Finding]) -> Finding:
    # Sorting makes the choice of title and URL independent of the order of the input. Those two
    # fields are display-only, so which of the candidates wins has no effect on any decision.
    ordered = sorted(group, key=lambda f: (sorted(f.artifacts), f.title or "", f.primary_url or ""))
    first = ordered[0]
    return Finding(
        vuln_id=first.vuln_id,
        package=first.package,
        ecosystem=first.ecosystem,
        installed_version=first.installed_version,
        fixed_versions=[version for f in ordered for version in f.fixed_versions],
        fix_status=set().union(*(f.fix_status for f in ordered)),
        scanner_severity=max((f.scanner_severity for f in ordered), key=lambda s: s.rank),
        cvss=_best_cvss(ordered),
        title=next((f.title for f in ordered if f.title), None),
        primary_url=next((f.primary_url for f in ordered if f.primary_url), None),
        asset_ids=set().union(*(f.asset_ids for f in ordered)),
        artifacts=set().union(*(f.artifacts for f in ordered)),
        pkg_paths=set().union(*(f.pkg_paths for f in ordered)),
        source=first.source,
    )
