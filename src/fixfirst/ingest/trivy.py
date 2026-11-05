"""Parse Trivy JSON reports.

Reports are untrusted input. Their size is limited, their content is only ever treated as data, and
error messages never repeat their values. Parsing is all or nothing: skipping a malformed entry
could silently hide a real vulnerability.

The one exception is an unrecognized Status string. The entry is kept with an unknown fix status and
the value is recorded for a warning, so a new Trivy status does not block a whole run.
"""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, NoReturn
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from fixfirst._input import describe_validation_error, read_limited
from fixfirst.errors import InputError
from fixfirst.models import (
    CvssScore,
    CvssVersion,
    Finding,
    FixStatus,
    NonEmptyStr,
    ParsedReport,
    Severity,
)

MAX_REPORT_BYTES = 100 * 1024 * 1024
SOURCE = "trivy"

_UNKNOWN_ECOSYSTEM = "unknown"
_ALLOWED_URL_SCHEMES = frozenset({"http", "https"})
_PREFERRED_CVSS_SOURCE = "nvd"

# Trivy writes whole scores as integers, such as 7 rather than 7.0.
_CvssNumber = Annotated[int, Field(ge=0, le=10)] | Annotated[float, Field(ge=0, le=10)]


class _TrivyCvssEntry(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)

    v3_score: _CvssNumber | None = Field(default=None, alias="V3Score")
    v40_score: _CvssNumber | None = Field(default=None, alias="V40Score")
    v2_score: _CvssNumber | None = Field(default=None, alias="V2Score")

    def score_for(self, version: CvssVersion) -> float | None:
        """Return the score of the given CVSS version, if there is one."""
        score = {
            CvssVersion.V3: self.v3_score,
            CvssVersion.V40: self.v40_score,
            CvssVersion.V2: self.v2_score,
        }[version]
        return None if score is None else float(score)


class _TrivyVulnerability(BaseModel):
    # Unknown fields are ignored so that new Trivy releases do not break parsing.
    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)

    vulnerability_id: NonEmptyStr = Field(alias="VulnerabilityID")
    pkg_name: NonEmptyStr = Field(alias="PkgName")
    # Absent, null and empty all mean the version is unknown.
    installed_version: str | None = Field(default=None, alias="InstalledVersion")
    pkg_path: str | None = Field(default=None, alias="PkgPath")
    fixed_version: str | None = Field(default=None, alias="FixedVersion")
    status: str | None = Field(default=None, alias="Status")
    severity: Severity = Field(default=Severity.UNKNOWN, alias="Severity")
    severity_source: str | None = Field(default=None, alias="SeveritySource")
    cvss: dict[NonEmptyStr, _TrivyCvssEntry] | None = Field(default=None, alias="CVSS")
    title: str | None = Field(default=None, alias="Title")
    primary_url: str | None = Field(default=None, alias="PrimaryURL")

    @field_validator("severity", mode="before")
    @classmethod
    def _parse_severity(cls, value: object) -> Severity:
        if value is None or value == "":
            return Severity.UNKNOWN
        # ASCII only: str.upper() maps some non-ASCII letters to ASCII ones, such as the Turkish
        # dotless i to I, which would turn text that is not a severity into a valid one.
        if isinstance(value, str) and value.isascii():
            try:
                return Severity(value.upper())
            except ValueError:
                pass
        raise ValueError("unrecognized severity")


class _TrivyResult(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)

    # Target is validated but not stored. It names what was scanned, such as "Python" for all
    # language packages in an image, while PkgPath gives the location of each package.
    target: str = Field(default="", alias="Target")
    type: str = Field(default="", alias="Type")
    vulnerabilities: list[_TrivyVulnerability] | None = Field(default=None, alias="Vulnerabilities")


class _TrivyReport(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)

    artifact_name: NonEmptyStr = Field(alias="ArtifactName")
    # Trivy omits Results when a scan finds nothing.
    results: list[_TrivyResult] | None = Field(default=None, alias="Results")


def parse_report(path: Path, max_bytes: int = MAX_REPORT_BYTES) -> ParsedReport:
    """Read a Trivy JSON report and normalize it.

    The returned findings have no asset ids yet.

    Raises:
        InputError: The file cannot be read, is too large, or is not a valid Trivy report.
    """
    raw = read_limited(path, max_bytes)
    try:
        # Decoding bytes rather than text lets json detect UTF-8 BOMs and UTF-16, which is what
        # redirecting output to a file produces in Windows PowerShell 5.1.
        data: object = json.loads(raw, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: invalid JSON at line {exc.lineno}, column {exc.colno}") from exc
    except ValueError as exc:
        raise InputError(f"{path}: invalid JSON") from exc
    except RecursionError as exc:
        raise InputError(f"{path}: invalid JSON (nested too deeply)") from exc

    try:
        report = _TrivyReport.model_validate(data)
    except ValidationError as exc:
        raise InputError(f"{path}: invalid Trivy report: {describe_validation_error(exc)}") from exc

    entries = [
        (result.type, vulnerability)
        for result in report.results or []
        for vulnerability in result.vulnerabilities or []
    ]
    return ParsedReport(
        artifact_name=report.artifact_name,
        findings=[
            _to_finding(vulnerability, result_type, report.artifact_name)
            for result_type, vulnerability in entries
        ],
        unrecognized_fix_statuses={
            vulnerability.status
            for _, vulnerability in entries
            if vulnerability.status and _parse_fix_status(vulnerability.status) is None
        },
    )


def _reject_constant(constant: str) -> NoReturn:
    # NaN and Infinity are accepted by Python's parser but are not valid JSON.
    raise ValueError(f"invalid JSON constant: {constant}")


def _parse_fix_status(value: str | None) -> FixStatus | None:
    """Return the fix status for a raw value, or None if the value is not recognized."""
    if not value:
        return FixStatus.UNKNOWN
    # ASCII only, for the same reason as severity: str.lower() maps the Kelvin sign to k.
    if not value.isascii():
        return None
    try:
        return FixStatus(value.lower())
    except ValueError:
        return None


def _to_finding(vulnerability: _TrivyVulnerability, result_type: str, artifact: str) -> Finding:
    return Finding(
        vuln_id=vulnerability.vulnerability_id,
        package=vulnerability.pkg_name,
        ecosystem=result_type or _UNKNOWN_ECOSYSTEM,
        installed_version=vulnerability.installed_version or None,
        fixed_versions=_split_fixed_versions(vulnerability.fixed_version),
        fix_status={_parse_fix_status(vulnerability.status) or FixStatus.UNKNOWN},
        scanner_severity=vulnerability.severity,
        cvss=_select_cvss(vulnerability.cvss or {}, vulnerability.severity_source),
        title=vulnerability.title or None,
        primary_url=_safe_url(vulnerability.primary_url),
        artifacts={artifact},
        pkg_paths={vulnerability.pkg_path} if vulnerability.pkg_path else set(),
        source=SOURCE,
    )


def _select_cvss(
    entries: Mapping[str, _TrivyCvssEntry], severity_source: str | None
) -> CvssScore | None:
    """Pick one score: V3 before V4.0 before V2, and nvd before the vendor Trivy took severity from.

    Remaining vendors follow alphabetically, so the choice does not depend on report order.
    """
    preferred = [_PREFERRED_CVSS_SOURCE, *([severity_source] if severity_source else [])]
    sources = [source for source in dict.fromkeys(preferred) if source in entries]
    sources += sorted(source for source in entries if source not in sources)
    for version in (CvssVersion.V3, CvssVersion.V40, CvssVersion.V2):
        for source in sources:
            score = entries[source].score_for(version)
            if score is not None:
                return CvssScore(score=score, version=version, source=source)
    return None


def _split_fixed_versions(value: str | None) -> list[str]:
    if value is None:
        return []
    return [version for part in value.split(",") if (version := part.strip())]


def _safe_url(value: str | None) -> str | None:
    """Keep only http(s) URLs, so that a report cannot plant e.g. a javascript: link."""
    if not value:
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if parts.scheme.lower() not in _ALLOWED_URL_SCHEMES or not parts.netloc:
        return None
    return value
