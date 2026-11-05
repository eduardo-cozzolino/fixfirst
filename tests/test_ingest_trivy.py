import json
from collections import Counter
from pathlib import Path

import pytest

from fixfirst.errors import InputError
from fixfirst.ingest.trivy import parse_report
from fixfirst.models import Finding, FixStatus, Severity

FIXTURES = Path(__file__).parent / "fixtures" / "trivy"
# Trimmed from a Trivy 0.76.1 scan of python:3.9-slim. The other fixtures are hand-written.
REAL_REPORT = FIXTURES / "real_python_3_9_slim.json"


def write_report(tmp_path: Path, vulnerability: dict[str, object]) -> Path:
    report = {
        "ArtifactName": "registry.example.com/shop/api:1.0",
        "Results": [{"Target": "t", "Type": "pip", "Vulnerabilities": [vulnerability]}],
    }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def valid_vulnerability(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "VulnerabilityID": "CVE-2099-0001",
        "PkgName": "examplelib",
        "InstalledVersion": "1.0.0",
        "Severity": "HIGH",
    }
    return base | overrides


def parse_single(tmp_path: Path, **overrides: object) -> Finding:
    path = write_report(tmp_path, valid_vulnerability(**overrides))
    findings = parse_report(path).findings
    assert len(findings) == 1
    return findings[0]


@pytest.mark.parametrize(
    ("vuln_id", "package", "ecosystem", "version", "fixed", "severity"),
    [
        pytest.param(
            "CVE-2026-8376",
            "perl-base",
            "debian",
            "5.40.1-6",
            ["5.40.1-6+deb13u1"],
            Severity.CRITICAL,
            id="critical",
        ),
        pytest.param(
            "CVE-2026-109518", "apt", "debian", "3.0.3", ["3.0.4"], Severity.HIGH, id="fixed"
        ),
        pytest.param(
            "CVE-2026-9538", "perl-base", "debian", "5.40.1-6", [], Severity.HIGH, id="fix-deferred"
        ),
        pytest.param(
            "CVE-2026-15059",
            "libudev1",
            "debian",
            "257.8-1~deb13u2",
            [],
            Severity.MEDIUM,
            id="affected",
        ),
        pytest.param(
            "TEMP-0628843-DBAD28",
            "passwd",
            "debian",
            "1:4.17.4-2",
            [],
            Severity.LOW,
            id="temp-id-with-epoch",
        ),
        pytest.param(
            "DSA-6549-1",
            "liblzma5",
            "debian",
            "5.8.1-1",
            ["5.8.1-1+deb13u2"],
            Severity.UNKNOWN,
            id="dsa-id",
        ),
        pytest.param(
            "CVE-2026-23949",
            "jaraco.context",
            "python-pkg",
            "5.3.0",
            ["6.1.0"],
            Severity.HIGH,
            id="python-pkg",
        ),
        pytest.param(
            "GHSA-xmj3-9gf7-h52w",
            "setuptools",
            "python-pkg",
            "79.0.1",
            ["84.1.0"],
            Severity.LOW,
            id="ghsa-id",
        ),
    ],
)
def test_real_report_values(
    vuln_id: str,
    package: str,
    ecosystem: str,
    version: str,
    fixed: list[str],
    severity: Severity,
) -> None:
    finding = next(f for f in parse_report(REAL_REPORT).findings if f.vuln_id == vuln_id)

    assert finding.package == package
    assert finding.ecosystem == ecosystem
    assert finding.installed_version == version
    assert finding.fixed_versions == fixed
    assert finding.scanner_severity is severity
    assert finding.artifacts == {"python:3.9-slim"}
    assert finding.source == "trivy"


def test_real_report_keeps_every_entry_before_dedup() -> None:
    report = parse_report(REAL_REPORT)

    assert report.artifact_name == "python:3.9-slim"
    assert Counter(f.ecosystem for f in report.findings) == {"debian": 6, "python-pkg": 4}


def test_real_report_urls() -> None:
    urls = {f.vuln_id: f.primary_url for f in parse_report(REAL_REPORT).findings}

    assert urls["CVE-2026-109518"] == "https://avd.aquasec.com/nvd/cve-2026-109518"
    assert urls["GHSA-xmj3-9gf7-h52w"] == "https://github.com/advisories/GHSA-xmj3-9gf7-h52w"
    assert urls["DSA-6549-1"] is None


def test_real_report_title_is_kept_as_trivy_truncated_it() -> None:
    finding = next(f for f in parse_report(REAL_REPORT).findings if f.package == "apt")

    assert finding.title is not None
    assert finding.title.endswith(" ...")


def test_real_fixture_has_no_run_specific_personal_or_advisory_text_fields() -> None:
    document = json.loads(REAL_REPORT.read_bytes())

    assert not {"ReportID", "CreatedAt"} & set(document)
    for result in document["Results"]:
        assert all("Maintainer" not in package for package in result["Packages"])
        for vulnerability in result["Vulnerabilities"]:
            assert not {"Description", "References"} & set(vulnerability)


@pytest.mark.parametrize(
    ("vuln_id", "expected"),
    [
        ("CVE-2026-8376", FixStatus.FIXED),
        ("CVE-2026-9538", FixStatus.FIX_DEFERRED),
        ("CVE-2026-15059", FixStatus.AFFECTED),
        ("GHSA-xmj3-9gf7-h52w", FixStatus.FIXED),
    ],
)
def test_real_report_fix_status(vuln_id: str, expected: FixStatus) -> None:
    finding = next(f for f in parse_report(REAL_REPORT).findings if f.vuln_id == vuln_id)

    assert finding.fix_status == {expected}


def test_real_report_pkg_paths() -> None:
    findings = parse_report(REAL_REPORT).findings

    debian = [f for f in findings if f.ecosystem == "debian"]
    assert all(f.pkg_paths == set() for f in debian)
    jaraco = next(f for f in findings if f.package == "jaraco.context")
    assert jaraco.pkg_paths == {
        "usr/local/lib/python3.9/site-packages/setuptools/_vendor/"
        "jaraco.context-5.3.0.dist-info/METADATA"
    }


@pytest.mark.parametrize("status", list(FixStatus))
def test_every_fix_status_is_accepted(tmp_path: Path, status: FixStatus) -> None:
    assert parse_single(tmp_path, Status=status.value).fix_status == {status}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("FIXED", FixStatus.FIXED),
        ("Fix_Deferred", FixStatus.FIX_DEFERRED),
        ("WILL_NOT_FIX", FixStatus.WILL_NOT_FIX),
    ],
)
def test_fix_status_is_case_insensitive(tmp_path: Path, raw: str, expected: FixStatus) -> None:
    assert parse_single(tmp_path, Status=raw).fix_status == {expected}


def test_not_affected_is_a_fix_status(tmp_path: Path) -> None:
    assert parse_single(tmp_path, Status="not_affected").fix_status == {FixStatus.NOT_AFFECTED}


@pytest.mark.parametrize("status", [None, ""])
def test_absent_fix_status_is_unknown(tmp_path: Path, status: str | None) -> None:
    assert parse_single(tmp_path, Status=status).fix_status == {FixStatus.UNKNOWN}


@pytest.mark.parametrize(
    "status",
    [
        pytest.param("resolved", id="unrecognized"),
        pytest.param("FUTURE_STATUS", id="uppercase"),
        pytest.param(" fixed", id="whitespace"),
        pytest.param("un\N{KELVIN SIGN}nown", id="non-ascii"),
    ],
)
def test_unrecognized_fix_status_keeps_the_finding_and_is_recorded(
    tmp_path: Path, status: str
) -> None:
    report = parse_report(write_report(tmp_path, valid_vulnerability(Status=status)))

    assert [f.fix_status for f in report.findings] == [{FixStatus.UNKNOWN}]
    assert report.findings[0].vuln_id == "CVE-2099-0001"
    assert report.unrecognized_fix_statuses == {status}


@pytest.mark.parametrize("status", ["fixed", "FIXED", "unknown", "not_affected", "", None])
def test_recognized_or_absent_fix_status_is_not_recorded(
    tmp_path: Path, status: str | None
) -> None:
    report = parse_report(write_report(tmp_path, valid_vulnerability(Status=status)))

    assert report.unrecognized_fix_statuses == set()


def test_real_report_has_no_unrecognized_fix_status() -> None:
    assert parse_report(REAL_REPORT).unrecognized_fix_statuses == set()


def test_omitted_fix_status_and_pkg_path_get_their_defaults(tmp_path: Path) -> None:
    finding = parse_single(tmp_path)

    assert finding.fix_status == {FixStatus.UNKNOWN}
    assert finding.pkg_paths == set()


@pytest.mark.parametrize("path", [None, ""])
def test_null_or_empty_pkg_path_gives_no_paths(tmp_path: Path, path: str | None) -> None:
    assert parse_single(tmp_path, PkgPath=path).pkg_paths == set()


def test_normal_report_is_normalized() -> None:
    report = parse_report(FIXTURES / "normal.json")

    assert report.artifact_name == "registry.example.com/shop/api:1.4.2"
    assert [f.vuln_id for f in report.findings] == [
        "CVE-2099-0001",
        "CVE-2099-0002",
        "GHSA-0000-0000-0001",
    ]
    first = report.findings[0]
    assert first.package == "libexample1"
    assert first.ecosystem == "debian"
    assert first.installed_version == "1.2.3-1"
    assert first.fixed_versions == ["1.2.3-2"]
    assert first.scanner_severity is Severity.CRITICAL
    assert first.title == "libexample: buffer overflow in parser"
    assert first.primary_url == "https://vuln.example.com/CVE-2099-0001"
    assert first.artifacts == {"registry.example.com/shop/api:1.4.2"}
    assert first.asset_ids == set()
    assert first.source == "trivy"
    assert report.findings[2].ecosystem == "pip"


def test_missing_optional_fields_become_none_or_empty() -> None:
    second = parse_report(FIXTURES / "normal.json").findings[1]

    assert second.fixed_versions == []
    assert second.title is None
    assert second.primary_url is None


def test_null_and_missing_vulnerabilities_give_no_findings() -> None:
    report = parse_report(FIXTURES / "null_vulnerabilities.json")

    assert report.artifact_name == "registry.example.com/shop/api:1.4.3"
    assert report.findings == []


def test_missing_results_gives_no_findings() -> None:
    report = parse_report(FIXTURES / "no_results.json")

    assert report.artifact_name == "registry.example.com/shop/worker:2.1.0"
    assert report.findings == []


def test_null_results_gives_no_findings(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text('{"ArtifactName": "a", "Results": null}', encoding="utf-8")

    assert parse_report(path).findings == []


def test_multiple_fixed_versions_are_split_and_deduplicated() -> None:
    finding = parse_report(FIXTURES / "multiple_fixed.json").findings[0]

    assert finding.fixed_versions == ["1.9.5", "2.0.1"]


def test_malformed_json_is_an_input_error() -> None:
    with pytest.raises(InputError, match="invalid JSON at line"):
        parse_report(FIXTURES / "malformed.json")


@pytest.mark.parametrize(
    "content",
    [
        pytest.param("[]", id="legacy-array-format"),
        pytest.param("null", id="null-document"),
        pytest.param('{"Results": []}', id="missing-artifact-name"),
        pytest.param('{"ArtifactName": ""}', id="empty-artifact-name"),
        pytest.param('{"ArtifactName": 42}', id="artifact-name-not-a-string"),
        pytest.param('{"ArtifactName": "a", "Results": {}}', id="results-not-a-list"),
    ],
)
def test_wrong_report_schema_is_an_input_error(tmp_path: Path, content: str) -> None:
    path = tmp_path / "report.json"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(InputError, match="invalid Trivy report"):
        parse_report(path)


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"VulnerabilityID": None}, id="null-id"),
        pytest.param({"PkgName": ""}, id="empty-package"),
        pytest.param({"Title": 42}, id="title-not-a-string"),
        pytest.param({"FixedVersion": ["1.0"]}, id="fixed-version-not-a-string"),
        pytest.param({"Severity": "SEVERE"}, id="unrecognized-severity"),
        pytest.param({"Severity": " HIGH"}, id="severity-with-whitespace"),
        pytest.param({"Severity": "h\N{LATIN SMALL LETTER DOTLESS I}gh"}, id="non-ascii-severity"),
        pytest.param({"Severity": 4}, id="severity-not-a-string"),
        pytest.param({"InstalledVersion": 1}, id="installed-version-not-a-string"),
        pytest.param({"Status": 3}, id="status-not-a-string"),
        pytest.param({"PkgPath": ["a"]}, id="pkg-path-not-a-string"),
    ],
)
def test_one_bad_vulnerability_rejects_the_report(
    tmp_path: Path, overrides: dict[str, object]
) -> None:
    path = write_report(tmp_path, valid_vulnerability(**overrides))

    with pytest.raises(InputError, match="invalid Trivy report"):
        parse_report(path)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("high", Severity.HIGH),
        ("High", Severity.HIGH),
        ("HIGH", Severity.HIGH),
        ("critical", Severity.CRITICAL),
        ("medium", Severity.MEDIUM),
        ("low", Severity.LOW),
        ("unknown", Severity.UNKNOWN),
    ],
)
def test_severity_is_case_insensitive(tmp_path: Path, raw: str, expected: Severity) -> None:
    assert parse_single(tmp_path, Severity=raw).scanner_severity is expected


@pytest.mark.parametrize("version", [None, ""])
def test_null_or_empty_installed_version_is_none(tmp_path: Path, version: str | None) -> None:
    assert parse_single(tmp_path, InstalledVersion=version).installed_version is None


def test_omitted_installed_version_is_none(tmp_path: Path) -> None:
    vulnerability = valid_vulnerability()
    del vulnerability["InstalledVersion"]
    path = write_report(tmp_path, vulnerability)

    assert parse_report(path).findings[0].installed_version is None


@pytest.mark.parametrize("severity", [None, ""])
def test_absent_severity_is_unknown(tmp_path: Path, severity: str | None) -> None:
    assert parse_single(tmp_path, Severity=severity).scanner_severity is Severity.UNKNOWN


def test_omitted_severity_is_unknown(tmp_path: Path) -> None:
    vulnerability = valid_vulnerability()
    del vulnerability["Severity"]
    path = write_report(tmp_path, vulnerability)

    assert parse_report(path).findings[0].scanner_severity is Severity.UNKNOWN


def test_missing_result_type_is_unknown_ecosystem(tmp_path: Path) -> None:
    report = {"ArtifactName": "a", "Results": [{"Vulnerabilities": [valid_vulnerability()]}]}
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    assert parse_report(path).findings[0].ecosystem == "unknown"


def test_error_messages_do_not_echo_report_values(tmp_path: Path) -> None:
    path = write_report(tmp_path, valid_vulnerability(Severity="SENTINEL", PkgName=["SENTINEL"]))

    with pytest.raises(InputError) as excinfo:
        parse_report(path)

    assert "SENTINEL" not in str(excinfo.value)
    assert "Severity" in str(excinfo.value)
    assert "PkgName" in str(excinfo.value)


def test_report_larger_than_limit_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    content = '{"ArtifactName": "a"}'
    path.write_text(content, encoding="utf-8")

    assert parse_report(path, max_bytes=len(content)).artifact_name == "a"
    with pytest.raises(InputError, match="byte limit"):
        parse_report(path, max_bytes=len(content) - 1)


def test_deeply_nested_json_is_an_input_error(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text("[" * 200_000, encoding="utf-8")

    with pytest.raises(InputError, match="invalid JSON"):
        parse_report(path)


@pytest.mark.parametrize(
    "content",
    [
        pytest.param('{"ArtifactName": NaN}', id="nan"),
        pytest.param('{"ArtifactName": -Infinity}', id="infinity"),
        pytest.param('{"ArtifactName": ' + "9" * 10_000 + "}", id="oversized-integer"),
    ],
)
def test_values_rejected_by_the_json_parser(tmp_path: Path, content: str) -> None:
    path = tmp_path / "report.json"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(InputError, match="invalid JSON"):
        parse_report(path)


def test_invalid_utf8_is_an_input_error(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_bytes(b'{"ArtifactName": "\xff\xfe"}')

    with pytest.raises(InputError, match="invalid JSON"):
        parse_report(path)


def test_lone_surrogate_is_an_input_error(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text('{"ArtifactName": "\\ud800"}', encoding="utf-8")

    with pytest.raises(InputError):
        parse_report(path)


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-16-le", "utf-32"])
def test_common_encodings_are_detected(tmp_path: Path, encoding: str) -> None:
    path = tmp_path / "report.json"
    path.write_text('{"ArtifactName": "café"}', encoding=encoding)

    assert parse_report(path).artifact_name == "café"


def test_missing_file_is_an_input_error(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="cannot read file"):
        parse_report(tmp_path / "absent.json")


def test_directory_is_an_input_error(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="cannot read file"):
        parse_report(tmp_path)


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "data:text/html,x",
        "file:///etc/passwd",
        "https://",
        "not a url",
        "http://[bad",
        "",
    ],
)
def test_unsafe_or_invalid_urls_are_dropped(tmp_path: Path, url: str) -> None:
    assert parse_single(tmp_path, PrimaryURL=url).primary_url is None


@pytest.mark.parametrize("url", ["https://example.com/a", "HTTP://example.com/a"])
def test_http_urls_are_kept(tmp_path: Path, url: str) -> None:
    assert parse_single(tmp_path, PrimaryURL=url).primary_url == url


def test_unknown_fields_are_ignored(tmp_path: Path) -> None:
    assert parse_single(tmp_path, FutureTrivyField={"x": 1}).vuln_id == "CVE-2099-0001"
