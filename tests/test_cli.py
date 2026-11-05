import json
from pathlib import Path
from typing import Any

import pytest

from fixfirst.cli import EXIT_INPUT_ERROR, EXIT_OK, main

FIXTURES = Path(__file__).parent / "fixtures" / "trivy"
ASSETS = Path(__file__).parent.parent / "examples" / "assets.yaml"


def fixture_args(*names: str, extra: tuple[str, ...] = ()) -> list[str]:
    reports = [str(FIXTURES / name) for name in names]
    return ["ingest", *reports, "--assets", str(ASSETS), *extra]


def run_json(capsys: pytest.CaptureFixture[str], *names: str) -> dict[str, Any]:
    assert main(fixture_args(*names, extra=("--json",))) == EXIT_OK
    result: dict[str, Any] = json.loads(capsys.readouterr().out)
    return result


def test_text_summary_for_one_report(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(fixture_args("normal.json")) == EXIT_OK

    assert capsys.readouterr().out.splitlines() == [
        "Findings by severity:",
        "  CRITICAL  1",
        "  HIGH      1",
        "  MEDIUM    0",
        "  LOW       1",
        "  UNKNOWN   0",
        "Unique findings:      3",
        "Assets affected:      1",
        "Unassigned artifacts: 0",
    ]


def test_text_summary_merges_duplicates_and_lists_unassigned(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(fixture_args("dup_image_a.json", "dup_image_b.json", "unmatched.json"))

    assert code == EXIT_OK
    assert capsys.readouterr().out.splitlines() == [
        "Findings by severity:",
        "  CRITICAL  1",
        "  HIGH      0",
        "  MEDIUM    1",
        "  LOW       0",
        "  UNKNOWN   0",
        "Unique findings:      2",
        "Assets affected:      2",
        "Unassigned artifacts: 1",
        "  registry.example.com/legacy/tool:0.9",
    ]


def test_text_summary_for_real_report(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(fixture_args("real_python_3_9_slim.json")) == EXIT_OK

    assert capsys.readouterr().out.splitlines() == [
        "Findings by severity:",
        "  CRITICAL  1",
        "  HIGH      4",
        "  MEDIUM    1",
        "  LOW       2",
        "  UNKNOWN   1",
        "Unique findings:      9",
        "Assets affected:      0",
        "Unassigned artifacts: 1",
        "  python:3.9-slim",
    ]


def test_real_report_merges_package_found_at_two_paths(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The fixture lists wheel twice: at the top level and vendored inside setuptools.
    result = run_json(capsys, "real_python_3_9_slim.json")

    matches = [f for f in result["findings"] if f["package"] == "wheel"]
    assert len(matches) == 1
    assert matches[0]["vuln_id"] == "CVE-2026-24049"
    assert matches[0]["installed_version"] == "0.45.1"
    assert matches[0]["fixed_versions"] == ["0.46.2"]
    assert matches[0]["ecosystem"] == "python-pkg"
    assert matches[0]["asset_ids"] == []
    assert matches[0]["fix_status"] == ["fixed"]
    # Both copies stay visible, because each has to be fixed.
    assert matches[0]["pkg_paths"] == [
        "usr/local/lib/python3.9/site-packages/setuptools/_vendor/wheel-0.45.1.dist-info/METADATA",
        "usr/local/lib/python3.9/site-packages/wheel-0.45.1.dist-info/METADATA",
    ]
    assert result["unassigned_artifacts"] == ["python:3.9-slim"]


def test_real_report_json_has_fix_status_for_every_finding(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = run_json(capsys, "real_python_3_9_slim.json")

    statuses = {f["vuln_id"]: f["fix_status"] for f in result["findings"]}
    assert statuses["CVE-2026-8376"] == ["fixed"]
    assert statuses["CVE-2026-9538"] == ["fix_deferred"]
    assert statuses["CVE-2026-15059"] == ["affected"]
    assert statuses["TEMP-0628843-DBAD28"] == ["affected"]


def test_conflicting_fix_statuses_are_sorted_in_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    paths = []
    for artifact, status in (("a:1", "fixed"), ("b:1", "affected")):
        vulnerability = {
            "VulnerabilityID": "CVE-2099-0001",
            "PkgName": "p",
            "InstalledVersion": "1",
            "Status": status,
        }
        results = [{"Vulnerabilities": [vulnerability]}]
        path = tmp_path / f"{artifact[0]}.json"
        path.write_text(
            json.dumps({"ArtifactName": artifact, "Results": results}), encoding="utf-8"
        )
        paths.append(str(path))

    assert main(["ingest", *paths, "--assets", str(ASSETS), "--json"]) == EXIT_OK

    assert json.loads(capsys.readouterr().out)["findings"][0]["fix_status"] == ["affected", "fixed"]


def write_report_with_statuses(tmp_path: Path, artifact: str, *statuses: str) -> str:
    vulnerabilities = [
        {"VulnerabilityID": f"CVE-2099-{index:04}", "PkgName": "p", "Status": status}
        for index, status in enumerate(statuses)
    ]
    path = tmp_path / f"{artifact[0]}.json"
    results = [{"Vulnerabilities": vulnerabilities}]
    path.write_text(json.dumps({"ArtifactName": artifact, "Results": results}), encoding="utf-8")
    return str(path)


def test_one_warning_per_distinct_unrecognized_status_across_reports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    first = write_report_with_statuses(tmp_path, "a:1", "zeta", "alpha", "zeta", "fixed")
    second = write_report_with_statuses(tmp_path, "b:1", "alpha")

    assert main(["ingest", first, second, "--assets", str(ASSETS), "--json"]) == EXIT_OK

    captured = capsys.readouterr()
    assert captured.err.splitlines() == [
        "warning: unrecognized fix status treated as unknown: alpha",
        "warning: unrecognized fix status treated as unknown: zeta",
    ]
    # Warnings stay out of stdout, and the findings are all still reported.
    findings = json.loads(captured.out)["findings"]
    assert [(f["vuln_id"], f["fix_status"]) for f in findings if f["artifacts"] == ["a:1"]] == [
        ("CVE-2099-0000", ["unknown"]),
        ("CVE-2099-0001", ["unknown"]),
        ("CVE-2099-0002", ["unknown"]),
        ("CVE-2099-0003", ["fixed"]),
    ]


def test_unrecognized_status_warns_in_text_mode_too(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report_with_statuses(tmp_path, "a:1", "resolved")

    assert main(["ingest", report, "--assets", str(ASSETS)]) == EXIT_OK

    captured = capsys.readouterr()
    assert "unrecognized fix status treated as unknown: resolved" in captured.err
    assert "Unique findings:      1" in captured.out
    assert "resolved" not in captured.out


def test_status_warning_escapes_and_shortens_the_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    long_value = "x" * 500
    report = write_report_with_statuses(tmp_path, "a:1", "evil\x1b[31m‮", long_value)

    assert main(["ingest", report, "--assets", str(ASSETS)]) == EXIT_OK

    lines = capsys.readouterr().err.splitlines()
    assert lines == [
        "warning: unrecognized fix status treated as unknown: evil\\x1b[31m\\u202e",
        f"warning: unrecognized fix status treated as unknown: {'x' * 80}...",
    ]


def test_recognized_statuses_print_no_warning(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(fixture_args("real_python_3_9_slim.json")) == EXIT_OK

    assert capsys.readouterr().err == ""


def test_no_warning_when_a_later_report_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report_with_statuses(tmp_path, "a:1", "resolved")
    bad = str(FIXTURES / "malformed.json")

    assert main(["ingest", report, bad, "--assets", str(ASSETS)]) == EXIT_INPUT_ERROR

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "warning" not in captured.err


def test_unrecognized_severity_still_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    vulnerability = {"VulnerabilityID": "CVE-2099-0001", "PkgName": "p", "Severity": "SEVERE"}
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"ArtifactName": "a:1", "Results": [{"Vulnerabilities": [vulnerability]}]}),
        encoding="utf-8",
    )

    assert main(["ingest", str(report), "--assets", str(ASSETS)]) == EXIT_INPUT_ERROR

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Severity" in captured.err


def test_json_output_has_normalized_findings(capsys: pytest.CaptureFixture[str]) -> None:
    result = run_json(capsys, "dup_image_a.json", "dup_image_b.json")

    assert result["unassigned_artifacts"] == []
    assert result["findings"][0] == {
        "vuln_id": "CVE-2099-0001",
        "package": "libexample1",
        "ecosystem": "debian",
        "installed_version": "1.2.3-1",
        "fixed_versions": ["1.2.3-2", "1.2.3-3"],
        "fix_status": ["unknown"],
        "scanner_severity": "CRITICAL",
        "cvss": None,
        "title": "libexample: title seen in image a",
        "primary_url": "https://vuln.example.com/CVE-2099-0001",
        "asset_ids": ["shop-api", "shop-worker"],
        "artifacts": [
            "registry.example.com/shop/api:1.5.0",
            "registry.example.com/shop/worker:2.0.0",
        ],
        "pkg_paths": [],
        "source": "trivy",
    }
    assert result["findings"][1]["vuln_id"] == "CVE-2099-0003"


def test_finding_in_matched_and_unmatched_artifact_stays_visible(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = run_json(capsys, "dup_image_a.json", "unmatched.json")

    assert result["unassigned_artifacts"] == ["registry.example.com/legacy/tool:0.9"]
    finding = result["findings"][0]
    assert finding["asset_ids"] == ["shop-api"]
    assert "registry.example.com/legacy/tool:0.9" in finding["artifacts"]


def test_finding_only_in_unmatched_artifact_is_kept(capsys: pytest.CaptureFixture[str]) -> None:
    result = run_json(capsys, "unmatched.json")

    assert result["findings"][0]["asset_ids"] == []
    assert result["unassigned_artifacts"] == ["registry.example.com/legacy/tool:0.9"]


def test_unmatched_artifact_without_findings_is_still_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = tmp_path / "clean.json"
    report.write_text('{"ArtifactName": "unlisted:1"}', encoding="utf-8")

    assert main(["ingest", str(report), "--assets", str(ASSETS), "--json"]) == EXIT_OK

    assert json.loads(capsys.readouterr().out) == {
        "findings": [],
        "unassigned_artifacts": ["unlisted:1"],
    }


def test_output_does_not_depend_on_report_order(capsys: pytest.CaptureFixture[str]) -> None:
    forward = run_json(capsys, "dup_image_a.json", "dup_image_b.json", "unmatched.json")
    backward = run_json(capsys, "unmatched.json", "dup_image_b.json", "dup_image_a.json")

    assert forward == backward


def test_critical_findings_do_not_change_the_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(fixture_args("normal.json")) == EXIT_OK
    assert "CRITICAL  1" in capsys.readouterr().out


def test_malformed_report_exits_2_without_partial_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(fixture_args("normal.json", "malformed.json")) == EXIT_INPUT_ERROR

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("error: ")
    assert "malformed.json" in captured.err


def test_missing_report_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["ingest", str(tmp_path / "absent.json"), "--assets", str(ASSETS)])

    assert code == EXIT_INPUT_ERROR
    assert "cannot read file" in capsys.readouterr().err


def test_invalid_inventory_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    inventory = tmp_path / "assets.yaml"
    inventory.write_text("assets: {}\n", encoding="utf-8")
    report = str(FIXTURES / "normal.json")

    assert main(["ingest", report, "--assets", str(inventory)]) == EXIT_INPUT_ERROR
    assert "invalid inventory" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        pytest.param([], id="no-command"),
        pytest.param(["ingest"], id="no-report"),
        pytest.param(["ingest", "report.json"], id="no-assets"),
    ],
)
def test_usage_errors_exit_2(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(argv)

    assert excinfo.value.code == EXIT_INPUT_ERROR
    assert "usage:" in capsys.readouterr().err


def test_terminal_control_characters_are_escaped_in_text_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # JSON escapes: ESC, a right-to-left override and a line separator.
    report = tmp_path / "evil.json"
    report.write_text(
        '{"ArtifactName": "evil\\u001b[31m\\u202e\\u2028\\nname:1"}', encoding="utf-8"
    )

    assert main(["ingest", str(report), "--assets", str(ASSETS)]) == EXIT_OK

    output = capsys.readouterr().out
    assert "\x1b" not in output
    assert "\N{RIGHT-TO-LEFT OVERRIDE}" not in output
    assert "\N{LINE SEPARATOR}" not in output
    assert output.splitlines()[-1] == "  evil\\x1b[31m\\u202e\\u2028\\nname:1"


def test_unknown_installed_version_is_null_in_json_and_counted_in_text(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = tmp_path / "no_version.json"
    vulnerability = {"VulnerabilityID": "CVE-2099-0001", "PkgName": "p", "Severity": "high"}
    report.write_text(
        json.dumps({"ArtifactName": "a:1", "Results": [{"Vulnerabilities": [vulnerability]}]}),
        encoding="utf-8",
    )
    args = ["ingest", str(report), "--assets", str(ASSETS)]

    assert main([*args, "--json"]) == EXIT_OK
    finding = json.loads(capsys.readouterr().out)["findings"][0]
    assert finding["installed_version"] is None
    assert finding["scanner_severity"] == "HIGH"

    assert main(args) == EXIT_OK
    output = capsys.readouterr().out
    assert "  HIGH      1" in output
    assert "Unique findings:      1" in output


def test_unknown_versions_merge_within_a_report_but_not_across_reports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    vulnerability = {"VulnerabilityID": "CVE-2099-0001", "PkgName": "p", "Severity": "HIGH"}
    result = {"Type": "pip", "Vulnerabilities": [vulnerability]}
    paths = []
    for artifact in ("a:1", "b:1"):
        path = tmp_path / f"{artifact[0]}.json"
        # The same package appears in two results of one artifact.
        path.write_text(
            json.dumps({"ArtifactName": artifact, "Results": [result, result]}), encoding="utf-8"
        )
        paths.append(str(path))

    assert main(["ingest", *paths, "--assets", str(ASSETS), "--json"]) == EXIT_OK

    findings = json.loads(capsys.readouterr().out)["findings"]
    assert [f["artifacts"] for f in findings] == [["a:1"], ["b:1"]]


def test_json_output_is_ascii_only(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report = tmp_path / "unicode.json"
    report.write_text('{"ArtifactName": "caf\\u00e9\\u001b[0m"}', encoding="utf-8")

    assert main(["ingest", str(report), "--assets", str(ASSETS), "--json"]) == EXIT_OK

    output = capsys.readouterr().out
    assert output.isascii()
    assert "\x1b" not in output
    assert json.loads(output)["unassigned_artifacts"] == ["café\x1b[0m"]


def test_error_output_escapes_control_characters(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["ingest", "evil\x1b[31m.json", "--assets", str(ASSETS)])

    assert code == EXIT_INPUT_ERROR
    assert "\x1b" not in capsys.readouterr().err
