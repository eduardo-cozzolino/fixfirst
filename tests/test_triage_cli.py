import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from fixfirst.cli import EXIT_ENRICHMENT_UNAVAILABLE, EXIT_INPUT_ERROR, EXIT_OK, main
from fixfirst.enrich.cache import MAX_AGE
from fixfirst.enrich.epss import EPSS_URL
from fixfirst.enrich.fetcher import Fetcher
from fixfirst.enrich.kev import KEV_URL
from fixfirst.errors import EnrichmentError

FIXTURES = Path(__file__).parent / "fixtures"
REAL_REPORT = FIXTURES / "trivy" / "real_python_3_9_slim.json"
KEV_FEED = (FIXTURES / "enrich" / "kev.json").read_bytes()
ASSETS = Path(__file__).parent.parent / "examples" / "assets.yaml"
NOW = datetime(2099, 1, 15, 12, tzinfo=UTC)
EXPOSED_IMAGE = "registry.example.com/shop/api:1.0"
INTERNAL_IMAGE = "registry.example.com/shop/worker:1.0"
UNKNOWN_EXPOSURE_IMAGE = "registry.example.com/docs/site:1.0"
UNLISTED_IMAGE = "registry.example.com/legacy/tool:1.0"
KEV_LISTED = "CVE-2099-1001"


class FakeServices:
    """Stands in for both data sources, and records what would have gone over the network."""

    def __init__(self, scores: dict[str, str] | None = None) -> None:
        self.scores = scores or {}
        self.urls: list[str] = []

    def fetch(self, url: str, max_bytes: int) -> bytes:
        self.urls.append(url)
        if url == KEV_URL:
            return KEV_FEED
        assert url.startswith(f"{EPSS_URL}?")
        ids = parse_qs(urlsplit(url).query)["cve"][0].split(",")
        rows = [
            {"cve": i, "epss": self.scores[i], "percentile": "0.5", "date": "2099-01-15"}
            for i in ids
            if i in self.scores
        ]
        return json.dumps({"status-code": 200, "total": len(rows), "data": rows}).encode("utf-8")


class Unreachable:
    def fetch(self, url: str, max_bytes: int) -> bytes:
        raise EnrichmentError("network is down")


def vuln(
    vuln_id: str, severity: str = "HIGH", package: str = "p", **extra: object
) -> dict[str, Any]:
    return {
        "VulnerabilityID": vuln_id,
        "PkgName": package,
        "InstalledVersion": "1.0",
        "Severity": severity,
    } | extra


def write_report(tmp_path: Path, artifact: str, *vulns: dict[str, Any]) -> str:
    path = tmp_path / f"report-{len(list(tmp_path.glob('report-*')))}.json"
    results = [{"Type": "debian", "Vulnerabilities": list(vulns)}]
    path.write_text(json.dumps({"ArtifactName": artifact, "Results": results}), encoding="utf-8")
    return str(path)


def run(
    tmp_path: Path,
    reports: list[str],
    *flags: str,
    fetcher: Fetcher | None = None,
    now: datetime = NOW,
) -> int:
    argv = ["triage", *reports, "--assets", str(ASSETS), "--cache-dir", str(tmp_path / "cache")]
    return main([*argv, *flags], fetcher=fetcher or FakeServices(), now=lambda: now)


def run_json(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    reports: list[str],
    *flags: str,
    fetcher: Fetcher | None = None,
) -> dict[str, Any]:
    assert run(tmp_path, reports, "--json", *flags, fetcher=fetcher) == EXIT_OK
    result: dict[str, Any] = json.loads(capsys.readouterr().out)
    return result


# Text output


def test_text_output_has_one_line_per_finding_and_a_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(
        tmp_path,
        EXPOSED_IMAGE,
        vuln(KEV_LISTED, package="openssl", FixedVersion="1.1, 1.2"),
        vuln("CVE-2099-3001", "MEDIUM", package="curl"),
    )

    assert run(tmp_path, [report]) == EXIT_OK

    assert capsys.readouterr().out.splitlines() == [
        "P1  CVE-2099-1001  openssl  1.0  fix:1.1,1.2  assets:shop-api  rule:kev-exposed  "
        "[no EPSS score]",
        "P4  CVE-2099-3001  curl  1.0  fix:-  assets:shop-api  rule:default  [no EPSS score]",
        "",
        "Priority summary:",
        "  P1  1",
        "  P2  0",
        "  P3  0",
        "  P4  1",
        "Findings: 2",
        "Unassigned artifacts: 0",
    ]


def test_unassigned_artifact_says_exposure_and_criticality_assumed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(
        tmp_path,
        UNLISTED_IMAGE,
        vuln(KEV_LISTED, "LOW"),
        vuln("CVE-2099-3001", "CRITICAL"),
    )

    assert run(tmp_path, [report]) == EXIT_OK

    assert capsys.readouterr().out.splitlines() == [
        "P1  CVE-2099-1001  p  1.0  fix:-  assets:unassigned  rule:kev-exposed  "
        "[exposure assumed]  [no EPSS score]",
        "P2  CVE-2099-3001  p  1.0  fix:-  assets:unassigned  rule:critical-on-critical-asset  "
        "[criticality assumed]  [no EPSS score]",
        "",
        "Priority summary:",
        "  P1  1",
        "  P2  1",
        "  P3  0",
        "  P4  0",
        "Findings: 2",
        "Unassigned artifacts: 1",
        f"  {UNLISTED_IMAGE}",
    ]


def test_unknown_declared_exposure_says_exposure_assumed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, UNKNOWN_EXPOSURE_IMAGE, vuln(KEV_LISTED))

    assert run(tmp_path, [report]) == EXIT_OK

    output = capsys.readouterr().out
    assert "assets:docs-site  rule:kev-exposed  [exposure assumed]" in output


def test_declared_exposure_is_not_marked_assumed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED))

    assert run(tmp_path, [report]) == EXIT_OK

    assert "assumed" not in capsys.readouterr().out


def test_assumption_is_not_shown_when_the_rule_did_not_rely_on_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, UNLISTED_IMAGE, vuln("CVE-2099-3001", "HIGH"))

    assert run(tmp_path, [report]) == EXIT_OK

    output = capsys.readouterr().out
    assert "rule:severe" in output
    assert "assumed" not in output


def test_non_cve_ids_are_marked_and_never_sent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(
        tmp_path,
        EXPOSED_IMAGE,
        vuln("TEMP-0628843-DBAD28", "CRITICAL"),
        vuln("DSA-6549-1", "UNKNOWN", FixedVersion="2.0"),
        vuln("GHSA-xmj3-9gf7-h52w", "LOW"),
        vuln("CVE-2099-3001", "LOW"),
    )
    services = FakeServices()

    assert run(tmp_path, [report], fetcher=services) == EXIT_OK

    lines = capsys.readouterr().out.splitlines()[:4]
    for line in lines:
        assert ("[no KEV/EPSS data]" in line) is ("CVE-2099-3001" not in line)
    assert services.urls == [KEV_URL, f"{EPSS_URL}?cve=CVE-2099-3001"]


def test_crafted_id_cannot_reach_a_request(tmp_path: Path) -> None:
    report = write_report(
        tmp_path,
        EXPOSED_IMAGE,
        vuln("CVE-2099-3001&limit=1"),
        vuln("CVE-2099-3002/../../x"),
        vuln("CVE-2099-3003", "LOW"),
    )
    services = FakeServices()

    assert run(tmp_path, [report], fetcher=services) == EXIT_OK

    assert services.urls[1] == f"{EPSS_URL}?cve=CVE-2099-3003"


def test_report_values_are_escaped_in_text_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(
        tmp_path,
        EXPOSED_IMAGE,
        vuln("TEMP-\x1b[31m", package="p‮kg", FixedVersion="1\x1b[0m"),
    )

    assert run(tmp_path, [report]) == EXIT_OK

    output = capsys.readouterr().out
    assert "\x1b" not in output
    assert "‮" not in output
    assert "TEMP-\\x1b[31m" in output


def test_unknown_installed_version_is_shown_as_unknown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    item = vuln("CVE-2099-3001")
    del item["InstalledVersion"]
    report = write_report(tmp_path, EXPOSED_IMAGE, item)

    assert run(tmp_path, [report]) == EXIT_OK

    assert "CVE-2099-3001  p  unknown  fix:-" in capsys.readouterr().out


def test_finding_in_assigned_and_unassigned_artifacts_lists_both(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    item = vuln("CVE-2099-3001")
    first = write_report(tmp_path, INTERNAL_IMAGE, item)
    second = write_report(tmp_path, UNLISTED_IMAGE, item)

    assert run(tmp_path, [first, second]) == EXIT_OK

    assert "assets:shop-worker,unassigned" in capsys.readouterr().out


def test_no_findings_needs_no_data_at_all(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE)
    services = FakeServices()

    assert run(tmp_path, [report], "--offline", fetcher=services) == EXIT_OK

    assert services.urls == []
    assert capsys.readouterr().out.splitlines()[0] == "Priority summary:"


def test_only_non_cve_ids_need_no_data_at_all(tmp_path: Path) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln("TEMP-0628843-DBAD28"))
    services = FakeServices()

    assert run(tmp_path, [report], "--offline", fetcher=services) == EXIT_OK

    assert services.urls == []


# Ordering and --top


def test_order_is_priority_then_severity_then_epss_then_identity(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(
        tmp_path,
        INTERNAL_IMAGE,
        vuln("CVE-2099-3001", "HIGH"),
        vuln("CVE-2099-3002", "HIGH"),
        vuln("CVE-2099-3003", "HIGH"),
        vuln("CVE-2099-3004", "HIGH"),
        vuln("CVE-2099-3005", "LOW"),
        vuln(KEV_LISTED, "LOW"),
        vuln("CVE-2099-3006", "CRITICAL"),
    )
    services = FakeServices(
        {"CVE-2099-3002": "0.09", "CVE-2099-3003": "0.01", "CVE-2099-3004": "0.5"}
    )

    result = run_json(tmp_path, capsys, [report], fetcher=services)

    assert [d["finding"]["vuln_id"] for d in result["decisions"]] == [
        "CVE-2099-3006",  # P2, critical on an important asset
        "CVE-2099-3004",  # P2, high with a score
        "CVE-2099-1001",  # P2, low but in KEV
        "CVE-2099-3002",  # P3, high, highest score
        "CVE-2099-3003",  # P3, high, lower score
        "CVE-2099-3001",  # P3, high, no score
        "CVE-2099-3005",  # P4
    ]


def test_top_limits_the_listing_but_not_the_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED), vuln("CVE-2099-3001", "LOW"))

    assert run(tmp_path, [report], "--top", "1") == EXIT_OK

    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("P1  CVE-2099-1001")
    assert "CVE-2099-3001" not in "\n".join(lines)
    assert "  P4  1" in lines
    assert "Findings: 2 (showing 1)" in lines


def test_top_in_json_keeps_only_the_evidence_of_listed_decisions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED), vuln("CVE-2099-3001", "LOW"))

    result = run_json(tmp_path, capsys, [report], "--top", "1")

    assert len(result["decisions"]) == 1
    assert result["summary"]["total"] == 2
    evidence_ids = {item["id"] for item in result["evidence"]}
    assert evidence_ids == set(result["decisions"][0]["evidence_ids"])
    assert not any("CVE-2099-3001" in item for item in evidence_ids)


def test_top_above_the_number_of_findings_shows_all(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED))

    assert run(tmp_path, [report], "--top", "5") == EXIT_OK

    assert "Findings: 1\n" in capsys.readouterr().out


@pytest.mark.parametrize("value", ["0", "-1", "two", "1.5"])
def test_invalid_top_is_a_usage_error(tmp_path: Path, value: str) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE)

    with pytest.raises(SystemExit) as excinfo:
        run(tmp_path, [report], "--top", value)
    assert excinfo.value.code == EXIT_INPUT_ERROR


# JSON and evidence


def test_json_lists_rule_exposure_and_evidence(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, UNKNOWN_EXPOSURE_IMAGE, vuln(KEV_LISTED))

    result = run_json(tmp_path, capsys, [report])

    decision = result["decisions"][0]
    assert decision["priority"] == "P1"
    assert decision["rule_id"] == "kev-exposed"
    assert decision["exposure"] == "assumed"
    assert decision["exposure_assumed"] is True
    assert decision["criticality_assumed"] is False
    assert decision["kev_state"] == "listed"
    assert decision["epss_state"] == "not_scored"
    assert decision["epss_score"] is None
    assert decision["finding"]["vuln_id"] == KEV_LISTED
    assert result["summary"] == {
        "by_priority": {"P1": 1, "P2": 0, "P3": 0, "P4": 0},
        "total": 1,
    }

    evidence = {item["id"]: item for item in result["evidence"]}
    assert set(decision["evidence_ids"]) == set(evidence)
    kev = evidence[f"kev:{KEV_LISTED}"]
    assert kev["source"] == "cisa_kev"
    assert kev["retrieved_at"] == "2099-01-15T12:00:00Z"
    assert kev["data"]["state"] == "listed"
    assert kev["data"]["catalog_version"] == "2099.01.15"
    assert kev["data"]["date_added"] == "2099-01-15"
    assert evidence[f"epss:{KEV_LISTED}"]["data"]["state"] == "not_scored"
    asset = evidence["asset:docs-site"]
    assert asset["source"] == "asset_inventory"
    assert asset["retrieved_at"] is None
    assert asset["data"] == {"internet_exposed": None, "criticality": "low"}


def test_every_decision_has_evidence_that_resolves(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    result = run_json(tmp_path, capsys, [str(REAL_REPORT)])

    evidence_ids = {item["id"] for item in result["evidence"]}
    cited = set()
    for decision in result["decisions"]:
        assert decision["evidence_ids"]
        cited.update(decision["evidence_ids"])
    assert cited == evidence_ids


def test_evidence_records_a_score_and_a_scanner_cvss(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cvss = {"redhat": {"V3Score": 7}, "nvd": {"V3Score": 9.8}}
    report = write_report(tmp_path, INTERNAL_IMAGE, vuln("CVE-2099-3001", CVSS=cvss))
    services = FakeServices({"CVE-2099-3001": "0.250000000"})

    result = run_json(tmp_path, capsys, [report], fetcher=services)

    evidence = {item["id"]: item for item in result["evidence"]}
    epss = evidence["epss:CVE-2099-3001"]
    assert epss["source"] == "first_epss"
    assert epss["data"]["score"] == 0.25
    assert epss["data"]["score_date"] == "2099-01-15"
    finding_evidence = next(item for item in result["evidence"] if item["id"].startswith("finding"))
    assert finding_evidence["source"] == "scanner_report"
    assert finding_evidence["data"]["cvss"] == {"score": 9.8, "version": "3", "source": "nvd"}


def test_cvss_does_not_change_a_priority(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(
        tmp_path, INTERNAL_IMAGE, vuln("CVE-2099-3001", "LOW", CVSS={"nvd": {"V3Score": 10}})
    )

    result = run_json(tmp_path, capsys, [report])

    assert result["decisions"][0]["priority"] == "P4"


def test_non_cve_evidence_says_not_applicable_with_no_timestamp(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln("DSA-6549-1"), vuln("CVE-2099-3001"))

    result = run_json(tmp_path, capsys, [report])

    evidence = {item["id"]: item for item in result["evidence"]}
    for prefix in ("kev", "epss"):
        item = evidence[f"{prefix}:DSA-6549-1"]
        assert item["data"]["state"] == "not_applicable"
        assert item["retrieved_at"] is None


def test_unassigned_artifact_is_evidence_when_a_rule_relied_on_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, UNLISTED_IMAGE, vuln(KEV_LISTED))

    result = run_json(tmp_path, capsys, [report])

    assert f"artifact:{UNLISTED_IMAGE}" in result["decisions"][0]["evidence_ids"]
    assert result["unassigned_artifacts"] == [UNLISTED_IMAGE]


def test_asset_evidence_is_only_cited_when_the_rule_read_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln("CVE-2099-3001", "LOW"))

    result = run_json(tmp_path, capsys, [report])

    assert not any(i.startswith("asset:") for i in result["decisions"][0]["evidence_ids"])


def test_json_is_ascii_only(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln("TEMP-café-\x1b[0m"))

    assert run(tmp_path, [report], "--json") == EXIT_OK

    output = capsys.readouterr().out
    assert output.isascii()
    assert "\x1b" not in output


def test_output_is_identical_between_runs_and_report_orders(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    first = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED), vuln("TEMP-1", "LOW"))
    second = write_report(tmp_path, UNLISTED_IMAGE, vuln(KEV_LISTED), vuln("CVE-2099-3001"))

    assert run(tmp_path, [first, second], "--json") == EXIT_OK
    forward = capsys.readouterr().out
    assert run(tmp_path, [second, first], "--json") == EXIT_OK

    assert capsys.readouterr().out == forward


# Decisions over merged findings


def test_merged_finding_takes_the_worst_exposure_of_its_assets(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    item = vuln(KEV_LISTED)
    internal = write_report(tmp_path, INTERNAL_IMAGE, item)
    exposed = write_report(tmp_path, EXPOSED_IMAGE, item)

    result = run_json(tmp_path, capsys, [internal, exposed])

    decision = result["decisions"][0]
    assert decision["finding"]["asset_ids"] == ["shop-api", "shop-worker"]
    assert decision["exposure"] == "exposed"
    assert decision["rule_id"] == "kev-exposed"
    assert decision["exposure_assumed"] is False


def test_not_exposed_asset_gets_the_lower_kev_priority(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, INTERNAL_IMAGE, vuln(KEV_LISTED))

    result = run_json(tmp_path, capsys, [report])

    assert result["decisions"][0]["priority"] == "P2"
    assert result["decisions"][0]["rule_id"] == "kev"
    assert result["decisions"][0]["exposure"] == "not_exposed"


def test_critical_on_important_asset_is_not_an_assumption(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, INTERNAL_IMAGE, vuln("CVE-2099-3001", "CRITICAL"))

    result = run_json(tmp_path, capsys, [report])

    decision = result["decisions"][0]
    assert decision["rule_id"] == "critical-on-critical-asset"
    assert decision["criticality_assumed"] is False


def test_all_not_affected_goes_to_p4_even_in_kev(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED, Status="not_affected"))

    result = run_json(tmp_path, capsys, [report])

    assert result["decisions"][0]["priority"] == "P4"
    assert result["decisions"][0]["rule_id"] == "not-affected"


def test_merged_mixed_status_is_not_treated_as_not_affected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    first = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED, Status="not_affected"))
    second = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED, Status="affected"))

    result = run_json(tmp_path, capsys, [first, second])

    assert result["decisions"][0]["rule_id"] == "kev-exposed"


def test_status_fixed_counts_as_a_fix_for_unknown_severity(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln("TEMP-1", "UNKNOWN", Status="fixed"))

    result = run_json(tmp_path, capsys, [report])

    assert result["decisions"][0]["rule_id"] == "unknown-with-fix"


# Real fixture


def test_real_report_decisions(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    result = run_json(tmp_path, capsys, [str(REAL_REPORT)])

    decisions = {d["finding"]["vuln_id"]: d for d in result["decisions"]}
    assert result["summary"]["total"] == 9
    expected = {
        "CVE-2026-8376": ("P2", "critical-on-critical-asset"),
        "CVE-2026-9538": ("P3", "severe"),
        "CVE-2026-109518": ("P3", "severe"),
        "CVE-2026-15059": ("P4", "default"),
        "TEMP-0628843-DBAD28": ("P4", "default"),
        "DSA-6549-1": ("P3", "unknown-with-fix"),
        "GHSA-xmj3-9gf7-h52w": ("P4", "default"),
    }
    for vuln_id, (priority, rule) in expected.items():
        assert (decisions[vuln_id]["priority"], decisions[vuln_id]["rule_id"]) == (priority, rule)
    assert decisions["CVE-2026-8376"]["criticality_assumed"] is True
    assert decisions["DSA-6549-1"]["kev_state"] == "not_applicable"
    assert decisions["GHSA-xmj3-9gf7-h52w"]["epss_state"] == "not_applicable"


# Exit codes and offline mode


def test_bad_report_exits_2_before_any_request(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    services = FakeServices()
    bad = str(FIXTURES / "trivy" / "malformed.json")

    assert run(tmp_path, [bad], fetcher=services) == EXIT_INPUT_ERROR

    assert services.urls == []
    assert capsys.readouterr().out == ""


def test_bad_inventory_exits_2_before_any_request(tmp_path: Path) -> None:
    services = FakeServices()
    inventory = tmp_path / "assets.yaml"
    inventory.write_text("assets: {}\n", encoding="utf-8")
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED))

    code = main(
        ["triage", report, "--assets", str(inventory), "--cache-dir", str(tmp_path / "c")],
        fetcher=services,
    )

    assert code == EXIT_INPUT_ERROR
    assert services.urls == []


def test_unreachable_network_without_cache_exits_3(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED))

    assert run(tmp_path, [report], fetcher=Unreachable()) == EXIT_ENRICHMENT_UNAVAILABLE

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: network is down\n"


def test_offline_without_cache_exits_3_without_a_request(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED))
    services = FakeServices()

    assert run(tmp_path, [report], "--offline", fetcher=services) == EXIT_ENRICHMENT_UNAVAILABLE

    assert services.urls == []
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "not in the cache" in captured.err


def test_offline_with_cache_matches_the_online_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED), vuln("CVE-2099-3001"))
    services = FakeServices({"CVE-2099-3001": "0.3"})

    assert run(tmp_path, [report], "--json", fetcher=services) == EXIT_OK
    online = capsys.readouterr().out
    untouched = FakeServices()
    assert run(tmp_path, [report], "--json", "--offline", fetcher=untouched) == EXIT_OK

    captured = capsys.readouterr()
    assert captured.out == online
    assert captured.err == ""
    assert untouched.urls == []


def test_offline_with_expired_cache_warns_and_marks_evidence_stale(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED))
    assert run(tmp_path, [report]) == EXIT_OK
    capsys.readouterr()

    later = NOW + MAX_AGE + timedelta(hours=1)
    assert run(tmp_path, [report], "--json", "--offline", now=later) == EXIT_OK

    captured = capsys.readouterr()
    evidence = {item["id"]: item for item in json.loads(captured.out)["evidence"]}
    assert evidence[f"kev:{KEV_LISTED}"]["data"]["stale"] is True
    assert evidence[f"epss:{KEV_LISTED}"]["data"]["stale"] is True
    assert "using expired KEV data" in captured.err
    assert "using expired EPSS data" in captured.err


def test_expired_cache_with_network_down_exits_3_and_offers_offline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED))
    assert run(tmp_path, [report]) == EXIT_OK
    capsys.readouterr()

    later = NOW + MAX_AGE + timedelta(hours=1)
    code = run(tmp_path, [report], fetcher=Unreachable(), now=later)

    assert code == EXIT_ENRICHMENT_UNAVAILABLE
    assert "--offline" in capsys.readouterr().err


def test_second_online_run_makes_no_requests(tmp_path: Path) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED))
    assert run(tmp_path, [report]) == EXIT_OK
    services = FakeServices()

    assert run(tmp_path, [report], fetcher=services) == EXIT_OK

    assert services.urls == []


def test_failed_cache_write_warns_and_still_succeeds(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED))

    code = main(
        ["triage", report, "--assets", str(ASSETS), "--cache-dir", str(blocker / "cache")],
        fetcher=FakeServices(),
        now=lambda: NOW,
    )

    assert code == EXIT_OK
    captured = capsys.readouterr()
    assert "cannot write cache file" in captured.err
    assert "rule:kev-exposed" in captured.out


def test_unrecognized_status_warns_in_triage_too(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln("TEMP-1", Status="resolved"))

    assert run(tmp_path, [report]) == EXIT_OK

    assert "unrecognized fix status treated as unknown: resolved" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        pytest.param(["triage"], id="no-report"),
        pytest.param(["triage", "report.json"], id="no-assets"),
    ],
)
def test_usage_errors_exit_2(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(argv)
    assert excinfo.value.code == EXIT_INPUT_ERROR


def test_default_network_is_used_when_none_is_injected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The guard in conftest.py blocks real connections, so this exercises the real fetcher's
    # failure path. A blocked lookup surfaces as an assertion from the guard, never as a request.
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED))

    with pytest.raises(AssertionError, match="offline"):
        main(["triage", report, "--assets", str(ASSETS), "--cache-dir", str(tmp_path / "c")])


def test_ingest_still_works_without_any_enrichment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, EXPOSED_IMAGE, vuln(KEV_LISTED))

    assert main(["ingest", report, "--assets", str(ASSETS)]) == EXIT_OK

    assert "Unique findings:      1" in capsys.readouterr().out
