from itertools import permutations

from fixfirst.dedup import merge_findings
from fixfirst.models import Finding, FixStatus, Severity


def make_finding(
    artifact: str = "img:1",
    *,
    vuln_id: str = "CVE-2099-0001",
    package: str = "libexample",
    ecosystem: str = "debian",
    installed_version: str | None = "1.0-1",
    fixed_versions: list[str] | None = None,
    severity: Severity = Severity.HIGH,
    title: str | None = None,
    primary_url: str | None = None,
    asset_ids: set[str] | None = None,
    pkg_paths: set[str] | None = None,
    fix_status: FixStatus = FixStatus.UNKNOWN,
) -> Finding:
    return Finding(
        vuln_id=vuln_id,
        package=package,
        ecosystem=ecosystem,
        installed_version=installed_version,
        fixed_versions=fixed_versions or [],
        scanner_severity=severity,
        title=title,
        primary_url=primary_url,
        asset_ids=asset_ids or set(),
        artifacts={artifact},
        pkg_paths=pkg_paths or set(),
        fix_status={fix_status},
        source="trivy",
    )


def test_same_key_across_artifacts_is_merged() -> None:
    merged = merge_findings(
        [
            make_finding("img:1", asset_ids={"a"}, fixed_versions=["2"]),
            make_finding("img:2", asset_ids={"b"}, fixed_versions=["3", "2"]),
        ]
    )

    assert len(merged) == 1
    assert merged[0].asset_ids == {"a", "b"}
    assert merged[0].artifacts == {"img:1", "img:2"}
    assert merged[0].fixed_versions == ["2", "3"]


def test_dedup_key_order_is_vuln_ecosystem_package_version() -> None:
    assert make_finding().dedup_key == ("CVE-2099-0001", "debian", "libexample", "1.0-1", ())


def test_dedup_key_of_unknown_version_includes_the_artifact() -> None:
    assert make_finding("img:1", installed_version=None).dedup_key == (
        "CVE-2099-0001",
        "debian",
        "libexample",
        None,
        ("img:1",),
    )


def test_pkg_paths_are_merged_as_a_union() -> None:
    merged = merge_findings(
        [
            make_finding("img:1", pkg_paths={"a/METADATA"}),
            make_finding("img:1", pkg_paths={"b/METADATA"}),
            make_finding("img:2", pkg_paths={"a/METADATA"}),
            make_finding("img:2"),
        ]
    )

    assert len(merged) == 1
    assert merged[0].pkg_paths == {"a/METADATA", "b/METADATA"}


def test_all_distinct_fix_statuses_are_kept() -> None:
    merged = merge_findings(
        [
            make_finding("a", fix_status=FixStatus.FIXED),
            make_finding("b", fix_status=FixStatus.FIX_DEFERRED),
            make_finding("c", fix_status=FixStatus.FIXED),
            make_finding("d", fix_status=FixStatus.UNKNOWN),
        ]
    )

    assert merged[0].fix_status == {FixStatus.FIXED, FixStatus.FIX_DEFERRED, FixStatus.UNKNOWN}


def test_new_fields_do_not_split_a_finding() -> None:
    merged = merge_findings(
        [
            make_finding("a", pkg_paths={"x"}, fix_status=FixStatus.FIXED),
            make_finding("a", pkg_paths={"y"}, fix_status=FixStatus.AFFECTED),
        ]
    )

    assert len(merged) == 1


def test_same_key_twice_in_one_artifact_is_merged() -> None:
    assert len(merge_findings([make_finding(), make_finding()])) == 1


def test_each_key_component_keeps_findings_apart() -> None:
    findings = [
        make_finding(),
        make_finding(vuln_id="CVE-2099-0002"),
        make_finding(package="other"),
        make_finding(ecosystem="ubuntu"),
        make_finding(installed_version="1.0-2"),
    ]

    assert len(merge_findings(findings)) == len(findings)


def test_merged_severity_is_the_highest_rank_not_the_alphabetical_maximum() -> None:
    # Alphabetically, "UNKNOWN" and "MEDIUM" sort above "CRITICAL" and "HIGH".
    merged = merge_findings(
        [
            make_finding("a", severity=Severity.UNKNOWN),
            make_finding("b", severity=Severity.MEDIUM),
            make_finding("c", severity=Severity.CRITICAL),
            make_finding("d", severity=Severity.HIGH),
        ]
    )

    assert merged[0].scanner_severity is Severity.CRITICAL


def test_title_and_url_come_from_the_first_artifact_that_has_them() -> None:
    merged = merge_findings(
        [
            make_finding("c", title="title c", primary_url="https://example.com/c"),
            make_finding("b", title="title b"),
            make_finding("a"),
        ]
    )

    assert merged[0].title == "title b"
    assert merged[0].primary_url == "https://example.com/c"


def test_merge_is_independent_of_input_order() -> None:
    findings = [
        make_finding("b", title="same artifact 2", fixed_versions=["1"], asset_ids={"x"}),
        make_finding("b", title="same artifact 1", severity=Severity.LOW, pkg_paths={"p2", "p1"}),
        make_finding(
            "a", fixed_versions=["2"], severity=Severity.CRITICAL, fix_status=FixStatus.FIXED
        ),
        make_finding("c", vuln_id="CVE-2099-0002", primary_url="https://example.com/"),
    ]

    outputs = {
        repr([f.model_dump(mode="json") for f in merge_findings(order)])
        for order in permutations(findings)
    }

    assert len(outputs) == 1


def test_output_is_sorted_by_severity_rank_then_key() -> None:
    merged = merge_findings(
        [
            make_finding(vuln_id="A", severity=Severity.UNKNOWN),
            make_finding(vuln_id="B", severity=Severity.LOW),
            make_finding(vuln_id="D", severity=Severity.CRITICAL),
            make_finding(vuln_id="C", severity=Severity.CRITICAL),
            make_finding(vuln_id="E", severity=Severity.HIGH),
        ]
    )

    assert [f.vuln_id for f in merged] == ["C", "D", "E", "B", "A"]


def test_unknown_versions_in_the_same_artifact_merge() -> None:
    merged = merge_findings(
        [
            make_finding("img:1", installed_version=None, fixed_versions=["2"]),
            make_finding("img:1", installed_version=None, fixed_versions=["3"]),
        ]
    )

    assert len(merged) == 1
    assert merged[0].installed_version is None
    assert merged[0].artifacts == {"img:1"}
    assert merged[0].fixed_versions == ["2", "3"]


def test_unknown_versions_in_different_artifacts_stay_separate() -> None:
    merged = merge_findings(
        [
            make_finding("img:1", installed_version=None, asset_ids={"x"}),
            make_finding("img:2", installed_version=None, asset_ids={"y"}),
        ]
    )

    assert [(f.artifacts, f.asset_ids) for f in merged] == [
        ({"img:1"}, {"x"}),
        ({"img:2"}, {"y"}),
    ]


def test_known_versions_still_merge_across_artifacts_next_to_unknown_ones() -> None:
    merged = merge_findings(
        [
            make_finding("img:1", installed_version="1.0-1"),
            make_finding("img:2", installed_version="1.0-1"),
            make_finding("img:1", installed_version=None),
        ]
    )

    assert [(f.installed_version, f.artifacts) for f in merged] == [
        ("1.0-1", {"img:1", "img:2"}),
        (None, {"img:1"}),
    ]


def test_order_of_unknown_versions_is_independent_of_input_order() -> None:
    findings = [make_finding(artifact, installed_version=None) for artifact in ("c", "a", "b")]

    for order in permutations(findings):
        assert [f.artifacts for f in merge_findings(order)] == [{"a"}, {"b"}, {"c"}]


def test_unknown_version_sorts_after_known_versions() -> None:
    versions = ["2.0", None, "1.0"]

    for order in permutations(versions):
        merged = merge_findings([make_finding(installed_version=v) for v in order])
        assert [f.installed_version for f in merged] == ["1.0", "2.0", None]


def test_no_findings_gives_no_output() -> None:
    assert merge_findings([]) == []
