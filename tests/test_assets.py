from pathlib import Path

import pytest

from fixfirst.assets import assign_assets, load_assets, match_assets
from fixfirst.errors import InputError
from fixfirst.models import (
    Asset,
    Criticality,
    DataClassification,
    Environment,
    Finding,
    ParsedReport,
    Severity,
)

EXAMPLE = Path(__file__).parent.parent / "examples" / "assets.yaml"

VALID_ASSET = """\
assets:
  - id: a
    owner: team
    criticality: high
    environment: prod
    data_classification: internal
    match: ["x:*"]
"""


def make_asset(asset_id: str, *patterns: str) -> Asset:
    return Asset(
        id=asset_id,
        owner="team",
        criticality=Criticality.HIGH,
        environment=Environment.PROD,
        data_classification=DataClassification.INTERNAL,
        match=list(patterns),
    )


def make_finding(artifact: str) -> Finding:
    return Finding(
        vuln_id="CVE-2099-0001",
        package="p",
        ecosystem="pip",
        installed_version="1",
        scanner_severity=Severity.LOW,
        artifacts={artifact},
        source="trivy",
    )


def write_inventory(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "assets.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def test_example_inventory_loads() -> None:
    assets = load_assets(EXAMPLE)

    assert [asset.id for asset in assets] == ["shop-api", "shop-worker", "docs-site"]
    assert assets[0].criticality is Criticality.CRITICAL
    assert assets[0].environment is Environment.PROD
    assert assets[0].data_classification is DataClassification.CONFIDENTIAL
    assert assets[0].internet_exposed is True
    assert assets[1].internet_exposed is False


def test_omitted_internet_exposed_is_unknown() -> None:
    assert load_assets(EXAMPLE)[2].internet_exposed is None


@pytest.mark.parametrize(
    ("old", "new"),
    [
        pytest.param("criticality: high", "criticality: urgent", id="bad-criticality"),
        pytest.param("environment: prod", "environment: production", id="bad-environment"),
        pytest.param("data_classification: internal", "data_classification: x", id="bad-class"),
        pytest.param('match: ["x:*"]', "match: []", id="empty-match"),
        pytest.param('match: ["x:*"]', 'match: [""]', id="empty-pattern"),
        pytest.param('match: ["x:*"]', 'match: "x:*"', id="match-not-a-list"),
        pytest.param("id: a", "id: 123", id="id-not-a-string"),
        pytest.param("owner: team", "owner: team\n    internet_exposure: true", id="unknown-key"),
        pytest.param("owner: team", 'owner: team\n    internet_exposed: "no"', id="quoted-bool"),
    ],
)
def test_invalid_asset_is_an_input_error(tmp_path: Path, old: str, new: str) -> None:
    assert old in VALID_ASSET
    path = write_inventory(tmp_path, VALID_ASSET.replace(old, new))

    with pytest.raises(InputError, match="invalid inventory"):
        load_assets(path)


@pytest.mark.parametrize(
    "content",
    [
        pytest.param("", id="empty-file"),
        pytest.param("- id: a\n", id="bare-list"),
        pytest.param("assets: {}\n", id="assets-not-a-list"),
        pytest.param("assets: []\nversion: 1\n", id="unknown-top-level-key"),
    ],
)
def test_wrong_inventory_shape_is_an_input_error(tmp_path: Path, content: str) -> None:
    with pytest.raises(InputError, match="invalid inventory"):
        load_assets(write_inventory(tmp_path, content))


def test_duplicate_asset_id_is_reported_by_position_without_its_value(tmp_path: Path) -> None:
    item = VALID_ASSET.removeprefix("assets:\n")
    duplicated = item.replace("id: a", "id: SENTINEL")
    other = item.replace("id: a", "id: other")
    path = write_inventory(tmp_path, f"assets:\n{duplicated}{other}{duplicated}")

    with pytest.raises(InputError, match=r"assets\.2\.id: duplicate asset id") as excinfo:
        load_assets(path)

    assert "SENTINEL" not in str(excinfo.value)


def test_invalid_yaml_is_an_input_error(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="invalid YAML at line"):
        load_assets(write_inventory(tmp_path, "assets: [unclosed\n"))


def test_yaml_cannot_construct_python_objects(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    content = f'assets: !!python/object/apply:pathlib.Path.touch ["{marker.as_posix()}"]\n'

    with pytest.raises(InputError, match="invalid YAML"):
        load_assets(write_inventory(tmp_path, content))
    assert not marker.exists()


def test_inventory_larger_than_limit_is_rejected(tmp_path: Path) -> None:
    path = write_inventory(tmp_path, VALID_ASSET)

    with pytest.raises(InputError, match="byte limit"):
        load_assets(path, max_bytes=10)


def test_missing_inventory_is_an_input_error(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="cannot read file"):
        load_assets(tmp_path / "absent.yaml")


@pytest.mark.parametrize(
    ("pattern", "artifact", "expected"),
    [
        pytest.param("registry/app:*", "registry/app:1.0", True, id="tag-wildcard"),
        pytest.param("registry/*", "registry/team/app:1.0", True, id="star-crosses-slash"),
        pytest.param("registry/app:1.?", "registry/app:1.5", True, id="question-mark"),
        pytest.param("registry/app", "registry/app:1.0", False, id="must-match-full-name"),
        pytest.param("app:*", "registry/app:1.0", False, id="anchored-at-start"),
        pytest.param("Registry/App:*", "registry/app:1.0", False, id="case-sensitive"),
        pytest.param("registry/*", "registry\\app", False, id="backslash-is-not-a-slash"),
    ],
)
def test_glob_semantics(pattern: str, artifact: str, expected: bool) -> None:
    assert (match_assets(artifact, [make_asset("a", pattern)]) == {"a"}) is expected


def test_one_artifact_can_match_several_assets() -> None:
    assets = [make_asset("a", "img:*"), make_asset("b", "other", "img:1"), make_asset("c", "no")]

    assert match_assets("img:1", assets) == {"a", "b"}


def test_assign_assets_sets_ids_and_reports_unmatched() -> None:
    reports = [
        ParsedReport(artifact_name="img:1", findings=[make_finding("img:1")]),
        ParsedReport(artifact_name="z-unknown:1", findings=[make_finding("z-unknown:1")]),
        ParsedReport(artifact_name="a-unknown:1", findings=[]),
    ]

    findings, unassigned = assign_assets(reports, [make_asset("a", "img:*")])

    assert [f.asset_ids for f in findings] == [{"a"}, set()]
    assert unassigned == ["a-unknown:1", "z-unknown:1"]
