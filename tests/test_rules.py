from dataclasses import replace
from math import nextafter

import pytest

from fixfirst.models import (
    Asset,
    Criticality,
    DataClassification,
    Environment,
    FixStatus,
    KevState,
    Severity,
)
from fixfirst.rules import (
    EPSS_CRITICAL,
    EPSS_ELEVATED,
    EPSS_MEDIUM,
    RULES,
    AssetImportance,
    Exposure,
    Priority,
    RuleId,
    RuleInput,
    compute_exposure,
    compute_importance,
    evaluate,
)

BASE = RuleInput(
    severity=Severity.LOW,
    fix_status=frozenset({FixStatus.AFFECTED}),
    fix_available=False,
    kev=KevState.NOT_LISTED,
    epss=None,
    exposure=Exposure.NOT_EXPOSED,
    importance=AssetImportance.NOT_IMPORTANT,
)
ALL_EXPOSURES = list(Exposure)


def just_below(value: float) -> float:
    return nextafter(value, 0.0)


def decide(**changes: object) -> tuple[Priority, RuleId]:
    rule = evaluate(replace(BASE, **changes))
    return rule.priority, rule.id


def asset(*, exposed: bool | None = False, criticality: Criticality = Criticality.LOW) -> Asset:
    return Asset(
        id="a",
        owner="team",
        criticality=criticality,
        environment=Environment.PROD,
        internet_exposed=exposed,
        data_classification=DataClassification.INTERNAL,
        match=["*"],
    )


def test_thresholds_are_the_documented_values() -> None:
    assert (EPSS_CRITICAL, EPSS_ELEVATED, EPSS_MEDIUM) == (0.5, 0.1, 0.05)


def test_rule_ids_are_stable() -> None:
    assert [rule.id.value for rule in RULES] == [
        "not-affected",
        "kev-exposed",
        "epss-exposed",
        "kev",
        "epss-severe",
        "critical-on-critical-asset",
        "severe",
        "medium-epss",
        "unknown-with-fix",
        "unknown-no-fix",
        "default",
    ]


def test_last_rule_always_applies() -> None:
    assert RULES[-1].id is RuleId.DEFAULT
    assert decide() == (Priority.P4, RuleId.DEFAULT)


# KEV


@pytest.mark.parametrize("exposure", [Exposure.EXPOSED, Exposure.ASSUMED])
@pytest.mark.parametrize("severity", list(Severity))
def test_kev_with_possible_exposure_is_p1_at_any_severity(
    exposure: Exposure, severity: Severity
) -> None:
    result = decide(kev=KevState.LISTED, exposure=exposure, severity=severity)
    assert result == (Priority.P1, RuleId.KEV_EXPOSED)


@pytest.mark.parametrize("severity", list(Severity))
def test_kev_without_exposure_is_p2_at_any_severity(severity: Severity) -> None:
    assert decide(kev=KevState.LISTED, severity=severity) == (Priority.P2, RuleId.KEV)


@pytest.mark.parametrize("state", [KevState.NOT_LISTED, KevState.NOT_APPLICABLE])
@pytest.mark.parametrize("exposure", ALL_EXPOSURES)
def test_kev_rules_need_a_listing(state: KevState, exposure: Exposure) -> None:
    assert decide(kev=state, exposure=exposure) == (Priority.P4, RuleId.DEFAULT)


# EPSS at P1


@pytest.mark.parametrize("severity", [Severity.HIGH, Severity.CRITICAL, Severity.UNKNOWN])
@pytest.mark.parametrize("exposure", [Exposure.EXPOSED, Exposure.ASSUMED])
def test_high_epss_with_possible_exposure_is_p1(severity: Severity, exposure: Exposure) -> None:
    result = decide(epss=EPSS_CRITICAL, severity=severity, exposure=exposure)
    assert result == (Priority.P1, RuleId.EPSS_EXPOSED)


def test_p1_epss_boundary() -> None:
    exposed = {"severity": Severity.HIGH, "exposure": Exposure.EXPOSED}
    assert decide(epss=0.5, **exposed) == (Priority.P1, RuleId.EPSS_EXPOSED)
    assert decide(epss=just_below(0.5), **exposed) == (Priority.P2, RuleId.EPSS_SEVERE)


@pytest.mark.parametrize("severity", [Severity.LOW, Severity.MEDIUM])
def test_high_epss_at_lower_severity_is_not_p1(severity: Severity) -> None:
    priority, _ = decide(epss=0.99, severity=severity, exposure=Exposure.EXPOSED)
    assert priority not in {Priority.P1, Priority.P2}


def test_high_epss_without_exposure_is_p2() -> None:
    assert decide(epss=0.99, severity=Severity.CRITICAL) == (Priority.P2, RuleId.EPSS_SEVERE)


# EPSS at P2


@pytest.mark.parametrize("severity", [Severity.HIGH, Severity.CRITICAL, Severity.UNKNOWN])
def test_elevated_epss_is_p2(severity: Severity) -> None:
    assert decide(epss=EPSS_ELEVATED, severity=severity) == (Priority.P2, RuleId.EPSS_SEVERE)


def test_p2_epss_boundary() -> None:
    assert decide(epss=0.1, severity=Severity.HIGH) == (Priority.P2, RuleId.EPSS_SEVERE)
    assert decide(epss=just_below(0.1), severity=Severity.HIGH) == (Priority.P3, RuleId.SEVERE)


def test_unknown_severity_counts_as_high_in_epss_rules() -> None:
    unknown = {"severity": Severity.UNKNOWN}
    assert decide(epss=0.5, exposure=Exposure.ASSUMED, **unknown)[1] is RuleId.EPSS_EXPOSED
    assert decide(epss=0.1, **unknown)[1] is RuleId.EPSS_SEVERE
    assert decide(epss=just_below(0.1), **unknown)[1] is RuleId.UNKNOWN_NO_FIX


# CRITICAL on an important asset


@pytest.mark.parametrize("importance", [AssetImportance.IMPORTANT, AssetImportance.ASSUMED])
def test_critical_on_important_or_unknown_asset_is_p2(importance: AssetImportance) -> None:
    result = decide(severity=Severity.CRITICAL, importance=importance)
    assert result == (Priority.P2, RuleId.CRITICAL_ON_CRITICAL_ASSET)


def test_critical_on_unimportant_asset_is_p3() -> None:
    assert decide(severity=Severity.CRITICAL) == (Priority.P3, RuleId.SEVERE)


@pytest.mark.parametrize("severity", [Severity.HIGH, Severity.MEDIUM, Severity.LOW])
def test_importance_only_matters_for_critical(severity: Severity) -> None:
    _, rule = decide(severity=severity, importance=AssetImportance.IMPORTANT)
    assert rule is not RuleId.CRITICAL_ON_CRITICAL_ASSET


# P3


@pytest.mark.parametrize("severity", [Severity.HIGH, Severity.CRITICAL])
def test_other_severe_findings_are_p3(severity: Severity) -> None:
    assert decide(severity=severity) == (Priority.P3, RuleId.SEVERE)


def test_medium_epss_boundary() -> None:
    medium = {"severity": Severity.MEDIUM}
    assert decide(epss=0.05, **medium) == (Priority.P3, RuleId.MEDIUM_EPSS)
    assert decide(epss=just_below(0.05), **medium) == (Priority.P4, RuleId.DEFAULT)


def test_medium_with_very_high_epss_stays_p3() -> None:
    result = decide(epss=0.99, severity=Severity.MEDIUM, exposure=Exposure.EXPOSED)
    assert result == (Priority.P3, RuleId.MEDIUM_EPSS)


def test_unknown_with_fix_is_p3() -> None:
    result = decide(severity=Severity.UNKNOWN, fix_available=True)
    assert result == (Priority.P3, RuleId.UNKNOWN_WITH_FIX)


def test_unknown_without_fix_is_p3_with_its_own_rule() -> None:
    assert decide(severity=Severity.UNKNOWN) == (Priority.P3, RuleId.UNKNOWN_NO_FIX)


@pytest.mark.parametrize("fix_available", [True, False])
@pytest.mark.parametrize("exposure", ALL_EXPOSURES)
def test_unknown_severity_never_reaches_p4(fix_available: bool, exposure: Exposure) -> None:
    priority, _ = decide(severity=Severity.UNKNOWN, fix_available=fix_available, exposure=exposure)
    assert priority is not Priority.P4


# P4


def test_low_stays_p4_whatever_its_epss() -> None:
    assert decide(epss=0.99, exposure=Exposure.EXPOSED) == (Priority.P4, RuleId.DEFAULT)


def test_medium_without_score_is_p4() -> None:
    assert decide(severity=Severity.MEDIUM) == (Priority.P4, RuleId.DEFAULT)


def test_missing_score_never_matches_as_zero() -> None:
    # A threshold of zero is not in use, so check the helper's effect through a severe finding.
    assert decide(epss=None, severity=Severity.HIGH) == (Priority.P3, RuleId.SEVERE)
    assert decide(epss=0.0, severity=Severity.HIGH) == (Priority.P3, RuleId.SEVERE)


# not_affected


@pytest.mark.parametrize("kev", list(KevState))
@pytest.mark.parametrize("severity", list(Severity))
@pytest.mark.parametrize("exposure", ALL_EXPOSURES)
def test_not_affected_overrides_everything(
    kev: KevState, severity: Severity, exposure: Exposure
) -> None:
    result = decide(
        fix_status=frozenset({FixStatus.NOT_AFFECTED}),
        kev=kev,
        severity=severity,
        exposure=exposure,
        epss=0.99,
        importance=AssetImportance.IMPORTANT,
    )
    assert result == (Priority.P4, RuleId.NOT_AFFECTED)


def test_not_affected_with_another_status_uses_the_normal_rules() -> None:
    result = decide(
        fix_status=frozenset({FixStatus.NOT_AFFECTED, FixStatus.AFFECTED}),
        kev=KevState.LISTED,
        exposure=Exposure.EXPOSED,
    )
    assert result == (Priority.P1, RuleId.KEV_EXPOSED)


# Precedence


def test_highest_priority_wins_when_several_rules_match() -> None:
    result = decide(
        kev=KevState.LISTED,
        epss=0.99,
        severity=Severity.CRITICAL,
        exposure=Exposure.EXPOSED,
        importance=AssetImportance.IMPORTANT,
    )
    assert result == (Priority.P1, RuleId.KEV_EXPOSED)


def test_rules_are_ordered_by_priority_after_the_override() -> None:
    ranks = [rule.priority.rank for rule in RULES[1:]]
    assert ranks == sorted(ranks)


# Combining exposure and criticality


@pytest.mark.parametrize(
    ("declared", "unassigned", "expected"),
    [
        pytest.param([True], False, Exposure.EXPOSED, id="exposed"),
        pytest.param([False], False, Exposure.NOT_EXPOSED, id="not-exposed"),
        pytest.param([None], False, Exposure.ASSUMED, id="unknown"),
        pytest.param([], True, Exposure.ASSUMED, id="unassigned"),
        pytest.param([False], True, Exposure.ASSUMED, id="not-exposed-plus-unassigned"),
        pytest.param([False, None], False, Exposure.ASSUMED, id="not-exposed-plus-unknown"),
        pytest.param([True, None], False, Exposure.EXPOSED, id="declared-wins-over-unknown"),
        pytest.param([True], True, Exposure.EXPOSED, id="declared-wins-over-unassigned"),
        pytest.param([False, True], False, Exposure.EXPOSED, id="any-exposed-asset"),
    ],
)
def test_exposure_combination(
    declared: list[bool | None], unassigned: bool, expected: Exposure
) -> None:
    assets = [asset(exposed=value) for value in declared]
    assert compute_exposure(assets, has_unassigned_artifact=unassigned) is expected


@pytest.mark.parametrize(
    ("criticalities", "unassigned", "expected"),
    [
        pytest.param([Criticality.CRITICAL], False, AssetImportance.IMPORTANT, id="critical"),
        pytest.param([Criticality.HIGH], False, AssetImportance.IMPORTANT, id="high"),
        pytest.param([Criticality.MEDIUM], False, AssetImportance.NOT_IMPORTANT, id="medium"),
        pytest.param([Criticality.LOW], False, AssetImportance.NOT_IMPORTANT, id="low"),
        pytest.param([], True, AssetImportance.ASSUMED, id="unassigned"),
        pytest.param([Criticality.LOW], True, AssetImportance.ASSUMED, id="low-plus-unassigned"),
        pytest.param([Criticality.HIGH], True, AssetImportance.IMPORTANT, id="known-wins"),
        pytest.param(
            [Criticality.LOW, Criticality.CRITICAL], False, AssetImportance.IMPORTANT, id="any"
        ),
    ],
)
def test_importance_combination(
    criticalities: list[Criticality], unassigned: bool, expected: AssetImportance
) -> None:
    assets = [asset(criticality=value) for value in criticalities]
    assert compute_importance(assets, has_unassigned_artifact=unassigned) is expected
