"""The rules that turn a finding and its context into a priority.

The rules are an ordered table in which the first match wins, so reading ``RULES`` from top to
bottom explains every decision. Rule ids are stable and leave out the priority, so that they stay
valid if a rule ever moves. See docs/decisions/0002-triage.md for the reasoning.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum

from fixfirst.models import Asset, Criticality, FixStatus, KevState, Severity

# EPSS thresholds. All comparisons are inclusive.
EPSS_CRITICAL = 0.5
EPSS_ELEVATED = 0.1
EPSS_MEDIUM = 0.05


class Priority(StrEnum):
    """How soon a finding should be fixed. P1 comes first."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"

    @property
    def rank(self) -> int:
        """Return a number that grows as a priority gets less urgent."""
        return _PRIORITY_RANK[self]


_PRIORITY_RANK = {Priority.P1: 1, Priority.P2: 2, Priority.P3: 3, Priority.P4: 4}


class RuleId(StrEnum):
    """Stable identifiers of the rules."""

    NOT_AFFECTED = "not-affected"
    KEV_EXPOSED = "kev-exposed"
    EPSS_EXPOSED = "epss-exposed"
    KEV = "kev"
    EPSS_SEVERE = "epss-severe"
    CRITICAL_ON_CRITICAL_ASSET = "critical-on-critical-asset"
    SEVERE = "severe"
    MEDIUM_EPSS = "medium-epss"
    UNKNOWN_WITH_FIX = "unknown-with-fix"
    UNKNOWN_NO_FIX = "unknown-no-fix"
    DEFAULT = "default"


class Exposure(StrEnum):
    """Whether a finding is reachable from the internet."""

    EXPOSED = "exposed"
    # Nothing is declared exposed, but at least one asset or artifact is unknown.
    ASSUMED = "assumed"
    NOT_EXPOSED = "not_exposed"


class AssetImportance(StrEnum):
    """Whether a finding affects an asset with high or critical business criticality."""

    IMPORTANT = "important"
    # No asset is known to be important, but at least one artifact has no asset at all.
    ASSUMED = "assumed"
    NOT_IMPORTANT = "not_important"


@dataclass(frozen=True)
class RuleInput:
    """Everything the rules may read. Display text is deliberately not part of it."""

    severity: Severity
    fix_status: frozenset[FixStatus]
    fix_available: bool
    kev: KevState
    # None means there is no score, which is never treated as a score of zero.
    epss: float | None
    exposure: Exposure
    importance: AssetImportance


@dataclass(frozen=True)
class Rule:
    """One row of the rule table."""

    id: RuleId
    priority: Priority
    applies: Callable[[RuleInput], bool]
    reads_exposure: bool = False
    reads_importance: bool = False


_SEVERE = frozenset({Severity.HIGH, Severity.CRITICAL})
# An unknown severity must never read as low risk, so EPSS rules treat it like a high one.
_SEVERE_FOR_EPSS = _SEVERE | {Severity.UNKNOWN}


def _epss_at_least(item: RuleInput, threshold: float) -> bool:
    return item.epss is not None and item.epss >= threshold


def _may_be_exposed(item: RuleInput) -> bool:
    return item.exposure is not Exposure.NOT_EXPOSED


RULES: tuple[Rule, ...] = (
    Rule(
        RuleId.NOT_AFFECTED,
        Priority.P4,
        # Only when every copy says so. One affected copy keeps a finding in the normal rules.
        lambda item: item.fix_status == {FixStatus.NOT_AFFECTED},
    ),
    Rule(
        RuleId.KEV_EXPOSED,
        Priority.P1,
        lambda item: item.kev is KevState.LISTED and _may_be_exposed(item),
        reads_exposure=True,
    ),
    Rule(
        RuleId.EPSS_EXPOSED,
        Priority.P1,
        lambda item: (
            _epss_at_least(item, EPSS_CRITICAL)
            and item.severity in _SEVERE_FOR_EPSS
            and _may_be_exposed(item)
        ),
        reads_exposure=True,
    ),
    Rule(RuleId.KEV, Priority.P2, lambda item: item.kev is KevState.LISTED),
    Rule(
        RuleId.EPSS_SEVERE,
        Priority.P2,
        lambda item: _epss_at_least(item, EPSS_ELEVATED) and item.severity in _SEVERE_FOR_EPSS,
    ),
    Rule(
        RuleId.CRITICAL_ON_CRITICAL_ASSET,
        Priority.P2,
        lambda item: (
            item.severity is Severity.CRITICAL
            and item.importance is not AssetImportance.NOT_IMPORTANT
        ),
        reads_importance=True,
    ),
    Rule(RuleId.SEVERE, Priority.P3, lambda item: item.severity in _SEVERE),
    Rule(
        RuleId.MEDIUM_EPSS,
        Priority.P3,
        lambda item: item.severity is Severity.MEDIUM and _epss_at_least(item, EPSS_MEDIUM),
    ),
    Rule(
        RuleId.UNKNOWN_WITH_FIX,
        Priority.P3,
        lambda item: item.severity is Severity.UNKNOWN and item.fix_available,
    ),
    Rule(RuleId.UNKNOWN_NO_FIX, Priority.P3, lambda item: item.severity is Severity.UNKNOWN),
    Rule(RuleId.DEFAULT, Priority.P4, lambda item: True),
)


def evaluate(item: RuleInput) -> Rule:
    """Return the first rule that applies. The last rule always applies."""
    return next(rule for rule in RULES if rule.applies(item))


def compute_exposure(assets: Iterable[Asset], *, has_unassigned_artifact: bool) -> Exposure:
    """Combine the exposure of everything a finding affects, assuming the worst for unknowns."""
    declared = [asset.internet_exposed for asset in assets]
    if any(value is True for value in declared):
        return Exposure.EXPOSED
    if has_unassigned_artifact or any(value is None for value in declared):
        return Exposure.ASSUMED
    return Exposure.NOT_EXPOSED


def compute_importance(
    assets: Iterable[Asset], *, has_unassigned_artifact: bool
) -> AssetImportance:
    """Combine the criticality of everything a finding affects, assuming the worst for unknowns."""
    if any(asset.criticality in {Criticality.HIGH, Criticality.CRITICAL} for asset in assets):
        return AssetImportance.IMPORTANT
    if has_unassigned_artifact:
        return AssetImportance.ASSUMED
    return AssetImportance.NOT_IMPORTANT
