"""Turn findings and enrichment data into priority decisions with their evidence."""

import hashlib
import json
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence

from pydantic import BaseModel, ConfigDict

from fixfirst.dedup import finding_sort_key
from fixfirst.enrich.epss import EpssData
from fixfirst.enrich.kev import KevData
from fixfirst.models import (
    Asset,
    AssetEvidence,
    EpssEvidence,
    EpssState,
    Evidence,
    EvidenceSource,
    Finding,
    FindingEvidence,
    FixStatus,
    KevEvidence,
    KevState,
    UnassignedArtifactEvidence,
)
from fixfirst.rules import (
    AssetImportance,
    Exposure,
    Priority,
    RuleId,
    RuleInput,
    compute_exposure,
    compute_importance,
    evaluate,
)


class TriageDecision(BaseModel):
    """The priority of one finding, the rule that decided it and the evidence behind it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    priority: Priority
    rule_id: RuleId
    finding: Finding
    exposure: Exposure
    # Whether the deciding rule relied on an assumption, rather than whether one exists.
    exposure_assumed: bool
    criticality_assumed: bool
    has_unassigned_artifact: bool
    kev_state: KevState
    epss_state: EpssState
    epss_score: float | None
    evidence_ids: list[str]


class TriageSummary(BaseModel):
    """Counts over all decisions, including any left out of the listing by a limit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    by_priority: dict[Priority, int]
    total: int


class TriageResult(BaseModel):
    """The outcome of a triage run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    decisions: list[TriageDecision]
    evidence: list[Evidence]
    summary: TriageSummary
    unassigned_artifacts: list[str]


def triage(
    findings: Iterable[Finding],
    assets: Iterable[Asset],
    unassigned_artifacts: Sequence[str],
    kev: KevData,
    epss: EpssData,
) -> TriageResult:
    """Decide the priority of every finding. The result is the same for the same input."""
    assets_by_id = {asset.id: asset for asset in assets}
    unassigned = frozenset(unassigned_artifacts)
    evidence: dict[str, Evidence] = {}
    decisions = [
        _decide(finding, assets_by_id, unassigned, kev, epss, evidence) for finding in findings
    ]
    decisions.sort(key=_decision_sort_key)
    counts = Counter(decision.priority for decision in decisions)
    return TriageResult(
        decisions=decisions,
        evidence=[evidence[evidence_id] for evidence_id in sorted(evidence)],
        summary=TriageSummary(
            by_priority={priority: counts[priority] for priority in Priority},
            total=len(decisions),
        ),
        unassigned_artifacts=sorted(unassigned),
    )


def limit_decisions(result: TriageResult, top: int) -> TriageResult:
    """Keep the first decisions and the evidence they cite. The summary still counts everything."""
    decisions = result.decisions[:top]
    cited = {evidence_id for decision in decisions for evidence_id in decision.evidence_ids}
    return result.model_copy(
        update={
            "decisions": decisions,
            "evidence": [item for item in result.evidence if item.id in cited],
        }
    )


def _decide(
    finding: Finding,
    assets_by_id: Mapping[str, Asset],
    unassigned: frozenset[str],
    kev: KevData,
    epss: EpssData,
    evidence: dict[str, Evidence],
) -> TriageDecision:
    assets = [assets_by_id[asset_id] for asset_id in sorted(finding.asset_ids)]
    unassigned_artifacts = sorted(finding.artifacts & unassigned)
    has_unassigned = bool(unassigned_artifacts)
    kev_result = kev.lookup(finding.vuln_id)
    epss_result = epss.lookup(finding.vuln_id)
    exposure = compute_exposure(assets, has_unassigned_artifact=has_unassigned)
    importance = compute_importance(assets, has_unassigned_artifact=has_unassigned)

    rule = evaluate(
        RuleInput(
            severity=finding.scanner_severity,
            fix_status=frozenset(finding.fix_status),
            fix_available=bool(finding.fixed_versions) or FixStatus.FIXED in finding.fix_status,
            kev=kev_result.state,
            epss=epss_result.score,
            exposure=exposure,
            importance=importance,
        )
    )

    # Every rule above the deciding one was checked against KEV and EPSS, so a finding's priority
    # always rests on them, even when they say nothing.
    used = [
        _record(evidence, _finding_evidence(finding)),
        _record(evidence, _kev_evidence(finding.vuln_id, kev_result, kev)),
        _record(evidence, _epss_evidence(finding.vuln_id, epss_result, epss)),
    ]
    if rule.reads_exposure or rule.reads_importance:
        used += [_record(evidence, _asset_evidence(asset)) for asset in assets]
        used += [_record(evidence, _artifact_evidence(name)) for name in unassigned_artifacts]

    return TriageDecision(
        priority=rule.priority,
        rule_id=rule.id,
        finding=finding,
        exposure=exposure,
        exposure_assumed=rule.reads_exposure and exposure is Exposure.ASSUMED,
        criticality_assumed=rule.reads_importance and importance is AssetImportance.ASSUMED,
        has_unassigned_artifact=has_unassigned,
        kev_state=kev_result.state,
        epss_state=epss_result.state,
        epss_score=epss_result.score,
        evidence_ids=sorted(used),
    )


def _record(evidence: dict[str, Evidence], item: Evidence) -> str:
    evidence[item.id] = item
    return item.id


def _finding_evidence(finding: Finding) -> Evidence:
    # A hash keeps the id short and stable, whatever a report puts in the key's fields.
    digest = hashlib.sha256(json.dumps(finding.dedup_key).encode("utf-8")).hexdigest()[:16]
    return Evidence(
        id=f"finding:{digest}",
        source=EvidenceSource.SCANNER_REPORT,
        retrieved_at=None,
        data=FindingEvidence(
            severity=finding.scanner_severity,
            fix_status=sorted(finding.fix_status),
            fixed_versions=finding.fixed_versions,
            cvss=finding.cvss,
        ),
    )


def _kev_evidence(vuln_id: str, result: KevEvidence, kev: KevData) -> Evidence:
    applicable = result.state is not KevState.NOT_APPLICABLE
    return Evidence(
        id=f"kev:{vuln_id}",
        source=EvidenceSource.CISA_KEV,
        retrieved_at=kev.retrieved_at if applicable else None,
        data=result,
    )


def _epss_evidence(vuln_id: str, result: EpssEvidence, epss: EpssData) -> Evidence:
    return Evidence(
        id=f"epss:{vuln_id}",
        source=EvidenceSource.FIRST_EPSS,
        retrieved_at=epss.retrieved_at(vuln_id),
        data=result,
    )


def _asset_evidence(asset: Asset) -> Evidence:
    return Evidence(
        id=f"asset:{asset.id}",
        source=EvidenceSource.ASSET_INVENTORY,
        retrieved_at=None,
        data=AssetEvidence(internet_exposed=asset.internet_exposed, criticality=asset.criticality),
    )


def _artifact_evidence(artifact: str) -> Evidence:
    return Evidence(
        id=f"artifact:{artifact}",
        source=EvidenceSource.ASSET_INVENTORY,
        retrieved_at=None,
        data=UnassignedArtifactEvidence(artifact=artifact),
    )


def _decision_sort_key(
    decision: TriageDecision,
) -> tuple[int, int, float, tuple[str, str, str, bool, str, tuple[str, ...]]]:
    key = finding_sort_key(decision.finding)
    # Scores sort highest first, and a missing score after every real one.
    epss_order = 1.0 if decision.epss_score is None else -decision.epss_score
    return (decision.priority.rank, key[0], epss_order, key[1:])
