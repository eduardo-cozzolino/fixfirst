"""The data model shared by all fixfirst components."""

from datetime import date
from enum import StrEnum
from typing import Annotated

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StringConstraints,
    field_serializer,
    field_validator,
)

NonEmptyStr = Annotated[str, StringConstraints(strict=True, min_length=1)]

# vuln_id, ecosystem, package, installed_version, artifact scope
DedupKey = tuple[str, str, str, str | None, tuple[str, ...]]


class Severity(StrEnum):
    """Severity reported by a scanner.

    Always order severities through ``rank``. Comparing the members directly compares their names
    alphabetically, which would put HIGH below LOW.
    """

    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Return a number that grows with severity. UNKNOWN is the lowest."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.UNKNOWN: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class FixStatus(StrEnum):
    """Whether a fix exists for a vulnerability, as reported by a scanner."""

    FIXED = "fixed"
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    FIX_DEFERRED = "fix_deferred"
    WILL_NOT_FIX = "will_not_fix"
    END_OF_LIFE = "end_of_life"
    UNDER_INVESTIGATION = "under_investigation"
    UNKNOWN = "unknown"


class Criticality(StrEnum):
    """Business criticality of an asset."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Environment(StrEnum):
    """Deployment environment of an asset."""

    PROD = "prod"
    STAGING = "staging"
    DEV = "dev"


class DataClassification(StrEnum):
    """Sensitivity of the data an asset handles."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class CvssVersion(StrEnum):
    """CVSS version of a score."""

    V2 = "2"
    V3 = "3"
    V40 = "4.0"


class CvssScore(BaseModel):
    """A CVSS score and where it came from."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    score: float = Field(ge=0, le=10)
    version: CvssVersion
    source: NonEmptyStr


class Finding(BaseModel):
    """One vulnerability in one package version, with everything it affects."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    vuln_id: NonEmptyStr
    package: NonEmptyStr
    ecosystem: NonEmptyStr
    # None means unknown, which is not the same as any particular version.
    installed_version: NonEmptyStr | None = None
    fixed_versions: list[str] = Field(default_factory=list)
    # A set because the merged copies of a finding can report different statuses.
    fix_status: set[FixStatus] = Field(default_factory=lambda: {FixStatus.UNKNOWN}, min_length=1)
    scanner_severity: Severity
    cvss: CvssScore | None = None
    title: str | None = None
    primary_url: str | None = None
    asset_ids: set[str] = Field(default_factory=set)
    artifacts: set[str]
    # Where the copies are installed. Empty when the scanner reports no path, as for OS packages.
    pkg_paths: set[str] = Field(default_factory=set)
    source: NonEmptyStr

    @property
    def dedup_key(self) -> DedupKey:
        """Return the identity of this finding.

        The artifact scope is empty when the version is known, so the finding can merge across
        artifacts. An unknown version is scoped to its artifacts, because two unknown versions in
        different artifacts cannot be assumed to be the same version.
        """
        scope = tuple(sorted(self.artifacts)) if self.installed_version is None else ()
        return (self.vuln_id, self.ecosystem, self.package, self.installed_version, scope)

    @field_validator("fixed_versions")
    @classmethod
    def _normalize_fixed_versions(cls, value: list[str]) -> list[str]:
        # The order is only there to make output reproducible. It says nothing about which
        # version is newer.
        return sorted(set(value))

    @field_serializer("asset_ids", "artifacts", "pkg_paths")
    def _serialize_sorted(self, value: set[str]) -> list[str]:
        # Set iteration order changes between runs, and output has to be reproducible.
        return sorted(value)

    @field_serializer("fix_status")
    def _serialize_fix_status(self, value: set[FixStatus]) -> list[str]:
        return sorted(status.value for status in value)


class Asset(BaseModel):
    """An entry of the asset inventory."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: NonEmptyStr
    owner: NonEmptyStr
    criticality: Criticality
    environment: Environment
    # None means unknown, which is not the same as False.
    internet_exposed: StrictBool | None = None
    data_classification: DataClassification
    match: list[NonEmptyStr] = Field(min_length=1)


class ParsedReport(BaseModel):
    """The normalized content of one scanner report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_name: NonEmptyStr
    findings: list[Finding]
    # Raw values that were mapped to FixStatus.UNKNOWN. Untrusted: escape them before display.
    unrecognized_fix_statuses: set[str] = Field(default_factory=set)


class IngestResult(BaseModel):
    """The outcome of an ingest run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    findings: list[Finding]
    unassigned_artifacts: list[str]


class KevState(StrEnum):
    """What the KEV catalog says about a vulnerability id."""

    LISTED = "listed"
    NOT_LISTED = "not_listed"
    # The id is not a CVE, so KEV cannot say anything. This never means "not exploited".
    NOT_APPLICABLE = "not_applicable"


class EpssState(StrEnum):
    """What EPSS says about a vulnerability id."""

    SCORED = "scored"
    # EPSS has no score for this CVE. This never means a score of zero.
    NOT_SCORED = "not_scored"
    # The id is not a CVE, so EPSS cannot say anything. This never means "not exploited".
    NOT_APPLICABLE = "not_applicable"


class EvidenceSource(StrEnum):
    """Where a piece of evidence came from."""

    CISA_KEV = "cisa_kev"
    FIRST_EPSS = "first_epss"
    SCANNER_REPORT = "scanner_report"
    ASSET_INVENTORY = "asset_inventory"


class KevEvidence(BaseModel):
    """The KEV state of a vulnerability id."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: KevState
    catalog_version: str | None = None
    date_added: date | None = None
    due_date: date | None = None
    stale: bool = False


class EpssEvidence(BaseModel):
    """The EPSS state of a vulnerability id."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: EpssState
    score: float | None = None
    percentile: float | None = None
    score_date: date | None = None
    stale: bool = False


class FindingEvidence(BaseModel):
    """What a scanner report says about a finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    severity: Severity
    fix_status: list[FixStatus]
    fixed_versions: list[str]
    cvss: CvssScore | None


class AssetEvidence(BaseModel):
    """What the inventory says about an asset."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    internet_exposed: bool | None
    criticality: Criticality


class UnassignedArtifactEvidence(BaseModel):
    """An artifact that matches no asset, so its exposure and criticality are unknown."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact: NonEmptyStr


class Evidence(BaseModel):
    """A fact that a priority decision relied on."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: NonEmptyStr
    source: EvidenceSource
    # None for reports and inventories, which are read rather than retrieved. A timestamp of the run
    # would add nothing and would make the output differ between identical runs.
    retrieved_at: AwareDatetime | None
    data: KevEvidence | EpssEvidence | FindingEvidence | AssetEvidence | UnassignedArtifactEvidence
