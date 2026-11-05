"""FIRST Exploit Prediction Scoring System scores.

The API fails silently in two ways, both measured against the live service. A ``cve`` parameter of
more than about 2,000 characters returns HTTP 200 with no rows, and more than 100 ids return only
the first 100 rows. Batches stay below both limits, and responses are checked for both symptoms.
"""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Annotated

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StringConstraints,
    ValidationError,
    field_validator,
)

from fixfirst._input import describe_validation_error
from fixfirst.enrich import CveId, is_cve_id
from fixfirst.enrich.cache import Cache
from fixfirst.enrich.fetcher import Fetcher
from fixfirst.errors import EnrichmentError
from fixfirst.models import EpssEvidence, EpssState

EPSS_URL = "https://api.first.org/data/v1/epss"
MAX_EPSS_RESPONSE_BYTES = 1024 * 1024
MAX_BATCH_IDS = 100
MAX_BATCH_CHARACTERS = 1900
# This many ids with no scores at all looks like the silent failure, not like a set of new CVEs.
MIN_IDS_FOR_EMPTY_RESPONSE_ERROR = 20

_CACHE_NAME = "epss.json"
_HTTP_OK = 200

# The API sends numbers as strings. A plain decimal form rules out float() extras such as "inf",
# "1_0" or surrounding whitespace.
_DecimalString = Annotated[
    str, StringConstraints(strict=True, pattern=r"^[0-9]{1,3}(\.[0-9]{1,20})?$")
]


class _Row(BaseModel):
    # Unknown fields are ignored so that new API fields do not break parsing.
    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)

    cve: CveId
    epss: _DecimalString
    percentile: _DecimalString
    score_date: date = Field(alias="date")

    @field_validator("epss", "percentile")
    @classmethod
    def _check_range(cls, value: str) -> str:
        if not 0.0 <= float(value) <= 1.0:
            raise ValueError("must be between 0 and 1")
        return value


class _Response(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)

    status_code: StrictInt = Field(alias="status-code")
    total: StrictInt
    data: list[_Row]


class EpssEntry(BaseModel):
    """The cached result for one CVE. No score means EPSS has none, not a score of zero."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    retrieved_at: AwareDatetime
    score: float | None = Field(default=None, ge=0, le=1)
    percentile: float | None = Field(default=None, ge=0, le=1)
    score_date: date | None = None


class _CacheFile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    entries: dict[CveId, EpssEntry]


@dataclass(frozen=True)
class EpssData:
    """The EPSS results to use for a run."""

    entries: dict[str, EpssEntry] = field(default_factory=dict)
    stale_ids: frozenset[str] = frozenset()

    def lookup(self, vuln_id: str) -> EpssEvidence:
        """Return what EPSS says about a vulnerability id."""
        entry = self.entries.get(vuln_id)
        if not is_cve_id(vuln_id) or entry is None:
            return EpssEvidence(state=EpssState.NOT_APPLICABLE)
        return EpssEvidence(
            state=EpssState.NOT_SCORED if entry.score is None else EpssState.SCORED,
            score=entry.score,
            percentile=entry.percentile,
            score_date=entry.score_date,
            stale=vuln_id in self.stale_ids,
        )

    def retrieved_at(self, vuln_id: str) -> datetime | None:
        """Return when the result for an id was retrieved."""
        entry = self.entries.get(vuln_id)
        return entry.retrieved_at if entry else None


def load_epss(cve_ids: Iterable[str], cache: Cache, fetcher: Fetcher, *, offline: bool) -> EpssData:
    """Return results for the given ids from the cache, querying the API when needed and allowed.

    Ids that are not valid CVE ids are never sent anywhere. All ids get a result or the call fails.

    Raises:
        EnrichmentError: A result is not available for every id.
    """
    wanted = sorted({vuln_id for vuln_id in cve_ids if is_cve_id(vuln_id)})
    cached_file = cache.load(_CACHE_NAME, _CacheFile)
    cached = dict(cached_file.entries) if cached_file else {}
    missing = [vuln_id for vuln_id in wanted if vuln_id not in cached]
    expired = [
        vuln_id
        for vuln_id in wanted
        if vuln_id in cached and not cache.is_fresh(cached[vuln_id].retrieved_at)
    ]

    if offline:
        if missing:
            raise EnrichmentError(
                f"EPSS data for {len(missing)} CVE ids is not in the cache at {cache.directory}; "
                "run without --offline first"
            )
        if expired:
            cache.warnings.append(f"using expired EPSS data for {len(expired)} CVE ids")
        return EpssData({vuln_id: cached[vuln_id] for vuln_id in wanted}, frozenset(expired))

    needed = sorted({*missing, *expired})
    if needed:
        try:
            cached.update(_query(needed, cache, fetcher))
        except EnrichmentError as exc:
            if missing:
                raise
            raise EnrichmentError(
                f"{exc}; expired EPSS data for {len(expired)} CVE ids can be used with --offline"
            ) from exc
        cache.save(_CACHE_NAME, _CacheFile(entries=cached))
    return EpssData({vuln_id: cached[vuln_id] for vuln_id in wanted})


def batches(cve_ids: Iterable[str]) -> Iterator[list[str]]:
    """Split ids into groups that stay below both API limits."""
    batch: list[str] = []
    characters = 0
    for vuln_id in cve_ids:
        added = len(vuln_id) + (1 if batch else 0)
        if batch and (len(batch) == MAX_BATCH_IDS or characters + added > MAX_BATCH_CHARACTERS):
            yield batch
            batch = []
            characters = 0
            added = len(vuln_id)
        batch.append(vuln_id)
        characters += added
    if batch:
        yield batch


def _query(cve_ids: Iterable[str], cache: Cache, fetcher: Fetcher) -> dict[str, EpssEntry]:
    results: dict[str, EpssEntry] = {}
    for batch in batches(cve_ids):
        rows = _query_batch(batch, fetcher)
        retrieved_at = cache.now()
        for vuln_id in batch:
            row = rows.get(vuln_id)
            results[vuln_id] = (
                EpssEntry(
                    retrieved_at=retrieved_at,
                    score=float(row.epss),
                    percentile=float(row.percentile),
                    score_date=row.score_date,
                )
                if row
                else EpssEntry(retrieved_at=retrieved_at)
            )
    return results


def _query_batch(batch: list[str], fetcher: Fetcher) -> dict[str, _Row]:
    # Every id matched the CVE pattern, so the query string needs no escaping.
    raw = fetcher.fetch(f"{EPSS_URL}?cve={','.join(batch)}", MAX_EPSS_RESPONSE_BYTES)
    try:
        response = _Response.model_validate_json(raw)
    except ValidationError as exc:
        raise EnrichmentError(f"invalid EPSS response: {describe_validation_error(exc)}") from exc
    if response.status_code != _HTTP_OK:
        raise EnrichmentError(f"EPSS API returned status code {response.status_code}")
    if response.total != len(response.data):
        raise EnrichmentError(
            f"EPSS API returned {len(response.data)} rows out of {response.total}"
        )
    if not response.data and len(batch) >= MIN_IDS_FOR_EMPTY_RESPONSE_ERROR:
        raise EnrichmentError(f"EPSS API returned no rows for a batch of {len(batch)} CVE ids")
    return {row.cve: row for row in response.data}
