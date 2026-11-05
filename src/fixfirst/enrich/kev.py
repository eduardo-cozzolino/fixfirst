"""The CISA Known Exploited Vulnerabilities catalog."""

from dataclasses import dataclass
from datetime import date, datetime
from typing import Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    ValidationError,
    model_validator,
)

from fixfirst._input import describe_validation_error
from fixfirst.enrich import CveId, is_cve_id
from fixfirst.enrich.cache import Cache
from fixfirst.enrich.fetcher import Fetcher
from fixfirst.errors import EnrichmentError
from fixfirst.models import KevEvidence, KevState, NonEmptyStr

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_KEV_BYTES = 16 * 1024 * 1024

_CACHE_NAME = "kev.json"


class _FeedEntry(BaseModel):
    # Unknown fields are ignored so that new catalog fields do not break the feed.
    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)

    cve_id: CveId = Field(alias="cveID")
    date_added: date = Field(alias="dateAdded")
    due_date: date | None = Field(default=None, alias="dueDate")


class _Feed(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)

    catalog_version: NonEmptyStr = Field(alias="catalogVersion")
    count: StrictInt
    # An empty or cut-off catalog must never read as "nothing is exploited".
    vulnerabilities: list[_FeedEntry] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_count(self) -> Self:
        if self.count != len(self.vulnerabilities):
            raise ValueError("count does not match the number of vulnerabilities")
        return self


class KevEntry(BaseModel):
    """One catalog entry, without its description text."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    date_added: date
    due_date: date | None


class KevCatalog(BaseModel):
    """A validated catalog snapshot, as stored in the cache."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    catalog_version: NonEmptyStr
    retrieved_at: AwareDatetime
    entries: dict[CveId, KevEntry] = Field(min_length=1)


@dataclass(frozen=True)
class KevData:
    """The catalog to use for a run. ``catalog`` is None only when no CVE id needs a lookup."""

    catalog: KevCatalog | None = None
    stale: bool = False

    def lookup(self, vuln_id: str) -> KevEvidence:
        """Return what the catalog says about a vulnerability id."""
        if self.catalog is None or not is_cve_id(vuln_id):
            return KevEvidence(state=KevState.NOT_APPLICABLE)
        entry = self.catalog.entries.get(vuln_id)
        return KevEvidence(
            state=KevState.LISTED if entry else KevState.NOT_LISTED,
            catalog_version=self.catalog.catalog_version,
            date_added=entry.date_added if entry else None,
            due_date=entry.due_date if entry else None,
            stale=self.stale,
        )

    @property
    def retrieved_at(self) -> datetime | None:
        """Return when the catalog was retrieved."""
        return self.catalog.retrieved_at if self.catalog else None


def load_kev(cache: Cache, fetcher: Fetcher, *, offline: bool) -> KevData:
    """Return the catalog from the cache, downloading it when needed and allowed.

    Raises:
        EnrichmentError: No usable catalog is available.
    """
    cached = cache.load(_CACHE_NAME, KevCatalog)
    if cached is not None and cache.is_fresh(cached.retrieved_at):
        return KevData(cached)
    if offline:
        if cached is None:
            raise EnrichmentError(
                f"KEV data is not in the cache at {cache.directory}; run without --offline first"
            )
        cache.warnings.append(
            f"using expired KEV data retrieved at {cached.retrieved_at.isoformat()}"
        )
        return KevData(cached, stale=True)
    try:
        catalog = _download(cache, fetcher)
    except EnrichmentError as exc:
        if cached is None:
            raise
        raise EnrichmentError(
            f"{exc}; expired KEV data retrieved at {cached.retrieved_at.isoformat()} "
            "can be used with --offline"
        ) from exc
    cache.save(_CACHE_NAME, catalog)
    return KevData(catalog)


def _download(cache: Cache, fetcher: Fetcher) -> KevCatalog:
    raw = fetcher.fetch(KEV_URL, MAX_KEV_BYTES)
    try:
        feed = _Feed.model_validate_json(raw)
    except ValidationError as exc:
        raise EnrichmentError(f"invalid KEV feed: {describe_validation_error(exc)}") from exc
    return KevCatalog(
        catalog_version=feed.catalog_version,
        retrieved_at=cache.now(),
        entries={
            entry.cve_id: KevEntry(date_added=entry.date_added, due_date=entry.due_date)
            for entry in feed.vulnerabilities
        },
    )
