import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from fixfirst.enrich.cache import MAX_AGE, Cache
from fixfirst.enrich.kev import KEV_URL, MAX_KEV_BYTES, load_kev
from fixfirst.errors import EnrichmentError
from fixfirst.models import KevState

FEED = (Path(__file__).parent / "fixtures" / "enrich" / "kev.json").read_bytes()
NOW = datetime(2099, 1, 15, 12, tzinfo=UTC)


class FakeFetcher:
    def __init__(self, body: bytes = FEED, error: EnrichmentError | None = None) -> None:
        self.body = body
        self.error = error
        self.calls: list[tuple[str, int]] = []

    def fetch(self, url: str, max_bytes: int) -> bytes:
        self.calls.append((url, max_bytes))
        if self.error is not None:
            raise self.error
        return self.body


def cache_at(directory: Path, now: datetime = NOW) -> Cache:
    return Cache(directory, lambda: now)


def feed_with(**changes: object) -> bytes:
    return json.dumps(json.loads(FEED) | changes).encode("utf-8")


def test_download_uses_the_official_url_and_a_size_limit(tmp_path: Path) -> None:
    fetcher = FakeFetcher()

    load_kev(cache_at(tmp_path), fetcher, offline=False)

    assert fetcher.calls == [(KEV_URL, MAX_KEV_BYTES)]
    assert KEV_URL.startswith("https://www.cisa.gov/")


def test_lookup_states(tmp_path: Path) -> None:
    kev = load_kev(cache_at(tmp_path), FakeFetcher(), offline=False)

    listed = kev.lookup("CVE-2099-1001")
    assert listed.state is KevState.LISTED
    assert listed.catalog_version == "2099.01.15"
    assert listed.date_added == date(2099, 1, 15)
    assert listed.due_date == date(2099, 2, 5)
    assert listed.stale is False

    missing = kev.lookup("CVE-2099-9999")
    assert missing.state is KevState.NOT_LISTED
    assert missing.catalog_version == "2099.01.15"
    assert missing.date_added is None


@pytest.mark.parametrize(
    "vuln_id", ["TEMP-0628843-DBAD28", "DSA-6549-1", "GHSA-xmj3-9gf7-h52w", "cve-2099-1001"]
)
def test_non_cve_ids_are_not_applicable_never_not_listed(tmp_path: Path, vuln_id: str) -> None:
    kev = load_kev(cache_at(tmp_path), FakeFetcher(), offline=False)

    assert kev.lookup(vuln_id).state is KevState.NOT_APPLICABLE


def test_second_call_uses_the_cache_and_does_not_download(tmp_path: Path) -> None:
    load_kev(cache_at(tmp_path), FakeFetcher(), offline=False)
    fetcher = FakeFetcher()

    kev = load_kev(cache_at(tmp_path), fetcher, offline=False)

    assert fetcher.calls == []
    assert kev.lookup("CVE-2099-1001").state is KevState.LISTED
    assert kev.retrieved_at == NOW


def test_cache_holds_no_description_text(tmp_path: Path) -> None:
    load_kev(cache_at(tmp_path), FakeFetcher(), offline=False)

    assert "Synthetic entry" not in (tmp_path / "kev.json").read_text(encoding="utf-8")


def test_cache_at_max_age_is_used_and_just_past_it_is_refreshed(tmp_path: Path) -> None:
    load_kev(cache_at(tmp_path), FakeFetcher(), offline=False)

    fetcher = FakeFetcher()
    load_kev(cache_at(tmp_path, NOW + MAX_AGE), fetcher, offline=False)
    assert fetcher.calls == []

    later = NOW + MAX_AGE + timedelta(seconds=1)
    kev = load_kev(cache_at(tmp_path, later), fetcher, offline=False)
    assert len(fetcher.calls) == 1
    assert kev.retrieved_at == later
    assert kev.stale is False


def test_expired_cache_with_failed_refresh_fails_and_offers_offline(tmp_path: Path) -> None:
    load_kev(cache_at(tmp_path), FakeFetcher(), offline=False)
    later = NOW + MAX_AGE + timedelta(hours=1)

    with pytest.raises(EnrichmentError, match="--offline"):
        load_kev(
            cache_at(tmp_path, later), FakeFetcher(error=EnrichmentError("down")), offline=False
        )


def test_failed_download_without_cache_fails_without_mentioning_offline(tmp_path: Path) -> None:
    with pytest.raises(EnrichmentError) as excinfo:
        load_kev(cache_at(tmp_path), FakeFetcher(error=EnrichmentError("down")), offline=False)

    assert str(excinfo.value) == "down"


def test_offline_with_fresh_cache_uses_no_network(tmp_path: Path) -> None:
    load_kev(cache_at(tmp_path), FakeFetcher(), offline=False)
    fetcher = FakeFetcher()
    cache = cache_at(tmp_path)

    kev = load_kev(cache, fetcher, offline=True)

    assert fetcher.calls == []
    assert kev.stale is False
    assert cache.warnings == []


def test_offline_without_cache_fails_clearly(tmp_path: Path) -> None:
    fetcher = FakeFetcher()

    with pytest.raises(EnrichmentError, match="not in the cache"):
        load_kev(cache_at(tmp_path), fetcher, offline=True)
    assert fetcher.calls == []


def test_offline_with_corrupt_cache_fails_clearly(tmp_path: Path) -> None:
    (tmp_path / "kev.json").write_text("{broken", encoding="utf-8")

    with pytest.raises(EnrichmentError, match="not in the cache"):
        load_kev(cache_at(tmp_path), FakeFetcher(), offline=True)


def test_offline_with_expired_cache_warns_and_marks_it_stale(tmp_path: Path) -> None:
    load_kev(cache_at(tmp_path), FakeFetcher(), offline=False)
    cache = cache_at(tmp_path, NOW + MAX_AGE + timedelta(hours=1))
    fetcher = FakeFetcher()

    kev = load_kev(cache, fetcher, offline=True)

    assert fetcher.calls == []
    assert kev.lookup("CVE-2099-1001").stale is True
    assert kev.lookup("CVE-2099-9999").stale is True
    assert len(cache.warnings) == 1
    assert NOW.isoformat() in cache.warnings[0]


def test_corrupt_cache_is_replaced_online(tmp_path: Path) -> None:
    (tmp_path / "kev.json").write_text("{broken", encoding="utf-8")
    fetcher = FakeFetcher()

    kev = load_kev(cache_at(tmp_path), fetcher, offline=False)

    assert len(fetcher.calls) == 1
    assert kev.lookup("CVE-2099-1001").state is KevState.LISTED


def test_tampered_cache_with_empty_catalog_is_not_used(tmp_path: Path) -> None:
    (tmp_path / "kev.json").write_text(
        json.dumps({"catalog_version": "x", "retrieved_at": NOW.isoformat(), "entries": {}}),
        encoding="utf-8",
    )
    fetcher = FakeFetcher()

    load_kev(cache_at(tmp_path), fetcher, offline=False)

    assert len(fetcher.calls) == 1


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(b"{not json", id="malformed"),
        pytest.param(b"[]", id="not-an-object"),
        pytest.param(b"null", id="null"),
        pytest.param(feed_with(vulnerabilities=[], count=0), id="empty-catalog"),
        pytest.param(feed_with(count=3), id="count-too-high"),
        pytest.param(feed_with(count=1), id="count-too-low"),
        pytest.param(feed_with(count="2"), id="count-not-a-number"),
        pytest.param(feed_with(catalogVersion=""), id="empty-version"),
        pytest.param(
            feed_with(vulnerabilities=[{"cveID": "CVE-2099-1001"}], count=1),
            id="entry-without-date",
        ),
        pytest.param(
            feed_with(vulnerabilities=[{"cveID": "not-a-cve", "dateAdded": "2099-01-15"}], count=1),
            id="malformed-id",
        ),
        pytest.param(
            feed_with(vulnerabilities=[{"cveID": "CVE-2099-1", "dateAdded": "soon"}], count=1),
            id="malformed-date",
        ),
    ],
)
def test_invalid_feed_fails_and_is_not_cached(tmp_path: Path, body: bytes) -> None:
    with pytest.raises(EnrichmentError):
        load_kev(cache_at(tmp_path), FakeFetcher(body), offline=False)
    assert not (tmp_path / "kev.json").exists()


def test_invalid_feed_errors_do_not_echo_its_content(tmp_path: Path) -> None:
    body = feed_with(vulnerabilities=[{"cveID": "SENTINEL", "dateAdded": "SENTINEL"}], count=1)

    with pytest.raises(EnrichmentError) as excinfo:
        load_kev(cache_at(tmp_path), FakeFetcher(body), offline=False)

    assert "SENTINEL" not in str(excinfo.value)


def test_failed_cache_write_still_returns_the_data(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    cache = cache_at(blocker / "dir")

    kev = load_kev(cache, FakeFetcher(), offline=False)

    assert kev.lookup("CVE-2099-1001").state is KevState.LISTED
    assert len(cache.warnings) == 1
