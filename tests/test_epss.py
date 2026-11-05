import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from fixfirst.enrich.cache import MAX_AGE, Cache
from fixfirst.enrich.epss import (
    EPSS_URL,
    MAX_BATCH_CHARACTERS,
    MAX_BATCH_IDS,
    MAX_EPSS_RESPONSE_BYTES,
    MIN_IDS_FOR_EMPTY_RESPONSE_ERROR,
    batches,
    load_epss,
)
from fixfirst.errors import EnrichmentError
from fixfirst.models import EpssState

RECORDED = json.loads((Path(__file__).parent / "fixtures" / "enrich" / "epss.json").read_bytes())
NOW = datetime(2099, 1, 15, 12, tzinfo=UTC)


def row(cve: str, epss: str = "0.100000000") -> dict[str, str]:
    return {"cve": cve, "epss": epss, "percentile": "0.900000000", "date": "2099-01-15"}


def response(rows: list[dict[str, Any]], **changes: object) -> bytes:
    return json.dumps(
        {"status": "OK", "status-code": 200, "total": len(rows), "data": rows} | changes
    ).encode("utf-8")


class FakeApi:
    """Answers like the API: known ids get rows, and unknown ids are simply left out."""

    def __init__(self, scores: dict[str, str] | None = None, *, score_all: bool = False) -> None:
        self.scores = scores or {}
        self.score_all = score_all
        self.requested: list[list[str]] = []
        self.calls: list[tuple[str, int]] = []

    def fetch(self, url: str, max_bytes: int) -> bytes:
        self.calls.append((url, max_bytes))
        ids = parse_qs(urlsplit(url).query)["cve"][0].split(",")
        self.requested.append(ids)
        return response(
            [
                row(vuln_id, self.scores.get(vuln_id, "0.100000000"))
                for vuln_id in ids
                if self.score_all or vuln_id in self.scores
            ]
        )


class FixedResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def fetch(self, url: str, max_bytes: int) -> bytes:
        return self.body


class Failing:
    def fetch(self, url: str, max_bytes: int) -> bytes:
        raise EnrichmentError("down")


def cache_at(directory: Path, now: datetime = NOW) -> Cache:
    return Cache(directory, lambda: now)


def test_recorded_response_is_parsed(tmp_path: Path) -> None:
    fetcher = FixedResponse(json.dumps(RECORDED).encode("utf-8"))

    epss = load_epss(["CVE-2099-2001", "CVE-2099-2002"], cache_at(tmp_path), fetcher, offline=False)

    scored = epss.lookup("CVE-2099-2001")
    assert scored.state is EpssState.SCORED
    assert scored.score == 0.5
    assert scored.percentile == 0.98
    assert scored.score_date == date(2099, 1, 15)
    assert epss.lookup("CVE-2099-2002").score == 0.0054
    assert epss.retrieved_at("CVE-2099-2001") == NOW


def test_request_url_and_size_limit(tmp_path: Path) -> None:
    api = FakeApi()

    load_epss(["CVE-2099-0002", "CVE-2099-0001"], cache_at(tmp_path), api, offline=False)

    assert api.calls == [
        (f"{EPSS_URL}?cve=CVE-2099-0001,CVE-2099-0002", MAX_EPSS_RESPONSE_BYTES),
    ]
    assert EPSS_URL.startswith("https://api.first.org/")


def test_id_without_a_row_is_not_scored_never_zero(tmp_path: Path) -> None:
    api = FakeApi({"CVE-2099-0001": "0.200000000"})

    epss = load_epss(["CVE-2099-0001", "CVE-2099-0002"], cache_at(tmp_path), api, offline=False)

    result = epss.lookup("CVE-2099-0002")
    assert result.state is EpssState.NOT_SCORED
    assert result.score is None


@pytest.mark.parametrize(
    "vuln_id",
    [
        "TEMP-0628843-DBAD28",
        "DSA-6549-1",
        "GHSA-xmj3-9gf7-h52w",
        "cve-2099-0001",
        "CVE-2099-0001&limit=1",
        "CVE-2099-0001,CVE-2099-0002",
        "CVE-2099-12345678",
        "CVE-2099-123",
        "CVE-2099-١٢٣٤",
        "CVE-2099-0001\n",
    ],
)
def test_ids_that_are_not_plain_cves_are_never_sent(tmp_path: Path, vuln_id: str) -> None:
    api = FakeApi()

    epss = load_epss([vuln_id], cache_at(tmp_path), api, offline=False)

    assert api.calls == []
    assert epss.lookup(vuln_id).state is EpssState.NOT_APPLICABLE


def test_ids_are_deduplicated(tmp_path: Path) -> None:
    api = FakeApi()

    load_epss(["CVE-2099-0001", "CVE-2099-0001"], cache_at(tmp_path), api, offline=False)

    assert api.requested == [["CVE-2099-0001"]]


def test_no_ids_means_no_request_and_no_cache_write(tmp_path: Path) -> None:
    api = FakeApi()

    load_epss([], cache_at(tmp_path), api, offline=False)

    assert api.calls == []
    assert not (tmp_path / "epss.json").exists()


@pytest.mark.parametrize("count", [1, 99, 100, 101, 200, 201, 350])
def test_batches_keep_every_id_within_the_count_limit(count: int) -> None:
    ids = [f"CVE-2099-{index:04}" for index in range(count)]

    result = list(batches(ids))

    assert [vuln_id for batch in result for vuln_id in batch] == ids
    assert all(len(batch) <= MAX_BATCH_IDS for batch in result)


def test_batches_respect_the_character_limit_with_long_ids() -> None:
    # 100 of these would be 1,799 characters, so use a lower limit by adding more ids of max length.
    ids = [f"CVE-2099-{index:07}" for index in range(500)]

    result = list(batches(ids))

    assert [vuln_id for batch in result for vuln_id in batch] == ids
    assert all(len(",".join(batch)) <= MAX_BATCH_CHARACTERS for batch in result)
    assert all(len(batch) <= MAX_BATCH_IDS for batch in result)


def test_batches_split_on_characters_before_reaching_the_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("fixfirst.enrich.epss.MAX_BATCH_CHARACTERS", 40)
    ids = [f"CVE-2099-{index:04}" for index in range(5)]

    result = list(batches(ids))

    # 13 characters each plus a comma: three ids make 41, which is over the limit.
    assert [len(batch) for batch in result] == [2, 2, 1]
    assert all(len(",".join(batch)) <= 40 for batch in result)


def test_batch_limits_stay_below_the_measured_silent_limits() -> None:
    assert MAX_BATCH_IDS <= 100
    assert MAX_BATCH_CHARACTERS < 2000


def test_large_request_is_split_and_complete(tmp_path: Path) -> None:
    ids = [f"CVE-2099-{index:04}" for index in range(250)]
    api = FakeApi(score_all=True)

    epss = load_epss(ids, cache_at(tmp_path), api, offline=False)

    assert [len(batch) for batch in api.requested] == [100, 100, 50]
    assert all(epss.lookup(vuln_id).state is EpssState.SCORED for vuln_id in ids)


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(b"{not json", id="malformed"),
        pytest.param(b"[]", id="not-an-object"),
        pytest.param(b"", id="empty-body"),
        pytest.param(response([], data=None), id="null-data"),
        pytest.param(response([row("CVE-2099-0001")], **{"status-code": 500}), id="status-code"),
        pytest.param(response([row("CVE-2099-0001")], total=2), id="truncated-total-above-rows"),
        pytest.param(response([row("CVE-2099-0001")], total=0), id="total-below-rows"),
        pytest.param(response([row("CVE-2099-0001")], total="1"), id="total-not-a-number"),
        pytest.param(response([row("not-a-cve")]), id="malformed-id"),
        pytest.param(response([row("CVE-2099-0001", "1.5")]), id="score-above-one"),
        pytest.param(response([row("CVE-2099-0001", "-0.1")]), id="negative-score"),
        pytest.param(response([row("CVE-2099-0001", "NaN")]), id="nan"),
        pytest.param(response([row("CVE-2099-0001", "inf")]), id="infinity"),
        pytest.param(response([row("CVE-2099-0001", "1e-3")]), id="exponent"),
        pytest.param(response([row("CVE-2099-0001", "0_1")]), id="underscore"),
        pytest.param(response([row("CVE-2099-0001", " 0.1")]), id="whitespace"),
        pytest.param(response([row("CVE-2099-0001", "")]), id="empty-score"),
        pytest.param(
            response([{"cve": "CVE-2099-0001", "epss": 0.5, "percentile": "0.5", "date": "x"}]),
            id="score-not-a-string",
        ),
        pytest.param(
            response([{"cve": "CVE-2099-0001", "epss": "0.5", "percentile": "0.5"}]),
            id="missing-date",
        ),
    ],
)
def test_malformed_response_fails_and_is_not_cached(tmp_path: Path, body: bytes) -> None:
    with pytest.raises(EnrichmentError):
        load_epss(["CVE-2099-0001"], cache_at(tmp_path), FixedResponse(body), offline=False)
    assert not (tmp_path / "epss.json").exists()


def test_large_batch_with_no_rows_looks_like_the_silent_failure(tmp_path: Path) -> None:
    ids = [f"CVE-2099-{index:04}" for index in range(MIN_IDS_FOR_EMPTY_RESPONSE_ERROR)]

    with pytest.raises(EnrichmentError, match="no rows"):
        load_epss(ids, cache_at(tmp_path), FixedResponse(response([])), offline=False)


def test_small_batch_with_no_rows_is_just_not_scored(tmp_path: Path) -> None:
    ids = [f"CVE-2099-{index:04}" for index in range(MIN_IDS_FOR_EMPTY_RESPONSE_ERROR - 1)]

    epss = load_epss(ids, cache_at(tmp_path), FixedResponse(response([])), offline=False)

    assert all(epss.lookup(vuln_id).state is EpssState.NOT_SCORED for vuln_id in ids)


def test_rows_for_ids_not_requested_are_ignored(tmp_path: Path) -> None:
    body = response([row("CVE-2099-0001"), row("CVE-2099-9999")])

    epss = load_epss(["CVE-2099-0001"], cache_at(tmp_path), FixedResponse(body), offline=False)

    assert set(epss.entries) == {"CVE-2099-0001"}


def test_failing_second_batch_fails_everything_and_writes_nothing(tmp_path: Path) -> None:
    class FailsOnSecond(FakeApi):
        def fetch(self, url: str, max_bytes: int) -> bytes:
            if self.calls:
                raise EnrichmentError("down")
            return super().fetch(url, max_bytes)

    ids = [f"CVE-2099-{index:04}" for index in range(150)]

    with pytest.raises(EnrichmentError):
        load_epss(ids, cache_at(tmp_path), FailsOnSecond(score_all=True), offline=False)
    assert not (tmp_path / "epss.json").exists()


def test_errors_do_not_echo_response_content(tmp_path: Path) -> None:
    body = response([row("SENTINEL", "SENTINEL")])

    with pytest.raises(EnrichmentError) as excinfo:
        load_epss(["CVE-2099-0001"], cache_at(tmp_path), FixedResponse(body), offline=False)

    assert "SENTINEL" not in str(excinfo.value)


def test_cached_ids_are_not_requested_again(tmp_path: Path) -> None:
    load_epss(["CVE-2099-0001"], cache_at(tmp_path), FakeApi(score_all=True), offline=False)
    api = FakeApi(score_all=True)

    epss = load_epss(["CVE-2099-0001", "CVE-2099-0002"], cache_at(tmp_path), api, offline=False)

    assert api.requested == [["CVE-2099-0002"]]
    assert epss.lookup("CVE-2099-0001").state is EpssState.SCORED


def test_not_scored_results_are_cached_too(tmp_path: Path) -> None:
    load_epss(["CVE-2099-0001"], cache_at(tmp_path), FakeApi(), offline=False)
    api = FakeApi(score_all=True)

    epss = load_epss(["CVE-2099-0001"], cache_at(tmp_path), api, offline=False)

    assert api.calls == []
    assert epss.lookup("CVE-2099-0001").state is EpssState.NOT_SCORED


def test_expired_entries_are_refreshed_and_others_kept(tmp_path: Path) -> None:
    load_epss(["CVE-2099-0001"], cache_at(tmp_path), FakeApi(score_all=True), offline=False)
    half = NOW + MAX_AGE / 2
    load_epss(["CVE-2099-0002"], cache_at(tmp_path, half), FakeApi(score_all=True), offline=False)
    api = FakeApi(score_all=True)
    later = NOW + MAX_AGE + timedelta(seconds=1)

    epss = load_epss(
        ["CVE-2099-0001", "CVE-2099-0002"], cache_at(tmp_path, later), api, offline=False
    )

    assert api.requested == [["CVE-2099-0001"]]
    assert epss.retrieved_at("CVE-2099-0001") == later
    assert epss.retrieved_at("CVE-2099-0002") == half


def test_expired_cache_with_failed_refresh_fails_and_offers_offline(tmp_path: Path) -> None:
    load_epss(["CVE-2099-0001"], cache_at(tmp_path), FakeApi(score_all=True), offline=False)
    later = NOW + MAX_AGE + timedelta(hours=1)

    with pytest.raises(EnrichmentError, match="--offline"):
        load_epss(["CVE-2099-0001"], cache_at(tmp_path, later), Failing(), offline=False)


def test_failure_with_a_missing_id_does_not_offer_offline(tmp_path: Path) -> None:
    with pytest.raises(EnrichmentError) as excinfo:
        load_epss(["CVE-2099-0001"], cache_at(tmp_path), Failing(), offline=False)

    assert str(excinfo.value) == "down"


def test_offline_with_full_cache_uses_no_network(tmp_path: Path) -> None:
    load_epss(["CVE-2099-0001"], cache_at(tmp_path), FakeApi(score_all=True), offline=False)
    api = FakeApi()
    cache = cache_at(tmp_path)

    epss = load_epss(["CVE-2099-0001"], cache, api, offline=True)

    assert api.calls == []
    assert epss.lookup("CVE-2099-0001").stale is False
    assert cache.warnings == []


def test_offline_without_cache_fails_clearly(tmp_path: Path) -> None:
    api = FakeApi()

    with pytest.raises(EnrichmentError, match="not in the cache"):
        load_epss(["CVE-2099-0001"], cache_at(tmp_path), api, offline=True)
    assert api.calls == []


def test_offline_with_one_id_missing_fails_and_counts_without_listing(tmp_path: Path) -> None:
    load_epss(["CVE-2099-0001"], cache_at(tmp_path), FakeApi(score_all=True), offline=False)

    with pytest.raises(EnrichmentError) as excinfo:
        load_epss(["CVE-2099-0001", "CVE-2099-0002"], cache_at(tmp_path), FakeApi(), offline=True)

    assert "for 1 CVE ids" in str(excinfo.value)
    assert "CVE-2099-0002" not in str(excinfo.value)


def test_offline_with_expired_cache_warns_and_marks_only_expired_ids_stale(tmp_path: Path) -> None:
    load_epss(["CVE-2099-0001"], cache_at(tmp_path), FakeApi(score_all=True), offline=False)
    half = NOW + MAX_AGE / 2
    load_epss(["CVE-2099-0002"], cache_at(tmp_path, half), FakeApi(score_all=True), offline=False)
    cache = cache_at(tmp_path, NOW + MAX_AGE + timedelta(seconds=1))

    epss = load_epss(["CVE-2099-0001", "CVE-2099-0002"], cache, FakeApi(), offline=True)

    assert epss.lookup("CVE-2099-0001").stale is True
    assert epss.lookup("CVE-2099-0002").stale is False
    assert cache.warnings == ["using expired EPSS data for 1 CVE ids"]


def test_future_timestamp_counts_as_expired(tmp_path: Path) -> None:
    load_epss(["CVE-2099-0001"], cache_at(tmp_path), FakeApi(score_all=True), offline=False)
    api = FakeApi(score_all=True)

    load_epss(["CVE-2099-0001"], cache_at(tmp_path, NOW - timedelta(minutes=1)), api, offline=False)

    assert api.requested == [["CVE-2099-0001"]]


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param({"retrieved_at": "2099-01-15T12:00:00Z", "score": 5.0}, id="score-above-one"),
        pytest.param({"retrieved_at": "not a date"}, id="bad-timestamp"),
        pytest.param({"score": 0.5}, id="missing-timestamp"),
    ],
)
def test_tampered_cache_is_not_trusted(tmp_path: Path, entry: dict[str, Any]) -> None:
    (tmp_path / "epss.json").write_text(
        json.dumps({"entries": {"CVE-2099-0001": entry}}), encoding="utf-8"
    )
    api = FakeApi({"CVE-2099-0001": "0.200000000"})

    epss = load_epss(["CVE-2099-0001"], cache_at(tmp_path), api, offline=False)

    assert api.requested == [["CVE-2099-0001"]]
    assert epss.lookup("CVE-2099-0001").score == 0.2
