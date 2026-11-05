from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import AwareDatetime, BaseModel

from fixfirst.enrich import cache as cache_module
from fixfirst.enrich.cache import MAX_AGE, Cache, default_cache_dir
from fixfirst.errors import InputError

NOW = datetime(2099, 1, 15, 12, tzinfo=UTC)


class Sample(BaseModel):
    value: int
    at: AwareDatetime


def make_cache(directory: Path) -> Cache:
    return Cache(directory, lambda: NOW)


def test_round_trip_creates_the_directory(tmp_path: Path) -> None:
    cache = make_cache(tmp_path / "nested" / "dir")

    cache.save("sample.json", Sample(value=7, at=NOW))

    assert cache.load("sample.json", Sample) == Sample(value=7, at=NOW)
    assert cache.warnings == []


def test_missing_file_is_none(tmp_path: Path) -> None:
    assert make_cache(tmp_path).load("absent.json", Sample) is None


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(b"{not json", id="malformed"),
        pytest.param(b'{"value": "seven", "at": "2099-01-15T12:00:00Z"}', id="wrong-type"),
        pytest.param(b'{"value": 7, "at": "2099-01-15T12:00:00"}', id="naive-timestamp"),
        pytest.param(b"", id="empty"),
    ],
)
def test_invalid_file_counts_as_missing(tmp_path: Path, content: bytes) -> None:
    (tmp_path / "sample.json").write_bytes(content)

    assert make_cache(tmp_path).load("sample.json", Sample) is None


def test_oversized_file_counts_as_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = make_cache(tmp_path)
    cache.save("sample.json", Sample(value=7, at=NOW))
    monkeypatch.setattr(cache_module, "MAX_CACHE_FILE_BYTES", 5)

    assert cache.load("sample.json", Sample) is None


def test_failed_write_warns_and_leaves_no_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*args: object) -> None:
        raise PermissionError

    monkeypatch.setattr(Path, "replace", fail)
    cache = make_cache(tmp_path)

    cache.save("sample.json", Sample(value=7, at=NOW))

    assert len(cache.warnings) == 1
    assert "cannot write cache file" in cache.warnings[0]
    assert list(tmp_path.iterdir()) == []


def test_unusable_directory_warns(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    cache = make_cache(blocker / "dir")

    cache.save("sample.json", Sample(value=7, at=NOW))

    assert len(cache.warnings) == 1


def test_failed_write_keeps_the_previous_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = make_cache(tmp_path)
    cache.save("sample.json", Sample(value=1, at=NOW))

    def fail(*args: object) -> None:
        raise PermissionError

    monkeypatch.setattr(Path, "replace", fail)
    cache.save("sample.json", Sample(value=2, at=NOW))
    monkeypatch.undo()

    assert cache.load("sample.json", Sample) == Sample(value=1, at=NOW)


@pytest.mark.parametrize(
    ("age", "fresh"),
    [
        pytest.param(timedelta(0), True, id="now"),
        pytest.param(MAX_AGE, True, id="exactly-max-age"),
        pytest.param(MAX_AGE + timedelta(seconds=1), False, id="just-expired"),
        pytest.param(timedelta(seconds=-1), False, id="future-timestamp"),
    ],
)
def test_freshness(tmp_path: Path, age: timedelta, fresh: bool) -> None:
    assert make_cache(tmp_path).is_fresh(NOW - age) is fresh


def test_default_dir_uses_the_platform_location(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cache_module.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(Path("base")))
    assert default_cache_dir() == Path("base") / "fixfirst"


def test_default_dir_on_windows_without_the_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cache_module.sys, "platform", "win32")
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert default_cache_dir() == tmp_path / "AppData" / "Local" / "fixfirst"


def test_default_dir_on_macos(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cache_module.sys, "platform", "darwin")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert default_cache_dir() == tmp_path / "Library" / "Caches" / "fixfirst"


def test_default_dir_on_linux_honours_absolute_xdg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cache_module.sys, "platform", "linux")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert default_cache_dir() == tmp_path / "fixfirst"


@pytest.mark.parametrize("value", ["relative/path", ""])
def test_default_dir_on_linux_ignores_relative_or_empty_xdg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setattr(cache_module.sys, "platform", "linux")
    monkeypatch.setenv("XDG_CACHE_HOME", value)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert default_cache_dir() == tmp_path / ".cache" / "fixfirst"


def test_default_dir_without_a_home_directory_is_an_input_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_home() -> Path:
        raise RuntimeError

    monkeypatch.setattr(cache_module.sys, "platform", "linux")
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setattr(Path, "home", no_home)

    with pytest.raises(InputError, match="--cache-dir"):
        default_cache_dir()
