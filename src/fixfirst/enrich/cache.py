"""On-disk cache for enrichment data.

Cache files are untrusted input like any other file: their size is limited and their content is
validated. A file that fails either check counts as missing.
"""

import os
import sys
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel, ValidationError

from fixfirst._input import read_limited
from fixfirst.errors import InputError

MAX_AGE = timedelta(hours=24)
MAX_CACHE_FILE_BYTES = 32 * 1024 * 1024


def default_cache_dir() -> Path:
    """Return the per-user cache directory for this platform.

    Raises:
        InputError: The home directory cannot be determined, so ``--cache-dir`` is needed.
    """
    try:
        if sys.platform == "win32":
            base = os.environ.get("LOCALAPPDATA")
            return Path(base) / "fixfirst" if base else Path.home() / "AppData/Local/fixfirst"
        if sys.platform == "darwin":
            return Path.home() / "Library/Caches/fixfirst"
        base = os.environ.get("XDG_CACHE_HOME")
        # The XDG specification says relative paths must be ignored.
        if base and Path(base).is_absolute():
            return Path(base) / "fixfirst"
        return Path.home() / ".cache/fixfirst"
    except RuntimeError as exc:
        raise InputError("cannot determine a cache directory; use --cache-dir") from exc


def utc_now() -> datetime:
    """Return the current time."""
    return datetime.now(UTC)


class Cache:
    """Reads and writes validated models in one directory."""

    def __init__(self, directory: Path, now: Callable[[], datetime] = utc_now) -> None:
        self.directory = directory
        self.now = now
        # For display on stderr. Nothing may branch on their text.
        self.warnings: list[str] = []

    def load[M: BaseModel](self, name: str, model: type[M]) -> M | None:
        """Return a cached model, or None if the file is missing or not valid."""
        try:
            return model.model_validate_json(
                read_limited(self.directory / name, MAX_CACHE_FILE_BYTES)
            )
        except (InputError, ValidationError):
            return None

    def save(self, name: str, value: BaseModel) -> None:
        """Write a model atomically. A failure only warns, because the data in memory is valid."""
        temporary: Path | None = None
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(dir=self.directory, suffix=".tmp")
            temporary = Path(temporary_name)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(value.model_dump_json().encode("utf-8"))
            temporary.replace(self.directory / name)
        except OSError as exc:
            self.warnings.append(
                f"cannot write cache file {self.directory / name} ({type(exc).__name__})"
            )
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def is_fresh(self, retrieved_at: datetime) -> bool:
        """Return whether data is recent enough. A timestamp in the future is never fresh."""
        now = self.now()
        return retrieved_at <= now and now - retrieved_at <= MAX_AGE
