"""Helpers shared by the code that reads input files."""

from pathlib import Path

from pydantic import ValidationError

from fixfirst.errors import InputError

_MAX_REPORTED_ERRORS = 5


def read_limited(path: Path, max_bytes: int) -> bytes:
    """Return the content of ``path``, failing if it is larger than ``max_bytes``.

    The limit is enforced on the bytes actually read, not on file metadata, so it also holds for
    special files and for files that grow while being read.
    """
    try:
        with path.open("rb") as stream:
            data = stream.read(max_bytes + 1)
    except OSError as exc:
        raise InputError(f"{path}: cannot read file ({type(exc).__name__})") from exc
    if len(data) > max_bytes:
        raise InputError(f"{path}: file exceeds the {max_bytes} byte limit")
    return data


def describe_validation_error(exc: ValidationError) -> str:
    """Summarize a validation error without echoing the rejected input values."""
    errors = exc.errors(include_input=False, include_url=False, include_context=False)
    parts = [
        f"{'.'.join(str(item) for item in error['loc']) or '<root>'}: {error['msg']}"
        for error in errors[:_MAX_REPORTED_ERRORS]
    ]
    hidden = len(errors) - len(parts)
    if hidden > 0:
        parts.append(f"and {hidden} more")
    return "; ".join(parts)
