"""Load the asset inventory and map scanned artifacts to assets."""

from collections.abc import Iterable, Sequence
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from fixfirst._input import describe_validation_error, read_limited
from fixfirst.errors import InputError
from fixfirst.models import Asset, Finding, ParsedReport

MAX_INVENTORY_BYTES = 1024 * 1024


class _Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    assets: list[Asset]

    @model_validator(mode="after")
    def _check_unique_ids(self) -> Self:
        seen: set[str] = set()
        for asset in self.assets:
            if asset.id in seen:
                raise ValueError(f"duplicate asset id: {asset.id}")
            seen.add(asset.id)
        return self


def load_assets(path: Path, max_bytes: int = MAX_INVENTORY_BYTES) -> list[Asset]:
    """Read and validate an inventory file.

    Raises:
        InputError: The file cannot be read, is too large, or is not a valid inventory.
    """
    raw = read_limited(path, max_bytes)
    try:
        data: object = yaml.safe_load(raw)
    except yaml.MarkedYAMLError as exc:
        location = f" at line {exc.problem_mark.line + 1}" if exc.problem_mark else ""
        raise InputError(f"{path}: invalid YAML{location}") from exc
    except yaml.YAMLError as exc:
        raise InputError(f"{path}: invalid YAML") from exc
    except RecursionError as exc:
        raise InputError(f"{path}: invalid YAML (nested too deeply)") from exc

    try:
        return _Inventory.model_validate(data).assets
    except ValidationError as exc:
        raise InputError(f"{path}: invalid inventory: {describe_validation_error(exc)}") from exc


def match_assets(artifact_name: str, assets: Iterable[Asset]) -> set[str]:
    """Return the ids of all assets with a glob matching the full artifact name.

    Matching uses ``fnmatchcase`` because ``fnmatch`` folds case and rewrites slashes on Windows
    only, which would make the result depend on the operating system. ``*`` also matches ``/``.
    """
    return {
        asset.id
        for asset in assets
        if any(fnmatchcase(artifact_name, pattern) for pattern in asset.match)
    }


def assign_assets(
    reports: Iterable[ParsedReport], assets: Sequence[Asset]
) -> tuple[list[Finding], list[str]]:
    """Attach asset ids to the findings of each report.

    Returns:
        The findings with their asset ids, and the sorted names of the artifacts that matched no
        asset. An unmatched artifact is listed even when it has no findings.
    """
    findings: list[Finding] = []
    unassigned: set[str] = set()
    for report in reports:
        asset_ids = match_assets(report.artifact_name, assets)
        if not asset_ids:
            unassigned.add(report.artifact_name)
        findings.extend(
            finding.model_copy(update={"asset_ids": asset_ids}) for finding in report.findings
        )
    return findings, sorted(unassigned)
