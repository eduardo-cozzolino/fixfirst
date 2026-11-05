# fixfirst

An exposure-aware vulnerability triage tool. It reads scanner output, maps findings to the assets
in an inventory file and removes duplicates, as the basis for deciding what to fix first.

**Status: early development.** Only the foundation exists today: Trivy JSON ingestion, asset mapping,
deduplication and a summary. It makes no network calls. See
[docs/decisions/0001-foundation.md](docs/decisions/0001-foundation.md) for the design and scope.

## Example

Text summary from a real scan with Trivy 0.76.1. Counts change as the vulnerability database updates.

```console
trivy image --format json -o report.json python:3.9-slim
fixfirst ingest report.json --assets examples/assets.yaml
```

```text
Findings by severity:
  CRITICAL  6
  HIGH      125
  MEDIUM    193
  LOW       158
  UNKNOWN   9
Unique findings:      491
Assets affected:      0
Unassigned artifacts: 1
  python:3.9-slim
```

The artifact is listed as unassigned because no glob in `examples/assets.yaml` matches
`python:3.9-slim`; its findings are still reported, just not attributed to any asset.

## Usage

Requires Python 3.12 or newer.

```console
pip install .
fixfirst ingest REPORT.json [REPORT.json ...] --assets examples/assets.yaml [--json]
```

Each Trivy report describes one artifact, so pass several reports to deduplicate across artifacts.

Exit codes: `0` for a successful run, whatever the findings are, and `2` for an input error.

## Running the tests

```console
pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy --strict src
pytest
```

The tests run fully offline.

## License

[MIT](LICENSE)

## About

Designed and reviewed by Eduardo Cozzolino as a portfolio project in
security engineering and AI-assisted vulnerability triage. Implemented with
the help of Claude Code under explicit design decisions recorded in
docs/decisions; every module is covered by tests.
