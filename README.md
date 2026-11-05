# fixfirst

An exposure-aware vulnerability triage tool. It reads scanner output, maps findings to the assets
in an inventory file and removes duplicates, as the basis for deciding what to fix first.

**Status: early development.** Only the foundation exists today: Trivy JSON ingestion, asset mapping,
deduplication and a summary. It makes no network calls. See
[docs/decisions/0001-foundation.md](docs/decisions/0001-foundation.md) for the design and scope.

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
