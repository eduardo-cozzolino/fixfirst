# fixfirst

An exposure-aware vulnerability triage tool. It reads scanner output, maps findings to the assets
in an inventory file, removes duplicates and decides what to fix first, with the rule and the
evidence behind every decision.

**Status: v0.1.** Ingests Trivy JSON, enriches findings with CISA KEV and FIRST EPSS, and assigns
P1-P4 priorities with the rule and evidence behind each decision. See docs/decisions for the design.

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

The same report through `triage`, with live KEV and EPSS data. Each line shows the priority, id,
package, installed version, fix, assets and the rule that decided it:

```console
fixfirst triage report.json --assets examples/assets.yaml --top 5
```

```text
P1  CVE-2025-15467  libssl3t64  3.5.1-1+deb13u1  fix:3.5.4-1~deb13u2  assets:unassigned  rule:epss-exposed  [exposure assumed]
P1  CVE-2025-15467  openssl  3.5.1-1+deb13u1  fix:3.5.4-1~deb13u2  assets:unassigned  rule:epss-exposed  [exposure assumed]
P1  CVE-2025-15467  openssl-provider-legacy  3.5.1-1+deb13u1  fix:3.5.4-1~deb13u2  assets:unassigned  rule:epss-exposed  [exposure assumed]
P2  CVE-2026-8376  perl-base  5.40.1-6  fix:5.40.1-6+deb13u1  assets:unassigned  rule:critical-on-critical-asset  [criticality assumed]
P2  CVE-2026-42496  perl-base  5.40.1-6  fix:5.40.1-6+deb13u1  assets:unassigned  rule:critical-on-critical-asset  [criticality assumed]

Priority summary:
  P1  3
  P2  6
  P3  134
  P4  348
Findings: 491 (showing 5)
Unassigned artifacts: 1
  python:3.9-slim
```

Unknown exposure and criticality count as the worse case, and the output says so, because
over-counting is the safer failure. Add `--json` to get the evidence behind each decision.

## Usage

Requires Python 3.12 or newer.

```console
pip install .
fixfirst ingest REPORT.json [REPORT.json ...] --assets examples/assets.yaml [--json]
fixfirst triage REPORT.json [REPORT.json ...] --assets examples/assets.yaml
                [--cache-dir DIR] [--offline] [--json] [--top N]
```

Each Trivy report describes one artifact, so pass several reports to deduplicate across artifacts.

`ingest` makes no network calls. `triage` downloads the CISA KEV catalog and queries the FIRST EPSS
API, and caches the results for 24 hours in your user cache directory or `--cache-dir`. Querying EPSS
tells FIRST which CVE ids you have, from your IP address; nothing else from your reports or inventory
is sent. `--offline` uses only the cache and sends nothing. Only `CVE-` ids are looked up: other ids
are marked as having no KEV or EPSS data, which never counts as "not exploited".

The rules and thresholds are in
[docs/decisions/0002-triage.md](docs/decisions/0002-triage.md).

Exit codes: `0` for a successful run, whatever the findings are, `2` for an input error, and `3` when
`triage` cannot get the enrichment data it needs.

## Running the tests

```console
pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy --strict src
pytest
```

The tests run fully offline.

## Roadmap

- Group findings that share one fix (e.g. one OpenSSL upgrade covering several packages)
- Computed network exposure from firewall rules and security groups
- An AI triage agent with an independent verifier, citation checks and prompt-injection tests

## License

[MIT](LICENSE)

## About

Designed and reviewed by Eduardo Cozzolino as a portfolio project in
security engineering and AI-assisted vulnerability triage. Implemented with
the help of Claude Code under explicit design decisions recorded in
docs/decisions; every module is covered by tests.
