# 0002: Triage: from findings to priorities

Status: accepted

## Context

ADR 0001 built the base: normalized, deduplicated findings mapped to assets. This step adds
`fixfirst triage`, which orders findings by priority P1 to P4, each with the rule that decided it and
the evidence behind it. All rules from ADR 0001 still apply. `fix_status`, which ADR 0001 said nothing
read yet, is now read by the rules.

## Enrichment

| Data | Source | Use |
|---|---|---|
| Known exploitation | CISA KEV JSON feed, downloaded whole | Rules |
| Exploit probability | FIRST EPSS API, queried by CVE id | Rules |
| CVSS | The `CVSS` field of the Trivy report | Evidence only |

**No NVD calls.** NVD's public API is rate limited, and the data is already present: in a real scan of
`python:3.9-slim`, 470 of 492 report entries carried CVSS scores.

**CVSS does not change a priority.** The rules use scanner severity and EPSS. The score is recorded with
its source and version so that a reader can see it. Selection is deterministic: V3 before V4.0 before V2,
and within a version nvd, then the vendor named by `SeveritySource`, then other vendors alphabetically. In
that scan nvd had a V3 score on only 100 entries, so most scores come from a vendor. A merged finding
prefers nvd and then the highest score. Trivy writes whole scores as integers, so the parser accepts both.

**Only CVE ids are looked up.** An id must fully match `CVE-[0-9]{4}-[0-9]{4,7}`. Ids come from untrusted
reports and end up in request URLs, so anything else is never sent. The length cap also stops a crafted id
from pushing a request over the silent limit below. `TEMP-`, `DSA-`, `GHSA-` and similar ids get the state
`not_applicable`, and the output says so.

**Absence is never a value.** KEV has the states `listed`, `not_listed` and `not_applicable`. EPSS has
`scored`, `not_scored` and `not_applicable`. A CVE without an EPSS score is not a score of zero, and a
non-CVE id is not "not exploited". The rules simply cannot match on data that does not exist, and the
output marks those findings.

### The EPSS API fails silently

These were measured against the live service, and the design depends on them:

- A `cve` parameter of more than about 2,000 characters returns HTTP 200, `status: OK`, `total: 0` and no
  rows. This looks exactly like "nothing is scored".
- More than 100 ids return the first 100 rows, with `total` above the number of rows.
- An unknown or invalid id is left out of the response, with no error.
- Scores are strings.

So batches hold at most 100 ids and 1,900 characters, and a response whose `total` differs from its row
count is an error. A batch of 20 or more ids with no rows at all is also an error, because that is what the
silent failure looks like if the limit ever changes.

KEV has the same risk in another form: an empty or cut-off feed must never read as "nothing is exploited".
A feed whose `count` differs from its entries, or that has no entries, is rejected.

### HTTP

HTTP uses the standard library through an injectable `Fetcher`, so tests stay offline. An autouse test
fixture blocks real connections, so a stray request fails rather than passing by accident.

- TLS verification and host name checks are on, and only https URLs are allowed.
- Redirects are refused, because following one could change host or downgrade TLS. Neither endpoint
  redirects.
- There is a socket timeout and an overall deadline, because a socket timeout alone does not stop a slow
  trickle of data.
- Response size is limited on the bytes actually read, and compression is not requested, so a small
  response cannot expand past the limit.
- The User-Agent is `fixfirst/<version>` and carries no personal data.
- Responses are untrusted: they are validated with Pydantic, one malformed entry rejects the whole
  response, and error messages do not repeat response content.

### What leaves the machine

An online `triage` tells FIRST which CVE ids you have, from your IP address. That is inherent to querying
the API. Downloading KEV is one whole file and reveals nothing about you. Package names, versions, asset
names and artifact names are never sent. `--offline` sends nothing.

### Cache

The default location is the per-user cache directory, found with the standard library, or `--cache-dir`.
Only validated, trimmed data is stored, so third-party description text does not end up on disk. EPSS
results are cached per CVE, including `not_scored` results, so that they are not requested again.

Cache files are untrusted like any other file. One that is too large or not valid counts as missing, and a
timestamp in the future counts as expired. Writes are atomic. A failed write only warns, because the data in
memory is still valid.

The maximum age is 24 hours for both sources:

| Situation | Result |
|---|---|
| Fresh cache | Used, with no request |
| Expired or missing, online | Refreshed |
| Expired, online, and the refresh fails | Exit 3, and the message offers `--offline` |
| Expired, `--offline` | Used, with a warning, and the evidence is marked `stale` |
| Missing or corrupt, `--offline` | Exit 3 |

Expired data under-counts if something has since been added to KEV, so it is never used silently. Offline,
the user has opted in explicitly and the timestamps stay visible.

## Evidence

`Evidence(id, source, retrieved_at, data)`, with typed `data` for each source. Ids are deterministic:
`kev:<id>`, `epss:<id>`, `asset:<id>`, `artifact:<name>` and `finding:<hash of the dedup key>`.

Every decision cites the finding, KEV and EPSS evidence, because the rules above the deciding one were all
checked against them. "Not in KEV" is evidence too, with the catalog version and retrieval time. Asset or
artifact evidence is cited only when the deciding rule read exposure or criticality.

`retrieved_at` is empty for reports and inventories, which are read rather than retrieved. A timestamp of the
run would add nothing and would make identical runs differ.

## Rules

An ordered table in `rules.py`, where the first match wins. Rule ids are stable and leave out the priority, so
that they stay valid if a rule ever moves. No rule reads display text.

| Order | Rule id | Priority | Condition |
|---|---|---|---|
| 0 | `not-affected` | P4 | every `fix_status` is `not_affected` |
| 1 | `kev-exposed` | P1 | in KEV, and exposure is not `not_exposed` |
| 2 | `epss-exposed` | P1 | EPSS >= 0.5, severity HIGH, CRITICAL or UNKNOWN, and exposure is not `not_exposed` |
| 3 | `kev` | P2 | in KEV |
| 4 | `epss-severe` | P2 | EPSS >= 0.1, severity HIGH, CRITICAL or UNKNOWN |
| 5 | `critical-on-critical-asset` | P2 | CRITICAL on an asset with high or critical criticality, or an unassigned artifact |
| 6 | `severe` | P3 | HIGH or CRITICAL |
| 7 | `medium-epss` | P3 | MEDIUM with EPSS >= 0.05 |
| 8 | `unknown-with-fix` | P3 | UNKNOWN with a fix available |
| 9 | `unknown-no-fix` | P3 | UNKNOWN |
| 10 | `default` | P4 | everything else |

### Thresholds

`EPSS_CRITICAL = 0.5`, `EPSS_ELEVATED = 0.1` and `EPSS_MEDIUM = 0.05`, all inclusive. These are judgment calls
for a first version, not values derived from data. They are named constants so that they are easy to find and
to challenge.

### Why the rules look like this

**Over-counting is the safer failure, as in ADR 0001.** Where something is unknown, the rules assume the worse
case and say so:

- Unknown exposure or an unassigned artifact counts as exposed, and the output says `exposure assumed`.
- An unassigned artifact has no known criticality either, so it qualifies for
  `critical-on-critical-asset`, and the output says `criticality assumed`.
- Those notes appear only when the deciding rule relied on the assumption.

**Merged findings take the worst case.** A finding can cover several assets. Any exposed asset makes it
`exposed`; otherwise any unknown exposure or unassigned artifact makes it `assumed`. Any high or critical asset
qualifies it for the criticality rule.

**UNKNOWN severity must never read as low risk.** The EPSS rules treat UNKNOWN like HIGH, and every UNKNOWN
finding reaches at least P3. `unknown-with-fix` and `unknown-no-fix` have the same priority but stay separate
rules, so that the output shows whether a fix exists.

**`not_affected` overrides everything, but only when every status agrees.** It is checked first, so a KEV entry
marked `not_affected` goes to P4 with its own rule id. `fix_status` is a set after merging, and a finding with
`{not_affected, affected}` has at least one affected copy, so it uses the normal rules. A report can lower a
priority this way, which is why the rule id is always visible.

**A fix is available** when `fixed_versions` is not empty or `fix_status` includes `fixed`. Versions are still
not compared.

## Output and exit codes

Input files are checked before any request, so a bad file never causes network traffic. Findings are ordered by
priority, severity, EPSS score (with no score last) and identity. `--top N` limits the listing, and the summary
still counts everything.

| Exit code | Meaning |
|---|---|
| 0 | Success, whatever was found |
| 2 | Input error |
| 3 | Required enrichment data is unavailable, with no partial output |

If there are no CVE ids at all, no enrichment is needed, so the run succeeds without data or network.

## Out of scope for this step

- NVD
- The AI agent
- Computed network exposure: `internet_exposed` is still declared by hand
- OSV and other sources
- Looking up the CVE aliases of non-CVE ids
- Grouping findings by fix: three binary packages from one source package are three findings
- Using CVSS scores in rules
- Failing a build based on priority
