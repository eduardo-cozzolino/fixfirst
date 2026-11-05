# 0001: Foundation

Status: accepted

## Context

fixfirst will combine scanner output, public threat intelligence, computed network exposure and a
controlled AI agent to decide what to fix first, with evidence for every decision. This first step
builds only the base those features depend on: read Trivy JSON, normalize it, map findings to assets,
deduplicate and print a summary.

## Data model

Scanner formats stay at the edge. `ingest/trivy.py` has private models that mirror Trivy's JSON and
ignore unknown fields, so a new Trivy release does not break parsing. Everything after that step uses
`Finding` and `Asset`, which reject unknown fields, so a typo in the inventory fails instead of being
ignored.

- **Decisions never depend on text.** Logic reads enum values and identifiers only. `title` is
  display-only, and no code branches on the text of an error message. `data_classification` is an
  enum for the same reason.
- **Severity order is explicit.** `Severity.rank` defines the order, because comparing the enum's
  strings would put `HIGH` below `LOW`.
- **`internet_exposed` has three states.** `None` means unknown and must never be read as `False`. The
  value is declared by hand for now and will be computed in a later version.
- **`installed_version` can be unknown.** A missing, null or empty version in a report becomes `None`,
  and JSON output shows it as `null`.
- **`Finding.artifacts` records provenance.** Without it, a finding in both a matched and an unmatched
  artifact would look fully assigned, because `asset_ids` alone would not show the unmatched artifact.
  It is also the start of the evidence trail.
- **`ecosystem` is Trivy's raw `Results[].Type`.** Mapping to OSV ecosystem names belongs to the step
  that introduces OSV.
- **`Finding.pkg_paths` records where copies are installed.** It comes from Trivy's `PkgPath` and is
  empty when there is none, as for OS packages. After a merge across artifacts it does not show which
  artifact holds which path.
- **`Finding.fix_status` keeps every status seen.** It comes from Trivy's `Status`, because a missing
  `FixedVersion` alone cannot separate `affected` from `fix_deferred`. It is a set because merged
  copies can report different statuses, and a missing status is `unknown`. Scoring will use it in a
  later step; nothing reads it yet. The enum has the eight values Trivy defines, including
  `not_affected`. Any other string becomes `unknown`, the finding is kept and one warning per distinct
  value goes to stderr. A new status value should not block a whole run, and the finding is still
  reported, so nothing is hidden. Severity stays strict: an unrecognized severity rejects the report.
- **`Results[].Target` is not stored.** It names what was scanned, such as `Python` for all language
  packages in an image, while `pkg_paths` gives the location of each package.

## Reports are untrusted

Report size is limited on the bytes actually read. Bytes are passed to the JSON parser so that BOMs and
UTF-16 are detected, which matters because Windows PowerShell 5.1 redirection writes UTF-16. Parse
failures, including excessive nesting, become an `InputError` and exit code 2.

Parsing is all or nothing. One bad entry rejects the whole run, because skipping it could silently hide
a real vulnerability. The one exception is an unrecognized `Status` string, where the entry is kept
rather than skipped. A `Status` that is not a string is still a schema error.

Error messages do not repeat values from the report, `PrimaryURL` is kept only for http(s) URLs, and
output escapes control and format characters that could manipulate a terminal. The status warning has
to show the value it warns about, so it escapes the value and shortens it to 80 characters.

## Why the inventory uses globs

A scanned artifact name such as `registry.example.com/shop/api:1.4.2` changes with every release, while
the asset behind it does not. A glob such as `registry.example.com/shop/api:*` describes that stable
identity in a line that is easy to write and review. Globs are also less error-prone than regular
expressions, and evaluating them needs no extra dependency.

Matching uses `fnmatch.fnmatchcase`, because `fnmatch.fnmatch` folds case and rewrites slashes on
Windows only, which would make results depend on the operating system. Patterns must match the whole
artifact name, and `*` also matches `/`. An artifact may match several assets.

Artifacts that match nothing are listed as unassigned in both text and JSON output, even when they have
no findings. An inventory gap must stay visible, not disappear from the results.

## Why deduplication works this way

A Trivy report describes exactly one artifact, so the CLI accepts several reports. The same vulnerable
package version usually appears in many artifacts, so findings with the same
`(vuln_id, ecosystem, package, installed_version)` become one finding, giving one view of the problem
rather than one row per image.

A merged finding is not a single fix. It can cover several installed copies that must each be fixed,
in different artifacts or at different paths in one artifact. For example, `wheel` can be installed at
the top level of an image and also vendored inside `setuptools`, where upgrading one does not fix the
other. `artifacts`, `asset_ids` and `pkg_paths` show what is covered.

`ecosystem` is part of the key because distinct ecosystems can share a package name and version string.
Debian and Ubuntu do this when Ubuntu syncs a package unchanged, and either may have a fix that the
other lacks. Merging those would report a fix that does not exist for one of the assets.

The accepted cost is over-counting. Trivy uses several types for one real ecosystem, such as `pip` and
`python-pkg`, so the same package found both ways stays as two findings until types are normalized. Two
findings where one would do is the safer failure for a triage tool, compared with a wrong "fix
available".

When `installed_version` is `None`, the artifact name also becomes part of the key. Findings with an
unknown version merge only within the same artifact, and never with a finding whose version is known.
Two unknown versions in different artifacts may in reality differ, so merging them could claim that a
single fix covers both. The cost is again over-counting: one package with an unknown version in five
artifacts is five findings, and over-counting is the safer failure. Known versions are not affected.

Merging does not depend on input order:

| Field | Rule |
|---|---|
| `asset_ids`, `artifacts`, `pkg_paths`, `fixed_versions`, `fix_status` | union |
| `scanner_severity` | highest rank |
| `title`, `primary_url` | first non-empty value, in sorted artifact order |

Findings are sorted by severity, highest first, and then by key, and sets are serialized sorted, so
identical input gives identical output.

## Out of scope for this step

- Network calls and enrichment from NVD, CISA KEV, FIRST EPSS or OSV
- Computed network exposure
- Scoring, prioritization and any AI agent
- Scanners other than Trivy, and report formats other than a single-artifact Trivy report, such as
  `trivy k8s`
- Version comparison: `fixed_versions` is sorted for reproducible output only, and that order says
  nothing about which version is newer
- Normalizing ecosystem names
- Failing a build based on findings: exit code 0 means the run succeeded, whatever it found
