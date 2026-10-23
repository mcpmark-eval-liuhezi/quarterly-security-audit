# quarterly-security-audit

Home of the quarterly security audit for the **HeziLiu** GitHub account.

## What this repository holds

- **`security-audit.md`** — the quarterly report, published via pull request. It contains three parts:
  1. **Repository Inventory** — every repository under the account, with its default branch, visibility, type (source or fork), primary language and last push date.
  2. **Secret Scanning Findings** — the per-repository result of secret scanning alert checks, for both open and resolved alerts.
  3. **Advisory Highlights** — the most severe current critical/high severity advisories for Python (pip) packages, including a deep dive on the most severe.
- **Recommendations** — the prioritized action list for the coming quarter, also inside the report.

## How the report is produced

- The report is drafted on the `audit-report` branch and merged into `main` via pull request once reviewed.
- Repository inventory and default branches are read from the GitHub API and confirmed against each repository's branch list.
- Advisory data is drawn from the GitHub global security advisory database, filtered to the `pip` ecosystem at critical and high severity.

## Current quarter status

| Section | Status |
|---------|--------|
| Repository inventory | Complete — 4 repositories |
| Secret scanning checks | Attempted — API returned 403 on all repositories, so posture is **unknown** rather than clean; re-run with an adequately scoped token |
| Advisory highlights | Complete — 3 advisories, one deep dive |

## Reporting cadence

This audit is refreshed quarterly. The next review is due in January.
