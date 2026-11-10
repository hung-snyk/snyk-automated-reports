# Snyk automated reports

Builds the Snyk Analytics reports (Issues Summary, OWASP Top 10, SLA Management, …) from the
[Snyk Export API](https://docs.snyk.io/developer-tools/snyk-api/using-specific-snyk-apis/export-api-specifications-columns-and-filters),
so you can create them from the command line, on a schedule or in CI instead of from the web UI.

Output formats: `pdf` (default; the UI's "Export to PDF" layout), `csv` (every table row) and `json` (headline
numbers and tables).

## Quick start

You need Python 3.9+ and a Snyk API token (**Account settings → General → Auth Token**, or a service account token)
that can read your org or group.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file in this folder with your token and group ID (**Group settings → General**). Reports cover every
org in the group; to report on one org instead, set `SNYK_ORG_ID` and leave out the group ID, or pass `--scope org`.

```
SNYK_TOKEN=your-token
SNYK_GROUP_ID=your-group-id
```

Then build a report. This writes `reports/snyk_issues-summary_<date>.pdf`:

```bash
python3 snyk_reports.py --report issues-summary
```

## Reports

| `--report` | Default scope (same as the UI) |
|---|---|
| `analytics-overview` | key numbers, last 30 days vs. the 30 before |
| `issues-summary` | open, new and resolved issues, last 30 days vs. the 30 before; top 50 projects |
| `issues-detail` | every open issue (table only: use `--format csv` or `json`) |
| `risk-exposure` | open issues by severity, 30-day trend |
| `vulnerabilities-detail` | open issues grouped by vulnerability |
| `sla-management` | Critical and High issues against targets of 15/30/90/180 days |
| `zero-day` | the CVEs or Snyk vulnerability IDs you name with `--zero-day` |
| `owasp-top-10-2025`, `cwe-top-25-2023`, `cwe-top-10-kev-2023` | open issues introduced in the last 30 days |
| `pci-dss-v4.0.1` | open Critical issues introduced in the last 30 days |
| `prevention` | issues fixed before merge, last 90 days |
| `pr-checks-usage` | PR check results and adoption, last 30 days |
| `dev-ide-cli-usage` | IDE and CLI scans, last 30 days |
| `test-usage-in-cicd-pipelines` | repositories tested in CI/CD, last 30 days |
| `dependencies-and-licenses` | open-source dependencies and their licenses |
| `snyk-generated-prs` | pull requests Snyk opened, last 90 days; needs `--experimental` (see [Limitations](#limitations)) |

`python3 snyk_reports.py --list` prints the names.

## Usage

```bash
# several reports in one run (the data is downloaded once)
python3 snyk_reports.py --report issues-summary,sla-management,owasp-top-10-2025

# other formats
python3 snyk_reports.py --report issues-summary --format pdf,csv,json

# one org instead of the group
python3 snyk_reports.py --report issues-summary --org-id your-org-id

# a different date range (default: each report's UI range, ending today in UTC)
python3 snyk_reports.py --report issues-summary --days 90 --end 2026-09-30

# Zero-Day needs the CVEs or Snyk vulnerability IDs to track
python3 snyk_reports.py --report zero-day --zero-day CVE-2026-111497
```

**Re-running without new downloads.** Snyk allows
[20 exports per hour](https://docs.snyk.io/developer-tools/snyk-api/using-specific-snyk-apis/export-api-specifications-columns-and-filters),
and a run uses up to about 5. To try different filters or formats, save the data once and rebuild from it:

```bash
python3 snyk_reports.py --report issues-summary --save-raw                      # saves the data in reports/raw/
python3 snyk_reports.py --report issues-summary --from-raw reports/raw --format csv   # no download
```

**From a CSV you already have.** `--from-csv FILE` builds the issue-based reports from an issues file, such as the
UI's Issues Detail download. That file has open issues only, so resolved counts, time to fix and trends are incomplete.

### Filters

`--filter "COLUMN<comparison>VALUE"` narrows the reports, like the filters in the UI. Columns are the
[Export API columns](https://docs.snyk.io/developer-tools/snyk-api/using-specific-snyk-apis/export-api-specifications-columns-and-filters),
also shown as headers in `--format csv` output. Commas inside a filter mean **or**; separate filters mean **and**.

```bash
python3 snyk_reports.py --report risk-exposure \
  --filter "ISSUE_SEVERITY=Critical,High" --filter "EXPLOIT_MATURITY!=No Known Exploit" \
  --filter "PROJECT_TAGS=team:payments" --filter "FIRST_INTRODUCED<=2026-09-28"
```

| Write | Keeps rows where the column | Example |
|---|---|---|
| `COL=a,b` / `COL!=a,b` | is / isn't `a` or `b` | `PRODUCT_NAME=Snyk Open Source` |
| `COL~text` / `COL!~text` | contains / doesn't contain `text` (any case) | `PROJECT_NAME~payments` |
| `COL=LO..HI`, `COL>=LO`, `COL<=HI` | is a number or `YYYY-MM-DD` date in range | `SCORE=700..1000` |
| `COL=last7days`, `last30days`, `last90days`, `last365days`, `lastmonth`, `monthtodate`, `yeartodate` | is a date in that period | `LAST_RESOLVED=last90days` |
| `COL=` / `COL!=` | is empty / isn't empty | `CVE!=` |

- Write values as Snyk shows them (`Proof of Concept`). If one matches nothing, the script prints the values that exist.
- List columns (`CWE`, `CVE`, `PROJECT_TAGS`, …) match when any item matches. Tags are `key:value`.
- Report-specific columns: `SLA_STATUS`, `ISSUE_AGE`, `TIME_UNTIL_BREACH` (SLA Management); `SDLC_STAGE`,
  `GIT_REPO`, `GIT_BRANCH` (Prevention); `ENVIRONMENT_DISPLAY_NAME`, `INTERACTION_TARGET_ID` (usage reports);
  `DEPENDENCY_TYPE`, `IS_DEPRECATED`, `LICENSE` (Dependencies; `dockerfile` is left out unless you filter on
  `DEPENDENCY_TYPE`, as in the UI).
- Attack Vector: `SNYK_CVSS_VECTOR~AV:N` (Network), `AV:A`, `AV:L` or `AV:P`. CISA KEV: `CISA_KEV=true`.
  CVSS v4 exploit maturity: `EXPLOIT_MATURITY_CVSS_V4=Attacked` (or `Proof of Concept`, `Not Defined`).
- Ignored issues and Prevention events are left out unless you pass `--include-ignored` or filter on their status
  yourself, such as `ISSUE_STATUS=Ignored` or `IS_SUPPRESSED=true`.

### Options

Each option can also be set as the environment variable shown, or in `.env`. The command wins over variables,
and variables win over `.env`.

| Option | Env var | Default |
|---|---|---|
| `--report` | `REPORTS` | required |
| `--format pdf,csv,json` | `REPORT_FORMATS` | `pdf` |
| `--org-id` / `--group-id` | `SNYK_ORG_ID` / `SNYK_GROUP_ID` | one is required |
| `--snyk-token` | `SNYK_TOKEN` | required; prefer `.env` |
| `--scope org\|group` | `SNYK_SCOPE` | the ID in the command, else the group (the org when only an org ID is set) |
| `--region us\|eu\|au\|us2` | `SNYK_REGION` | `us` |
| `--days`, `--end` | `REPORT_DAYS` | each report's UI range, ending today |
| `--filter` | `REPORT_FILTERS` (`;`-separated) | none |
| `--zero-day CVE-…` or `SNYK-…` | `ZERO_DAY_CVE` (comma list) | none; Zero-Day is skipped |
| `--sla critical=15:3,…` (days to fix : at-risk days) | `SLA_TARGETS` | the UI's targets |
| `--severity`, `--product`, `--include-ignored` | | the UI's defaults |
| `--max-projects`, `--max-rows` (PDF table rows, `0` = all) | `REPORT_MAX_PROJECTS`, `REPORT_MAX_ROWS` | `50`, `200` |
| `--lookback-days` | | `400`; raise it for `--days` over 200 |
| `--generated-by`, `--out` | `REPORT_AUTHOR`, `REPORT_OUT` | your user name, `reports` |
| `--experimental` | `SNYK_EXPERIMENTAL=1` | off; see [Limitations](#limitations) |

Exit codes: `0` success, `1` API or input error, `2` bad arguments.

## Limitations

These are missing or partial because the Export API doesn't include their data. Most of them are available with
`--experimental`, which also reads from Snyk's experimental Analytics API. Like any Snyk API version tagged
experimental, it can change or stop working without notice, so it's off by default.

| Report or panel | Export API only | With `--experimental` | Reason |
|---|---|---|---|
| Snyk Generated Pull Requests | not available | available | no data on Snyk-created pull requests |
| IDE/CLI usage: scans by AI agent | grouped by runtime environment | by AI agent, as in the UI\* | no AI agent name |
| IDE/CLI usage: scans by product | can be lower than the UI | as in the UI\* | non-scan events often have no product |
| CI/CD: committed repositories | not shown | shown | no SCM commit data |
| Zero-Day: Snyk's active incident and "Assets involved in the incident" | not shown; name the CVEs with `--zero-day` | shown; without `--zero-day`, tracks the active incident | comes from a Snyk-curated feed |
| Filters for risk factors (Deployed, Public facing, OS condition) and CI/CD test parameters | not available | not available | no matching columns |

\* Unfiltered runs only. Those panels can't apply `--filter` or `--product`, so on a filtered run the script builds
them from the Export API as usual and says so in its log.

## Security

The script only reads from Snyk and never prints the token. Keep the token in `.env` or a CI secret rather than on
the command line, and treat `reports/` as sensitive: it holds vulnerability data and, in the IDE/CLI report,
developer names.
