# Snyk automated reports

Builds the Snyk Analytics reports (Issues Summary, OWASP Top 10, SLA Management, …) from the
[Snyk Export API](https://docs.snyk.io/developer-tools/snyk-api/using-specific-snyk-apis/export-api-specifications-columns-and-filters),
so you can create them from the command line, on a schedule or in CI instead of from the web UI.

Output formats: `pdf` (default; the UI's "Export to PDF" layout), `csv` (every table row) and `json` (headline
numbers and tables).

## Quick start

You need Python 3.10+ and a Snyk API token (**Account settings → General → Auth Token**, or a service account token)
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

Keep the token in `.env` (git ignores it) or your CI system's secret store, not on the command line, where it stays
in your shell history. The script only reads from Snyk. Its reports hold vulnerability data, so share them as you
would any security report.

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
- CI/CD test parameters (the CLI flags a pipeline ran with): `INTERACTION_CATEGORIES=severity-threshold` (or
  `all-projects`, `json-file-output`, …).
- Ignored issues and Prevention events are left out unless you pass `--include-ignored` or filter on their status
  yourself, such as `ISSUE_STATUS=Ignored` or `IS_SUPPRESSED=true`. With `--include-ignored`, ignored issues count
  as open where a report tracks open issues over time, are added to the reports that list open issues (Issues Detail,
  Vulnerabilities Detail, OWASP, CWE, PCI-DSS), and appear in Zero-Day's targets table and charts. An
  `ISSUE_STATUS` filter takes precedence over it.

### Options

| Option | Values | Example |
|---|---|---|
| `--report` | one or more names from [Reports](#reports), comma-separated (required) | `--report issues-summary,sla-management` |
| `--list` | no value | `--list` |
| `--format` | `pdf` (default), `csv`, `json`, comma-separated | `--format pdf,csv` |
| `--group-id` | a group ID | `--group-id <group-id>` |
| `--org-id` | an org ID | `--org-id <org-id>` |
| `--scope` | `group` (default), `org` | `--scope org` |
| `--snyk-token` | a Snyk API token (prefer `SNYK_TOKEN` in `.env`) | `--snyk-token <token>` |
| `--region` | `us` (default), `eu`, `au`, `us2` | `--region eu` |
| `--days` | a number of days, 1 or more (default: each report's UI range) | `--days 90` |
| `--end` | a date, `YYYY-MM-DD` (default: today, UTC) | `--end 2026-09-30` |
| `--filter` | `COLUMN=VALUE` and the other forms in [Filters](#filters); repeatable | `--filter "ISSUE_SEVERITY=Critical,High"` |
| `--product` | `Snyk Open Source`, `Snyk Code`, `Snyk Container`, `Snyk IaC`, `Snyk Secrets`; repeatable | `--product "Snyk Code"` |
| `--severity` | `critical`, `high`, `medium`, `low`, any case, comma-separated | `--severity critical,high` |
| `--include-ignored` | no value; keeps ignored issues and Prevention events (see [Filters](#filters)) | `--include-ignored` |
| `--zero-day` | a CVE (`CVE-…`) or Snyk vulnerability ID (`SNYK-…`); repeat the flag for more | `--zero-day CVE-2021-44228` |
| `--sla` | `SEVERITY=DAYS` or `SEVERITY=DAYS:AT_RISK_DAYS`, comma-separated (default: `critical=15:3,high=30:10,medium=90:20,low=180:30`) | `--sla critical=7:2,high=14:5` |
| `--max-projects` | a number, 0 or more; `0` = all (default 50) | `--max-projects 0` |
| `--max-rows` | a number, 0 or more; `0` = all (default 200) | `--max-rows 500` |
| `--lookback-days` | a number of days, 1 or more (default 400) | `--lookback-days 800` |
| `--save-raw` | no value | `--save-raw` |
| `--from-raw` | a folder saved by `--save-raw` | `--from-raw reports/raw` |
| `--from-csv` | an issues CSV file | `--from-csv issues_detail.csv` |
| `--generated-by` | any name (default: your user name) | `--generated-by "Security team"` |
| `--out` | a folder (default: `reports`) | `--out ~/snyk-reports` |

You can also set these in `.env` or the environment, which suits CI: `SNYK_TOKEN`, `SNYK_GROUP_ID`, `SNYK_ORG_ID`,
`SNYK_SCOPE`, `SNYK_REGION`, `REPORTS`, `REPORT_FORMATS`, `REPORT_DAYS`, `REPORT_FILTERS` (`;`-separated),
`ZERO_DAY_CVE` (comma-separated), `SLA_TARGETS`, `REPORT_MAX_PROJECTS`, `REPORT_MAX_ROWS`, `REPORT_AUTHOR` and
`REPORT_OUT`. An option on the command line wins over the environment, and the environment wins over `.env`.

Exit codes: `0` success, `1` API or input error, `2` bad arguments.

## Limitations

The script only uses Snyk's supported APIs. These parts of Snyk Analytics have no supported API, so they aren't
available:

- **Snyk Generated Pull Requests report.** No supported API returns the fix, backlog and upgrade pull requests that
  Snyk opens. Use the report in the Snyk web UI.
- **Repositories Tested in CI/CD: the comparison with repositories that had commits.** The UI compares how many
  repositories Snyk tested in CI/CD with how many had recent commits, which Snyk reads from your source control. No
  supported API provides those commit counts, so the report shows tested repositories only.
- **Zero-Day: Snyk's active incident.** During a major zero-day event, Snyk curates an active incident, and the UI's
  Zero-Day report opens on it, with an "Assets involved in the incident" panel. That incident comes from Snyk's own
  curated feed rather than from your issues, and no supported API returns it. The rest of the report works from your
  issues: name the vulnerabilities to track with `--zero-day`, as CVE IDs or Snyk IDs (`SNYK-...`), which you can
  look up in the [Snyk Vulnerability Database](https://security.snyk.io).
- **Filters for risk factors (Deployed, Public facing, OS condition).** These come from Snyk Insights, and the issues
  export has no columns for them, so `--filter` can't use them.
