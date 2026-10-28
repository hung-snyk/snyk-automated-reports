# Snyk automated reports

Snyk Analytics has a catalog of reports (Issues Summary, OWASP Top 10, SLA Management and more) that you can
normally only open or download from the web UI. This script builds the same reports from the
[Snyk Export API](https://docs.snyk.io/developer-tools/snyk-api/using-specific-snyk-apis/export-api-specifications-columns-and-filters),
so you can create them from the command line, on a schedule, or in CI.

You choose the reports and the file format for each run:

| Format | What you get |
|---|---|
| `pdf` (default) | One PDF per report, in the same layout as the UI's "Export to PDF" |
| `csv` | The report's tables as CSV files, with every row (the PDF shortens long tables) |
| `json` | One JSON file per report with its headline numbers and all its tables, for scripts and dashboards |

## Quick start

You need Python 3.9 or later and a Snyk API token that can read the org or group you want to report on.
You can create a token in Snyk under **Account settings → General → Auth Token**, or use a service account token.

1. **Install the dependencies** (once):

   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Add your token and org ID** (Snyk: **Settings → General**) to a `.env` file in this folder:

   ```
   SNYK_TOKEN=your-token
   SNYK_ORG_ID=your-org-id
   ```

   Or pass them in the command: `--snyk-token your-token --org-id your-org-id` (the token is then saved in your shell history).

3. **Build a report.** Name it with `--report` (the names are in the next section):

   ```bash
   python3 snyk_reports.py --report issues-summary
   ```

   This writes `reports/snyk_issues-summary_<date>.pdf`, with your org's name from Snyk in the header.

## Reports

| Report name (`--report`) | Report in the UI | What it covers by default (same as the UI) |
|---|---|---|
| `analytics-overview` | Analytics Overview | key numbers for the last 30 days, compared with the 30 before |
| `issues-summary` | Issues Summary | open, new and resolved issues and time to fix, last 30 days vs. the 30 before; top 50 projects |
| `issues-detail` | Issues Detail | every open issue, one row each. A table only: use `--format csv` or `json` |
| `risk-exposure` | Risk Exposure | open issues by severity, with a 30-day trend |
| `vulnerabilities-detail` | Vulnerabilities Detail | open issues grouped by vulnerability |
| `sla-management` | SLA Management | Critical and High issues against fix-time targets of 15/30/90/180 days |
| `zero-day` | Zero-Day | the CVEs you name with `--zero-day` |
| `owasp-top-10-2025` | OWASP Top 10 (2025) | open issues introduced in the last 30 days, by OWASP category |
| `cwe-top-25-2023` | CWE Top 25 (2023) | the same, by CWE Top 25 weakness |
| `cwe-top-10-kev-2023` | CWE Top 10 KEV (2023) | the same, by CWE Top 10 KEV weakness |
| `pci-dss-v4.0.1` | PCI-DSS v4.0.1 | open Critical issues introduced in the last 30 days, by PCI-DSS attack category |
| `prevention` | Prevention | issues fixed before they were merged, last 90 days, by month |
| `pr-checks-usage` | Pull Request Checks Usage & Performance | PR check results and adoption, last 30 days |
| `dev-ide-cli-usage` | Developer IDE and CLI usage | scans by developers in IDEs and the CLI, last 30 days |
| `test-usage-in-cicd-pipelines` | Repositories Tested in CI/CD | repositories tested in CI/CD pipelines, last 30 days |
| `dependencies-and-licenses` | Dependencies and licenses | all open-source dependencies and their licenses |

To print the names, run `python3 snyk_reports.py --list`.

## Usage

Every command needs `--report`. Everything else is optional and changes one thing about the run.

**Several reports at once.** Separate the names with commas. The data is downloaded from Snyk once and shared
by all of them, so this is faster than separate runs:

```bash
python3 snyk_reports.py --report issues-summary,sla-management,owasp-top-10-2025
```

**Choose the file format.** Pass one or more of `pdf`, `csv` and `json`, separated by commas (default: `pdf`):

```bash
python3 snyk_reports.py --report issues-summary --format csv          # only the CSV tables
python3 snyk_reports.py --report issues-summary --format pdf,json     # the PDF and the JSON file
python3 snyk_reports.py --report issues-detail --format csv           # Issues Detail is always a table
```

**A group instead of an org.** A group report covers all the orgs in the group. Pass the group ID in the
command, or set `SNYK_GROUP_ID` in `.env` and add `--scope group`:

```bash
python3 snyk_reports.py --report issues-summary --group-id your-group-id
```

If `.env` has both an org ID and a group ID, the script uses the org unless you pass `--group-id` or
`--scope group`. An ID given in the command always wins over `.env`.

**A different date range.** Most reports cover the last 30 days, like the UI. `--days` changes the length and
`--end` the last day (default: today, in UTC):

```bash
python3 snyk_reports.py --report issues-summary --days 90 --end 2026-09-30
```

**Zero-Day report.** Name the CVEs to track. Without `--zero-day`, this report is skipped:

```bash
python3 snyk_reports.py --report zero-day --zero-day CVE-2026-111497
```

**Saving the Snyk data to re-run without downloading it again.** Each run downloads its data from Snyk through
the Export API, which allows
[20 downloads ("exports") per hour](https://docs.snyk.io/developer-tools/snyk-api/using-specific-snyk-apis/export-api-specifications-columns-and-filters).
A run uses one per kind of data its reports need (up to about 5). If you'll run the script several times in a
row, for example to try different filters or formats, keep a copy of the data from the first run with
`--save-raw`, then build from that copy with `--from-raw`:

```bash
python3 snyk_reports.py --report issues-summary --save-raw                    # downloads, and saves a copy in reports/raw/
python3 snyk_reports.py --report issues-summary --format csv --from-raw reports/raw   # no download; uses the copy
```

`--save-raw` doesn't create a report format. It saves the raw data the script downloaded from Snyk (mostly CSV
files, as the Export API sends them), so reports can be rebuilt offline. For report data in JSON, use
`--format json`.

**Building from a CSV you downloaded from Snyk.** Normally the script downloads the issues itself. If you
already have an issues file, such as the CSV from the UI's **Issues Detail** report ("Download CSV"), you can
build from that file instead, without calling Snyk:

```bash
python3 snyk_reports.py --report issues-summary,owasp-top-10-2025 --from-csv ~/Downloads/issues_detail.csv
```

This works for the issue-based reports. The UI's Issues Detail download contains open issues only, so anything
about resolved issues (resolved counts, time to fix, trends) will be incomplete. Prefer a normal run when you can.

### Filters

Filters narrow a report to the issues (or scans, or dependencies) you care about, like the filters at the top of
a report in the UI. A filter has three parts: a **column**, a **comparison** and a **value**:

```
--filter "ISSUE_SEVERITY=Critical,High"
          └─ column ─┘│└── value ──┘
                  comparison (= means "is")
```

Column names are the ones in the Export API. They're also the column headers you see when you run a report with
`--format csv`, which is the easiest way to find the right name and the exact values.

You can combine as many filters as you like. Commas inside one filter mean **or**; separate `--filter`
options mean **and**, so a row has to match all of them. For example, Critical or High issues with a known
exploit, in production projects owned by the payments team, that have been open for more than 30 days:

```bash
python3 snyk_reports.py --report risk-exposure,sla-management \
  --filter "ISSUE_SEVERITY=Critical,High" \
  --filter "EXPLOIT_MATURITY!=No Known Exploit" \
  --filter "PROJECT_LIFECYCLES=production" \
  --filter "PROJECT_TAGS=team:payments" \
  --filter "FIRST_INTRODUCED<=2026-09-28"
```

Each PDF lists the filters it was built with in its header, so readers know what they're looking at.

| Write | Keeps rows where the column | Example |
|---|---|---|
| `COL=a,b` | is `a` or `b` | `PRODUCT_NAME=Snyk Open Source,Snyk Container` |
| `COL!=a,b` | is neither `a` nor `b` | `EXPLOIT_MATURITY!=No Known Exploit` |
| `COL~text` / `COL!~text` | contains / doesn't contain `text` (any case) | `PROJECT_NAME~payments` |
| `COL=LO..HI`, `COL>=LO`, `COL<=HI` | is a number or date (`YYYY-MM-DD`) in that range, ends included | `SCORE=700..1000` |
| `COL=last7days`, `last30days`, `last90days`, `last365days`, `lastmonth`, `monthtodate`, `yeartodate` | is a date in that period | `LAST_RESOLVED=last90days` |
| `COL=` / `COL!=` | is empty / isn't empty | `CVE!=` (issues that have a CVE) |

Tips:

- Write values exactly as Snyk shows them, for example `Snyk Open Source` or `Proof of Concept`. If a value matches
  nothing, the script prints the values that do exist, so you can correct it.
- Some columns hold lists (`CWE`, `CVE`, `PROJECT_TAGS`, …). A row matches when any item in the list matches.
  Write tags as `key:value`.
- Some columns only exist in one report:
  - SLA Management: `SLA_STATUS` (`Within SLA`, `At Risk`, `Breached`), `ISSUE_AGE`, and `TIME_UNTIL_BREACH`
    (negative when overdue).
  - Prevention: `SDLC_STAGE`, `GIT_REPO` and `GIT_BRANCH`.
  - Usage reports: `ENVIRONMENT_DISPLAY_NAME`, and `INTERACTION_TARGET_ID~github.com/org/repo` for one repository.
  - Dependencies and licenses: `DEPENDENCY_TYPE`, `IS_DEPRECATED` and `LICENSE`. Without a `DEPENDENCY_TYPE`
    filter, `dockerfile` dependencies are left out, as in the UI.
- `ISSUE_SEVERITY` and `PRODUCT_NAME` also apply to the Prevention and usage reports.
- For Attack Vector, use `SNYK_CVSS_VECTOR~AV:N` (Network), `AV:A` (Adjacent), `AV:L` (Local) or `AV:P` (Physical).

### Options

Every option can also be set in `.env` or as an environment variable, using the name in the second column. A
value in the command wins over a variable, and a variable that's already set wins over `.env`.

| Option | Env var | What it does | Default |
|---|---|---|---|
| `--report` | `REPORTS` | Reports to build, comma-separated | required |
| `--format` | `REPORT_FORMATS` | Output formats: `pdf`, `csv`, `json`, comma-separated | `pdf` |
| `--org-id` / `--group-id` | `SNYK_ORG_ID` / `SNYK_GROUP_ID` | The org, or the group (all its orgs), to report on | one is required |
| `--snyk-token` | `SNYK_TOKEN` | Your Snyk API token. Prefer the variable or `.env` | required |
| `--scope org\|group` | `SNYK_SCOPE` | Which ID to use when both are set | the ID given in the command, else the org |
| `--region us\|eu\|au\|us2` | `SNYK_REGION` | Where your Snyk account is hosted | `us` |
| `--days`, `--end` | `REPORT_DAYS` | Length and last day of the date range | each report's UI default, ending today (UTC) |
| `--filter` | `REPORT_FILTERS` (separate with `;`) | Narrow the reports (see [Filters](#filters)) | none |
| `--zero-day CVE-…` | `ZERO_DAY_CVE` (comma list) | CVEs for the Zero-Day report | none; Zero-Day is skipped |
| `--sla critical=15:3,…` | `SLA_TARGETS` | SLA targets per severity: days to fix, then the "at risk" warning days | the UI's targets |
| `--severity`, `--product` | | Only these severities or Snyk products | the UI's defaults |
| `--include-ignored` | | Also count ignored issues | left out, as in the UI |
| `--max-projects`, `--max-rows` | `REPORT_MAX_PROJECTS`, `REPORT_MAX_ROWS` | Rows shown in long PDF tables (`0` = all). CSV and JSON always have every row | `50`, `200` |
| `--lookback-days` | | How much history to download for usage, Prevention and PR checks | `400`; raise it for `--days` over 200 |
| `--generated-by` | `REPORT_AUTHOR` | "Report generated by" name in the header | your user name |
| `--out` | `REPORT_OUT` | Folder for the reports | `reports` |
| `--save-raw`, `--from-raw`, `--from-csv` | | Save the downloaded data, or build from saved or downloaded files (see [Usage](#usage)) | off |

Exit codes: `0` success, `1` API or input error, `2` bad arguments.

## Limitations

Some reports and panels aren't available, because the Export API doesn't include their data.

| Report or panel | Status | Reason |
|---|---|---|
| Snyk Generated Pull Requests | not supported | no data on pull requests created by Snyk |
| IDE/CLI usage: scans by AI agent | grouped by runtime environment | no AI agent name |
| IDE/CLI usage: scans by product | can be lower than the UI | non-scan events often have no product |
| Repositories Tested in CI/CD: committed repositories | not shown | no SCM commit data |
| Zero-Day: "Assets involved in the incident" | not shown | comes from a Snyk-curated feed |
| Filters for CISA KEV, CVSS v4 exploit maturity, risk factors, CI/CD test parameters | not available | no matching columns |

## Security

The script only reads from Snyk and never prints the token. Keep the token in `.env` or a CI secret rather than
in a command (`--snyk-token`), and treat `reports/` as sensitive: it contains vulnerability data and, in the IDE/CLI
report, developer names.
