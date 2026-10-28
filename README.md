# Snyk automated reports

Rebuilds the reports from Snyk Analytics' **Reports** catalog, which are otherwise only available in the UI,
as PDF and CSV files. The data comes from the
[Export API](https://docs.snyk.io/developer-tools/snyk-api/using-specific-snyk-apis/export-api-specifications-columns-and-filters),
plus the v1 dependencies API for one report.

| Report (`--report` slug) | Data | Default scope (same as the UI) |
|---|---|---|
| `issues-summary` | issues | last 30 days; project table limited to the top 50 |
| `issues-detail` (CSV only) | issues | open issues |
| `risk-exposure` | issues | open issues; trend over the last 30 days |
| `vulnerabilities-detail` | issues | open issues, grouped by vulnerability |
| `sla-management` | issues | Critical and High; targets 15/30/90/180 days |
| `zero-day` | issues | the CVEs given with `--zero-day` |
| `owasp-top-10-2025`, `cwe-top-25-2023`, `cwe-top-10-kev-2023` | issues | open issues introduced in the last 30 days |
| `pci-dss-v4.0.1` | issues | open Critical issues introduced in the last 30 days |
| `prevention` | prevention_events | last 90 days |
| `pr-checks-usage` | pr_checks, pr_checks_project_adoption | last 30 days |
| `dev-ide-cli-usage` | usage | last 30 days |
| `test-usage-in-cicd-pipelines` | usage | last 30 days |
| `dependencies-and-licenses` | v1 dependencies API (org only) | all dependencies |

**Snyk Generated Pull Requests** isn't included: no public API exposes that data.

Each PDF uses the UI's landscape layout. CSVs contain every row, while long PDF tables are capped by `--max-rows`.
Each run also writes `summary_<date>.json` with the headline numbers, which is useful for CI checks or dashboards.

## Run locally

```bash
pip install -r requirements.txt
cat > .env <<'EOF'
SNYK_TOKEN=...
SNYK_ORG_ID=...
EOF
python3 snyk_reports.py --org-name demo-training                 # every report
python3 snyk_reports.py --report issues-summary,owasp-top-10-2025 # just some
python3 snyk_reports.py --list
```

The `.env` file is gitignored. Variables that are already set, such as CI secrets, take precedence over it.

| Option | Env var | Default |
|---|---|---|
| `--report` | `REPORTS` | `all` |
| `--org-id` / `--group-id` | `SNYK_ORG_ID` / `SNYK_GROUP_ID` | (one is required) |
| `--region us\|eu\|au\|us2` | `SNYK_REGION` | `us` |
| `--days` | `REPORT_DAYS` | Each report's UI default |
| `--end YYYY-MM-DD` | | today (UTC) |
| `--zero-day CVE-...` | `ZERO_DAY_CVE` (comma list) | (Zero-Day is skipped without it) |
| `--sla critical=15:3,high=30:10` | `SLA_TARGETS` | the UI's targets |
| `--severity`, `--product`, `--include-ignored` | | |
| `--max-projects` / `--max-rows` | `REPORT_MAX_PROJECTS` / `REPORT_MAX_ROWS` | `50` / `200` (`0` = all) |
| `--org-name`, `--generated-by` | `SNYK_ORG_NAME`, `REPORT_AUTHOR` / `GITHUB_ACTOR` | |
| `--out` | `REPORT_OUT` | `reports` |
| `--save-raw` / `--from-raw DIR` | | Saves every dataset under `<out>/raw/`, or rebuilds from it without calling the API. |

Each dataset is exported once per run, so a full run uses 5 exports. The Export API allows 20 exports per hour,
and its data refreshes about every 2 hours. To tweak and re-render, run once with `--save-raw`, then use `--from-raw reports/raw`.

Exit codes: `0` success, `1` API, export or input error, `2` bad arguments.

## CI

`.github/workflows/snyk-reports.yml` runs every Monday and on demand, then uploads `reports/` as a build artifact.
To set it up, add the secret `SNYK_TOKEN` and the variable `SNYK_ORG_ID` (or `SNYK_GROUP_ID`).
`SNYK_REGION`, `SNYK_ORG_NAME`, `REPORTS` and `ZERO_DAY_CVE` are optional variables.

Other CI systems work the same way. Here is a GitLab example:

```yaml
snyk-reports:
  image: python:3.12
  rules: [{ if: '$CI_PIPELINE_SOURCE == "schedule"' }]
  script:
    - pip install -r requirements.txt
    - python snyk_reports.py
  artifacts: { paths: [reports/], expire_in: 30 days }
```

## How the numbers are computed

These rules were checked against the UI for the demo-training org on 2026-10-28.

- **Open at a date**: introduced on or before that date and not resolved by then. Ignored issues are excluded unless `--include-ignored` is set.
- **New / resolved**: `FIRST_INTRODUCED` / `LAST_RESOLVED` falls inside the window. **MTTR** rounds each issue up to whole days, then averages.
- **Percentage change**: measured against the previous window of the same length. A zero baseline counts as 1, which matches the UI.
- **Compliance controls**: an issue counts once in each control whose CWEs it carries.
  OWASP uses the "List of Mapped CWEs" from [OWASP/Top10](https://github.com/OWASP/Top10/tree/master/2025/docs/en),
  and PCI-DSS uses [Snyk's attack-category CWE list](https://docs.snyk.io/scan-fix-and-prevent/prevent/analytics/reports-tab/compliance-reports).
- **SLA**: whole days since introduction against the target. An issue is "at risk" within the at-risk days before the target.
- **Prevention fix rate**: fixed findings divided by all findings with events in the window.
- **Usage**: events tagged `mcp` are agentic scans, language-server scans are IDE scans, and everything else counts as CLI.
  The UI's "IDE scans" tile also includes agentic scans.

### Known gaps vs the UI

- The Export API only gives each issue's *last* resolution date, so issues that were resolved and then reopened can shift historical points slightly.
- **Developer IDE and CLI usage**: the per-agent split (Claude, Cursor and so on) isn't in the export, and neither is the product of non-scan events.
- **Repositories Tested in CI/CD**: "committed repositories" comes from SCM commit data that isn't exported.
- **Zero-Day**: the "Assets involved in the incident" panel comes from a Snyk-curated feed with no public API.
- **PCI-DSS**: "high-risk vulnerabilities" is taken to mean issues in the CISA KEV catalog. This is an assumption, because Snyk doesn't document it.
