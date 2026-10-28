#!/usr/bin/env python3
"""Recreate the Snyk Analytics reports (PDF + CSV) from the Snyk Export API.

  python3 snyk_reports.py --list                          # available reports
  python3 snyk_reports.py --org-id <uuid> --org-name demo-training
  python3 snyk_reports.py --report issues-summary,owasp-top-10-2025 --days 30
  python3 snyk_reports.py --from-raw reports/raw          # rebuild offline from a --save-raw run

Settings can come from the environment or a .env file (SNYK_TOKEN, SNYK_ORG_ID, SNYK_GROUP_ID,
SNYK_REGION, SNYK_ORG_NAME, REPORTS, REPORT_DAYS, REPORT_OUT, ZERO_DAY_CVE), so CI only sets variables.
Each dataset is exported once per run; the Export API allows 20 exports per hour.
Exit codes: 0 success, 1 API/export/input error, 2 bad arguments.
"""
import argparse, json, os, sys
from datetime import datetime, timezone

from snykreports import api
from snykreports.common import Ctx


def load_dotenv(path=".env"):
    """Read KEY=VALUE lines into os.environ; variables already set (e.g. CI secrets) win."""
    if not os.path.isfile(path): return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            k, v = line.removeprefix("export ").split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip("'\""))


def env(name, default=None):
    return os.environ.get(name) or default


def main():
    load_dotenv()
    try:
        from snykreports.reports import REPORTS, UNSUPPORTED
    except ImportError as e:
        api.fail(f"{e}; install dependencies with: pip install -r requirements.txt")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", default=env("REPORTS", "all"), help="comma list of report slugs, or 'all' (see --list)")
    ap.add_argument("--list", action="store_true", help="list the available reports and exit")
    ap.add_argument("--org-id", default=env("SNYK_ORG_ID"))
    ap.add_argument("--group-id", default=env("SNYK_GROUP_ID"))
    ap.add_argument("--region", choices=api.REGIONS, default=env("SNYK_REGION", "us"))
    ap.add_argument("--from-raw", help="folder of datasets saved by --save-raw; no API calls")
    ap.add_argument("--from-csv", help="issues export or UI 'Issues Detail' CSV, for the issue-based reports only")
    ap.add_argument("--save-raw", action="store_true", help="also save each exported dataset under <out>/raw/")
    ap.add_argument("--days", type=int, default=int(env("REPORT_DAYS", 0)) or None,
                    help="report window for every report (default: each report's UI default, mostly 30 days)")
    ap.add_argument("--end", help="last day of the window, YYYY-MM-DD (default: today, UTC)")
    ap.add_argument("--lookback-days", type=int, default=400, help="history exported for non-issue datasets (default 400)")
    ap.add_argument("--product", action="append", help="e.g. 'Snyk Container' (repeatable)")
    ap.add_argument("--severity", action="append", help="Critical|High|Medium|Low; overrides the SLA and PCI-DSS defaults")
    ap.add_argument("--include-ignored", action="store_true")
    ap.add_argument("--sla", default=env("SLA_TARGETS"), help="SLA targets, e.g. critical=15:3,high=30:10 (days:at-risk days)")
    ap.add_argument("--zero-day", action="append", default=[c for c in (env("ZERO_DAY_CVE") or "").split(",") if c],
                    help="CVE for the Zero-Day report (repeatable)")
    ap.add_argument("--max-projects", type=int, default=int(env("REPORT_MAX_PROJECTS", 50)),
                    help="rows in the Issues Summary project table; the UI shows 50 (0 = all)")
    ap.add_argument("--max-rows", type=int, default=int(env("REPORT_MAX_ROWS", 200)),
                    help="rows in long PDF tables (0 = all); CSVs always have every row")
    ap.add_argument("--org-name", default=env("SNYK_ORG_NAME", "Snyk"), help="name shown in the PDF header")
    ap.add_argument("--generated-by", default=env("REPORT_AUTHOR") or env("GITHUB_ACTOR") or env("USER", "snyk_reports"))
    ap.add_argument("--out", default=env("REPORT_OUT", "reports"))
    a = ap.parse_args()

    if a.list:
        for slug, (title, _) in REPORTS.items(): print(f"{slug:32} {title}")
        for slug, why in UNSUPPORTED.items(): print(f"{slug:32} (not available: {why})")
        return
    slugs = list(REPORTS) if a.report.strip() == "all" else [s.strip() for s in a.report.split(",") if s.strip()]
    unknown = [s for s in slugs if s not in REPORTS and s not in UNSUPPORTED]
    if unknown: ap.error(f"unknown report(s): {', '.join(unknown)} (see --list)")
    if not (a.from_raw or a.from_csv) and bool(a.org_id) == bool(a.group_id):
        ap.error("pass exactly one of --org-id / --group-id")
    if a.from_csv and not a.from_raw:
        needs_api = [s for s in slugs if s in REPORTS and s not in ISSUE_ONLY]
        if needs_api: ap.error(f"--from-csv only covers issue-based reports; also pass --from-raw or drop: {', '.join(needs_api)}")
    try:
        end_day = datetime.strptime(a.end, "%Y-%m-%d").date() if a.end else datetime.now(timezone.utc).date()
    except ValueError:
        ap.error("--end must be YYYY-MM-DD")
    out = os.path.realpath(a.out)
    os.makedirs(out, exist_ok=True)

    ctx = Ctx(a, out, end_day)
    for slug in slugs:
        if slug in UNSUPPORTED:
            ctx.skipped[slug] = UNSUPPORTED[slug]; continue
        title, build = REPORTS[slug]
        api.log(f"building {title}")
        for p in build(ctx): print(f"wrote {p}")
    for slug, why in ctx.skipped.items(): api.log(f"skipped {slug}: {why}")
    summary_path = os.path.join(out, f"summary_{ctx.stamp}.json")
    # deepcode ignore PT: the output folder is the operator's own --out choice; filename is generated
    with open(summary_path, "w", encoding="utf-8") as f:
        # deepcode ignore PT: same output folder as above
        json.dump({"end": str(end_day), "reports": ctx.summary, "skipped": ctx.skipped}, f, indent=2, default=str)
    print(f"wrote {summary_path}")


ISSUE_ONLY = {"issues-summary", "issues-detail", "risk-exposure", "vulnerabilities-detail", "sla-management", "zero-day",
              "owasp-top-10-2025", "cwe-top-25-2023", "cwe-top-10-kev-2023", "pci-dss-v4.0.1"}

if __name__ == "__main__":
    main()
