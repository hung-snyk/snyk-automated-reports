#!/usr/bin/env python3
"""Recreate the Snyk Analytics reports (PDF + CSV) from the Snyk Export API.

  python3 snyk_reports.py --list                                    # available reports
  python3 snyk_reports.py --report issues-summary --org-id <uuid>
  python3 snyk_reports.py --report issues-summary,owasp-top-10-2025 --days 30
  python3 snyk_reports.py --report sla-management --from-raw reports/raw   # rebuild offline from a --save-raw run

Settings can come from the environment or a .env file (SNYK_TOKEN, SNYK_ORG_ID, SNYK_GROUP_ID,
SNYK_REGION, REPORTS, REPORT_DAYS, REPORT_OUT, ZERO_DAY_CVE), so CI only sets variables.
Each dataset is exported once per run; the Export API allows 20 exports per hour.
Exit codes: 0 success, 1 API/export/input error, 2 bad arguments.
"""
import argparse, json, os
from datetime import datetime, timezone

from snykreports import api, common
from snykreports.common import Ctx, Filter


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


def main(argv=None):
    """Build the selected reports; returns the run context (None for --list) so other tools can reuse a run."""
    load_dotenv()
    try:
        from snykreports.reports import INTERNAL_ONLY, REPORTS, UNSUPPORTED
    except ImportError as e:
        api.fail(f"{e}; install dependencies with: pip install -r requirements.txt")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", default=env("REPORTS"), help="report(s) to build, comma-separated (required; see --list)")
    ap.add_argument("--list", action="store_true", help="list the available reports and exit")
    ap.add_argument("--format", default=env("REPORT_FORMATS", "pdf"),
                    help="output format(s), comma-separated: pdf, csv, json (default: pdf)")
    ap.add_argument("--snyk-token", help="Snyk API token (default: SNYK_TOKEN). Prefer the variable: a command-line "
                                    "value is visible in your shell history and to other users of the machine")
    ap.add_argument("--org-id", help="org to report on (default: SNYK_ORG_ID)")
    ap.add_argument("--group-id", help="group to report on, across all its orgs (default: SNYK_GROUP_ID)")
    ap.add_argument("--scope", choices=["org", "group"], default=env("SNYK_SCOPE"),
                    help="which ID to use when both are set (default: the one given on the command line, "
                         "else the group)")
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
    ap.add_argument("--filter", action="append", default=[f for f in (env("REPORT_FILTERS") or "").split(";") if f.strip()],
                    help="filter rows by an export column, like the UI filters: COLUMN=a,b | COLUMN!=a | COLUMN~text | "
                         "COLUMN!~text | COLUMN=LO..HI | COLUMN>=LO | COLUMN<=HI (numbers or YYYY-MM-DD) | "
                         "COLUMN=last30days (repeatable; every filter must match; see README)")
    ap.add_argument("--sla", default=env("SLA_TARGETS"), help="SLA targets, e.g. critical=15:3,high=30:10 (days:at-risk days)")
    ap.add_argument("--zero-day", action="append", default=[c for c in (env("ZERO_DAY_CVE") or "").split(",") if c],
                    help="CVE or Snyk vulnerability ID (SNYK-...) for the Zero-Day report (repeatable); "
                         "with --internal-api it defaults to Snyk's active zero-day incident")
    ap.add_argument("--max-projects", type=int, default=int(env("REPORT_MAX_PROJECTS", 50)),
                    help="rows in the Issues Summary project table; the UI shows 50 (0 = all)")
    ap.add_argument("--max-rows", type=int, default=int(env("REPORT_MAX_ROWS", 200)),
                    help="rows in long PDF tables (0 = all); CSVs always have every row")
    ap.add_argument("--generated-by", default=env("REPORT_AUTHOR") or env("GITHUB_ACTOR") or env("USER", "snyk_reports"))
    ap.add_argument("--out", default=env("REPORT_OUT", "reports"))
    ap.add_argument("--internal-api", action="store_true", default=(env("SNYK_INTERNAL_API") or "").lower() in ("1", "true", "yes"),
                    help="also use the UI's undocumented reporting API for panels the Export API lacks, and for the "
                         "Snyk Generated Pull Requests report (unsupported by Snyk; may change without notice)")
    a = ap.parse_args(argv)

    hidden = set() if a.internal_api else INTERNAL_ONLY
    if a.list:
        for slug, (title, _) in REPORTS.items():
            if slug not in hidden: print(f"{slug:32} {title}")
        for slug, why in UNSUPPORTED.items(): print(f"{slug:32} (not available: {why})")
        return
    # each run names the reports it needs; there is deliberately no "all"
    slugs = list(dict.fromkeys(s.strip() for s in (a.report or "").split(",") if s.strip()))
    if not slugs: ap.error("--report is required: name one or more reports, comma-separated (see --list)")
    unavailable = [s for s in slugs if s in hidden]
    if unavailable: ap.error(f"not available from the Export API: {', '.join(unavailable)}")
    unknown = [s for s in slugs if s not in REPORTS and s not in UNSUPPORTED]
    if unknown: ap.error(f"unknown report(s): {', '.join(unknown)} (see --list)")
    try: a.filter = [Filter(s) for s in a.filter]
    except ValueError as e: ap.error(str(e))
    formats = {f.strip().lower() for f in a.format.split(",") if f.strip()}
    if not formats or formats - common.FORMATS:
        ap.error(f"--format takes pdf, csv and/or json, comma-separated; got {a.format!r}")
    common.FORMATS = formats
    if a.snyk_token: os.environ["SNYK_TOKEN"] = a.snyk_token
    # group scope is the default; an ID on the command line picks the scope, and IDs from .env/the environment only
    # fill in what's missing
    given = "org" if a.org_id and not a.group_id else "group" if a.group_id else None
    a.org_id, a.group_id = a.org_id or env("SNYK_ORG_ID"), a.group_id or env("SNYK_GROUP_ID")
    a.scope = a.scope or given or ("org" if a.org_id and not a.group_id else "group")
    if not (a.from_raw or a.from_csv) and not (a.org_id if a.scope == "org" else a.group_id):
        ap.error(f"--scope {a.scope} needs --{a.scope}-id (or SNYK_{a.scope.upper()}_ID)")
    if a.from_csv and not a.from_raw:
        needs_api = [s for s in slugs if s in REPORTS and s not in ISSUE_ONLY]
        if needs_api: ap.error(f"--from-csv only covers issue-based reports; also pass --from-raw or drop: {', '.join(needs_api)}")
    try:
        end_day = datetime.strptime(a.end, "%Y-%m-%d").date() if a.end else datetime.now(timezone.utc).date()
    except ValueError:
        ap.error("--end must be YYYY-MM-DD")
    # non-issue exports start --lookback-days before --end; a window and its previous period need 2 * --days - 1
    if a.days and not a.from_raw and 2 * a.days - 1 > a.lookback_days:
        api.log(f"warning: --days {a.days} needs {2 * a.days - 1} days of usage, prevention and PR-check "
                f"history, but --lookback-days is {a.lookback_days}; " +
                ("reports built on that data have their windows cut short" if a.days > a.lookback_days else "their previous-period comparisons are incomplete") +
                f". Pass --lookback-days {2 * a.days - 1} or more.")
    out = os.path.realpath(a.out)
    os.makedirs(out, exist_ok=True)

    a.org_name = scope_name(a, out)   # the report header shows the org's or group's name from Snyk
    ctx = Ctx(a, out, end_day)
    for slug in slugs:
        if slug in UNSUPPORTED:
            ctx.skipped[slug] = UNSUPPORTED[slug]; continue
        title, build = REPORTS[slug]
        api.log(f"building {title}")
        common.begin_report()
        written = [p for p in build(ctx) if p]
        tables = common.end_report()
        if "json" in formats and (tables or slug in ctx.summary):
            # deepcode ignore PT: the output folder is the operator's own --out choice; filename is generated
            written.append(write_json(ctx, slug, title, tables))
        if not written and slug not in ctx.skipped:
            api.log(f"note: {title} was not written: it has no PDF version (like the UI); add csv or json to --format")
        for p in written: print(f"wrote {p}")
    for slug, why in ctx.skipped.items(): api.log(f"skipped {slug}: {why}")
    return ctx


def scope_name(a, out):
    """The org's or group's name for the report header: from Snyk, or from a saved run when offline."""
    meta = os.path.join(a.from_raw or os.path.join(out, "raw"), "meta.json")
    if a.from_raw or a.from_csv:
        try:
            # deepcode ignore PT: --from-raw/--out are the operator's own folders; the filename is fixed
            with open(meta, encoding="utf-8") as f: return json.load(f).get("name") or "Snyk"
        except (OSError, ValueError): return "Snyk"
    name = api.scope_name(api.REGIONS[a.region], "orgs" if a.scope == "org" else "groups",
                          a.org_id if a.scope == "org" else a.group_id,
                          os.environ.get("SNYK_TOKEN") or api.fail("set SNYK_TOKEN, or pass --snyk-token"))
    if a.save_raw:   # so --from-raw runs later show the same name
        os.makedirs(os.path.dirname(meta), exist_ok=True)
        # deepcode ignore PT: the output folder is the operator's own --out choice; filename is generated
        with open(meta, "w", encoding="utf-8") as f: json.dump({"name": name}, f)
    return name


def write_json(ctx, slug, title, tables):
    """One JSON file per report: its headline numbers plus every table, as lists of row objects."""
    prefix, suffix = f"snyk_{slug}", f"_{ctx.stamp}.csv"
    def table_name(file):
        name = file.removesuffix(suffix)
        return name.removeprefix(prefix).lstrip("_") or "rows" if name.startswith(prefix) else name.removeprefix("snyk_")
    doc = {"report": slug, "title": title, "scope": ctx.args.scope, "name": ctx.args.org_name,
           "end": str(ctx.end_day), "filters": [f.spec for f in ctx.args.filter],
           "summary": ctx.summary.get(slug, {}),
           "tables": {table_name(file): [dict(zip(header, row)) for row in rows] for file, header, rows in tables}}
    path = ctx.path(slug, "json")
    # deepcode ignore PT: the output folder is the operator's own --out choice; filename is generated
    with open(path, "w", encoding="utf-8") as f:
        # deepcode ignore PT: same output folder as above
        json.dump(doc, f, indent=2, default=str)
    return path


ISSUE_ONLY = {"issues-summary", "issues-detail", "risk-exposure", "vulnerabilities-detail", "sla-management", "zero-day",
              "owasp-top-10-2025", "cwe-top-25-2023", "cwe-top-10-kev-2023", "pci-dss-v4.0.1"}

if __name__ == "__main__":
    main()
