"""Issues Summary (PDF) and Issues Detail (CSV)."""
import json
from collections import defaultdict
from datetime import timedelta

from ..common import SEV_RANK, change, ceil_days, is_open_at, jlist, write_csv
from ..pdf import M, SERIES, W, stacked
from .base import days, labels, open_pdf, period, week_starts

DETAIL_COLUMNS = ["ISSUE_SEVERITY_RANK", "ISSUE_SEVERITY", "SCORE", "PROBLEM_TITLE", "CVE", "CVE_URL",
                  "CWE", "PROJECT_NAME", "PROJECT_URL", "EXPLOIT_MATURITY", "COMPUTED_FIXABILITY",
                  "FIRST_INTRODUCED", "PRODUCT_NAME", "ISSUE_URL", "ISSUE_STATUS_INDICATOR", "ISSUE_TYPE"]
# Aging ranges used by the Exposure Window and Time to Resolve charts, oldest first.
BUCKETS = [("more than 30 days", 31, 10**6), ("15-30 days", 15, 30), ("less than 15 days", 0, 14)]


def issues_detail(ctx):
    sel = [r for r in ctx.issues(ctx.default_statuses("Open")) if not ctx.args.severity or r.get("ISSUE_SEVERITY") in ctx.args.severity]
    sel.sort(key=lambda r: (-SEV_RANK.get(r.get("ISSUE_SEVERITY"), 0), -float(r.get("SCORE") or 0)))
    compact = lambda v: json.dumps(v, separators=(",", ":"))

    def row(r):
        cves = jlist(r.get("CVE"))
        return [SEV_RANK.get(r.get("ISSUE_SEVERITY"), ""), r.get("ISSUE_SEVERITY"), r.get("SCORE"),
                r.get("PROBLEM_TITLE"), compact(cves), compact([f"https://www.cve.org/CVERecord?id={c}" for c in cves]),
                r.get("CWE", "[]"), r.get("PROJECT_NAME"), r.get("PROJECT_URL"), r.get("EXPLOIT_MATURITY"),
                r.get("COMPUTED_FIXABILITY"), r.get("FIRST_INTRODUCED"), r.get("PRODUCT_NAME"),
                r.get("ISSUE_URL"), r["_status"], r.get("ISSUE_TYPE")]
    return [write_csv(ctx.path("issues_detail", "csv"), DETAIL_COLUMNS, (row(r) for r in sel))]


def period_stats(rows, start, end):
    res = [r for r in rows if r["_res"] and start <= r["_res"] < end]
    # the UI counts a partial day as a full day per issue before averaging
    ttr = [ceil_days(r["_intro"], r["_res"]) for r in res]
    return {"open": sum(1 for r in rows if is_open_at(r, end)),
            "new": sum(1 for r in rows if start <= r["_open_from"] < end), "resolved": len(res),
            "mttr": round(sum(ttr) / len(ttr)) if ttr else 0}


def bucket_of(age):
    return next(i for i, (_, lo, hi) in enumerate(BUCKETS) if lo <= age <= hi) if age >= 0 else len(BUCKETS) - 1


def issues_summary(ctx):
    rows = ctx.issues()
    start, end = ctx.window(30)
    span = period(start, end)
    pts = days(start, end)
    weeks = week_starts(start, end)
    exposure = [[0] * len(pts) for _ in BUCKETS]
    for i, d in enumerate(pts):
        for r in rows:
            if is_open_at(r, d): exposure[bucket_of((d - r["_open_from"]).days)][i] += 1
    ttr = [[0] * len(weeks) for _ in BUCKETS]
    for r in rows:
        if r["_res"] and start <= r["_res"] < end:
            w = min(int((r["_res"] - start).days // 7), len(weeks) - 1)
            ttr[bucket_of((r["_res"] - r["_intro"]).days)][w] += 1
    by_project = defaultdict(list)
    for r in rows: by_project[r.get("PROJECT_URL") or r.get("PROJECT_NAME")].append(r)
    projects = []
    for rs in by_project.values():
        cur, prev = period_stats(rs, start, end), period_stats(rs, start - span, start)
        if cur["open"] or cur["new"] or cur["resolved"]:
            projects.append((rs[0].get("PROJECT_NAME", ""), rs[0].get("PROJECT_URL", ""), cur, prev))
    projects.sort(key=lambda p: (-p[2]["open"], p[0]))
    cur, prev = period_stats(rows, start, end), period_stats(rows, start - span, start)

    pdf, path = open_pdf(ctx, "issues-summary", "Issues Summary", date_range=(start, end))
    up_bad = {"open": True, "new": True, "resolved": False, "mttr": True}
    pdf.tiles([{"label": l, "value": cur[k], "badge": (change(cur[k], prev[k]), up_bad[k]),
                "sub": f"{prev[k]:,} previous period"}
               for l, k in [("Total open issues", "open"), ("Total new issues", "new"),
                            ("Total resolved issues", "resolved"), ("Mean Time To Resolve (Days)", "mttr")]])
    pdf.chart_block("Issues Identified and Resolved",
                    "Issues burn up trend, surfacing the open issues backlog as the gap between identified and resolved issue counters.",
                    labels(pts), [("Identified", SERIES[0], [sum(1 for r in rows if r["_intro"] <= d) for d in pts]),
                                  ("Resolved", SERIES[2], [sum(1 for r in rows if r["_res"] and r["_res"] <= d) for d in pts])],
                    fill=False)
    pdf.new_page()
    names = [b[0] for b in BUCKETS]
    pdf.chart_block("Exposure Window", "Issues aging analysis, presenting the open issues count per date and aging range.",
                    labels(pts), list(zip(names, SERIES, stacked(exposure))), advance=False)
    pdf.chart_block("Time to Resolve by Week",
                    "Issues resolution velocity, as the count of issues resolved within a time range per week.",
                    labels(weeks), list(zip(names, SERIES, stacked(ttr))), x=W / 2 + 6, smooth=True, label_every=1,
                    advance=False)
    pdf.new_page()
    pdf.section("Risk breakdown by Project", "A breakdown of issue metrics, along with their percentage change from the previous period.")
    limit = ctx.args.max_projects or len(projects)
    pdf.table([("Project Name", 0.32, "link"), ("Open Issues ↓", 0.17, "badge"), ("New Issues", 0.17, "badge"),
               ("Resolved Issues", 0.17, "badge"), ("Mean Time To Resolve (Days)", 0.17, "badge")],
              [[(n, u)] + [(c[k], change(c[k], p[k]), up_bad[k]) for k in ("open", "new", "resolved", "mttr")]
               for n, u, c, p in projects[:limit]])
    pdf.save()
    csv_path = write_csv(ctx.path("issues-summary_projects", "csv"),
                         ["PROJECT_NAME", "PROJECT_URL", "OPEN", "OPEN_PREV", "NEW", "NEW_PREV", "RESOLVED",
                          "RESOLVED_PREV", "MTTR_DAYS", "MTTR_DAYS_PREV"],
                         ([n, u] + [v for k in ("open", "new", "resolved", "mttr") for v in (c[k], p[k])]
                          for n, u, c, p in projects))
    ctx.summary["issues-summary"] = cur | {f"prev_{k}": v for k, v in prev.items()}
    return [path, csv_path]


REPORTS = {"issues-summary": ("Issues Summary", issues_summary), "issues-detail": ("Issues Detail", issues_detail)}
