"""Analytics Overview: the dashboard on the Analytics landing page (KPIs, exposure, remediation, usage)."""
from collections import Counter
from datetime import timedelta

from ..common import SEVERITIES, change, days_between, is_open_at, jlist, parse_dt, write_csv
from ..pdf import M, SERIES, SEV_COLOR, W
from .base import days, labels, open_pdf, period, week_starts

MTTR_BUCKETS = [("Less than 15 days", 0, 15), ("15-30 days", 15, 30.000001), ("More than 30 days", 30.000001, 10**6)]


def analytics_overview(ctx):
    rows = ctx.issues()
    start, end = ctx.window(30)
    span = period(start, end)
    ignored = sum(1 for r in ctx.data("issues") if r["_status"] == "Ignored")
    new = lambda a, b: [r for r in rows if a <= r["_open_from"] < b]
    resolved = lambda a, b: [r for r in rows if r["_res"] and a <= r["_res"] < b]
    # unique vulnerabilities = distinct vulnerabilities among the period's new issues that are still open
    unique = lambda a, b: len({r.get("PROBLEM_ID") for r in new(a, b) if r["_status"] == "Open"})
    cur = {"open": sum(1 for r in rows if is_open_at(r, end)), "new": len(new(start, end)),
           "resolved": len(resolved(start, end)), "unique_vulns": unique(start, end), "ignored": ignored}
    prev = {"open": sum(1 for r in rows if is_open_at(r, start)), "new": len(new(start - span, start)),
            "resolved": len(resolved(start - span, start)), "unique_vulns": unique(start - span, start)}

    pdf, path = open_pdf(ctx, "analytics-overview", "Analytics Overview", date_range=(start, end))
    pdf.section("Key Performance Indicators")
    tile = lambda label, k, up_bad: {"label": label, "value": cur[k], "badge": (change(cur[k], prev[k]), up_bad),
                                     "sub": f"{prev[k]:,} previous period"}
    pdf.tiles([tile("Open Issues", "open", True), {"label": "Ignored Issues", "value": ignored},
               tile("New Issues", "new", True), tile("Resolved Issues", "resolved", False),
               tile("Unique vulnerabilities", "unique_vulns", True)])
    pts = days(start, end)
    pdf.chart_block("Open issues over time, by severity", "Exposure", labels(pts),
                    [(s, SEV_COLOR[s], [sum(1 for r in rows if r.get("ISSUE_SEVERITY") == s and is_open_at(r, d)) for d in pts])
                     for s in SEVERITIES], fill=False, advance=False)
    by_product = Counter(r.get("PRODUCT_NAME") for r in rows if r["_status"] == "Open")
    total_open = sum(by_product.values()) or 1
    pdf.top = pdf.section("Open issues by Snyk product", x=W / 2 + 6, advance=False)
    pdf.table([("Snyk Product", 0.5, "text"), ("Open Issues", 0.25, "num"), ("Share", 0.25, "right")],
              [[p, n, f"{n / total_open * 100:.2f}%"] for p, n in by_product.most_common()], x=W / 2 + 6, w=W / 2 - 6 - M)
    pdf.new_page()
    pdf.chart_block("Issues identified and resolved over time", "Remediation", labels(pts),
                    [("Identified issues", SERIES[2], [sum(1 for r in rows if r["_intro"] <= d) for d in pts]),
                     ("Resolved issues", SERIES[3], [sum(1 for r in rows if r["_res"] and r["_res"] <= d) for d in pts])],
                    fill=False, advance=False)
    ttr = [days_between(r["_intro"], r["_res"]) for r in resolved(start, end)]
    mttr = [[name, sum(1 for t in ttr if lo <= t < hi)] for name, lo, hi in MTTR_BUCKETS]
    pdf.top = pdf.section("Resolved issues by MTTR duration", f"{len(ttr):,} resolved issues", x=W / 2 + 6, advance=False)
    pdf.table([("Time to resolve", 0.5, "text"), ("Resolved Issues", 0.25, "num"), ("Share", 0.25, "right")],
              [[n, c, f"{c / len(ttr) * 100:.2f}%" if ttr else "0%"] for n, c in mttr], x=W / 2 + 6, w=W / 2 - 6 - M)
    pdf.new_page()
    # the UI counts calendar weeks (Monday to Sunday) that begin inside the window
    first_monday = start + timedelta(days=-start.weekday() % 7)
    weeks = week_starts(first_monday, end) if first_monday <= end else []
    # developers who ran a scan (events tagged "test"); logins and config changes don't count, as in the UI
    usage = [(parse_dt(u.get("INTERACTION_TIMESTAMP")), u.get("USER_EMAIL")) for u in ctx.data("usage")
             if u.get("INTERACTION_STAGE") != "cicd" and "test" in jlist(u.get("INTERACTION_CATEGORIES"))]
    devs = [len({e for t, e in usage if t and e and w <= t < w + timedelta(days=7)}) for w in weeks]
    pdf.chart_block("Snyk IDE & CLI usage over time (developer count)", "Usage", labels(weeks),
                    [("Developer count", SERIES[2], devs)], smooth=True, label_every=1, fill=False, advance=False)
    by_cat = Counter(r.get("INTRODUCTION_CATEGORY") or "Unknown" for r in new(start, end))
    pdf.top = pdf.section("New issues by introduction category", f"{cur['new']:,} new issues", x=W / 2 + 6, advance=False)
    pdf.table([("Introduction Category", 0.5, "text"), ("New Issues", 0.25, "num"), ("Share", 0.25, "right")],
              [[k, n, f"{n / (cur['new'] or 1) * 100:.2f}%"] for k, n in by_cat.most_common()], x=W / 2 + 6, w=W / 2 - 6 - M)
    pdf.save()
    csv_path = write_csv(ctx.path("analytics-overview_kpis", "csv"), ["METRIC", "CURRENT", "PREVIOUS"],
                         [[k, cur[k], prev.get(k, "")] for k in cur])
    ctx.summary["analytics-overview"] = {**cur, **{f"prev_{k}": v for k, v in prev.items()},
                                         "mttr_buckets": {n: c for n, c in mttr}, "new_by_category": dict(by_cat),
                                         "weekly_developers": {f"{w:%Y-%m-%d}": n for w, n in zip(weeks, devs)}}
    return [path, csv_path]


REPORTS = {"analytics-overview": ("Analytics Overview", analytics_overview)}
