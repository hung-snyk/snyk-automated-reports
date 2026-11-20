"""Zero-Day: progress on one or more named vulnerabilities (--zero-day CVE-... or SNYK-..., repeatable).

The UI opens this report on Snyk's curated active incident, with an "Assets involved in the incident" panel. No
supported API returns that incident, so this report always tracks the vulnerabilities named with --zero-day."""
from collections import Counter, defaultdict

from ..common import SEV_RANK, is_open_at, jlist, write_csv
from ..pdf import M, SERIES, W
from .base import days, labels, open_pdf


def zero_day(ctx):
    cves = {c.strip().upper() for c in ctx.args.zero_day or [] if c.strip()}
    if not cves:
        ctx.skipped["zero-day"] = ("name the vulnerabilities to track with --zero-day CVE-YYYY-NNNN or SNYK-... (or set "
                                   "ZERO_DAY_CVE); Snyk's active zero-day incident has no supported API")
        return []
    all_rows = [r for r in ctx.data("issues") if r.get("PROBLEM_ID") in cves or cves & set(jlist(r.get("CVE")))]
    status = Counter(r["_status"] for r in all_rows)
    rows = [r for r in all_rows if r["_status"] != "Ignored"]
    start, end = ctx.window(30)
    pts = days(start, end)
    label = ", ".join(sorted(cves))
    pdf, path = open_pdf(ctx, "zero-day", "Zero-Day", [("Zero-Day Vulnerability", label)], (start, end))
    pdf.section(f"Issues for {label}")
    pdf.tiles([{"label": "Open Issues Remaining", "value": status["Open"]}, {"label": "Resolved Issues", "value": status["Resolved"]},
               {"label": "Ignored Issues", "value": status["Ignored"]}], w=900)
    targets = defaultdict(Counter)
    for r in rows: targets[r.get("PROJECT_TARGET_DISPLAY_NAME") or "Unknown"][r["_status"]] += 1
    trows = sorted(([t, c["Open"], c["Resolved"]] for t, c in targets.items()), key=lambda x: (-x[1], x[0]))
    pdf.section("Impacted Repositories", "Breakdown of the selected zero-day vulnerability issues across targets.")
    pdf.table([("Target Name", 0.6, "text"), ("Open Issues", 0.2, "num"), ("Resolved Issues", 0.2, "num")], trows)
    issues = sorted(all_rows, key=lambda r: (-float(r.get("SCORE") or 0), -SEV_RANK.get(r.get("ISSUE_SEVERITY"), 0)))
    pdf.section("All Issues", "Summary of all issues for the selected zero-day vulnerability.")
    pdf.table([("Severity", 0.06, "sev"), ("Score", 0.05, "num"), ("CVE", 0.11, "text"), ("Issue", 0.17, "link"),
               ("CWE", 0.07, "text"), ("Project", 0.2, "link"), ("Exploit Maturity", 0.09, "text"),
               ("Computed Fixability", 0.08, "text"), ("Introduced", 0.08, "text"), ("Snyk Product", 0.09, "text")],
              [[r.get("ISSUE_SEVERITY"), int(float(r.get("SCORE") or 0)), ", ".join(jlist(r.get("CVE"))),
                (r.get("PROBLEM_TITLE"), r.get("ISSUE_URL")), ", ".join(jlist(r.get("CWE"))),
                (r.get("PROJECT_NAME"), r.get("PROJECT_URL")), r.get("EXPLOIT_MATURITY"), r.get("COMPUTED_FIXABILITY"),
                f"{r['_intro']:%b %d, %Y}", r.get("PRODUCT_NAME")] for r in issues])
    pdf.chart_block("Accumulative Issues Backlog Trend", "Recent trend of open issues for the selected zero-day vulnerability.",
                    labels(pts), [("Open issues", SERIES[0], [sum(1 for r in rows if is_open_at(r, d)) for d in pts])],
                    w=W - 2 * M, h=220)
    pdf.chart_block("Issues Identified and Resolved Over Time",
                    "New issues identified for the selected zero-day vulnerability against remediation progress.", labels(pts),
                    [("Identified", SERIES[0], [sum(1 for r in rows if r["_intro"] <= d) for d in pts]),
                     ("Resolved", SERIES[2], [sum(1 for r in rows if r["_res"] and r["_res"] <= d) for d in pts])],
                    w=W - 2 * M, h=220, fill=False)
    pdf.save()
    csv_path = write_csv(ctx.path("zero-day", "csv"),
                         ["SEVERITY", "SCORE", "CVE", "ISSUE", "CWE", "PROJECT", "TARGET", "STATUS", "EXPLOIT_MATURITY",
                          "COMPUTED_FIXABILITY", "INTRODUCED", "SNYK_PRODUCT", "ISSUE_URL"],
                         ([r.get("ISSUE_SEVERITY"), r.get("SCORE"), ", ".join(jlist(r.get("CVE"))), r.get("PROBLEM_TITLE"),
                           ", ".join(jlist(r.get("CWE"))), r.get("PROJECT_NAME"), r.get("PROJECT_TARGET_DISPLAY_NAME"),
                           r["_status"], r.get("EXPLOIT_MATURITY"), r.get("COMPUTED_FIXABILITY"), r.get("FIRST_INTRODUCED"),
                           r.get("PRODUCT_NAME"), r.get("ISSUE_URL")] for r in issues))
    ctx.summary.setdefault("zero-day", {}).update({"cve": label, "open": status["Open"], "resolved": status["Resolved"], "ignored": status["Ignored"]})
    return [path, csv_path]


REPORTS = {"zero-day": ("Zero-Day", zero_day)}
