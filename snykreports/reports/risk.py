"""Risk Exposure and Vulnerabilities Detail."""
from collections import Counter, defaultdict

from ..common import SEVERITIES, is_open_at, jlist, write_csv
from ..pdf import M, SEV_COLOR, W
from .base import days, labels, open_pdf


def breakdown(rows, key):
    """[(dimension value, [critical, high, medium, low], impacted assets)] sorted by critical desc."""
    sev, assets = defaultdict(Counter), defaultdict(set)
    for r in rows:
        k = r.get(key) or "Unknown"
        sev[k][r.get("ISSUE_SEVERITY")] += 1
        if r.get("ASSET_ID"): assets[k].add(r["ASSET_ID"])
    out = [(k, [c[s] for s in SEVERITIES], len(assets[k])) for k, c in sev.items()]
    return sorted(out, key=lambda t: [-v for v in t[1]])


def risk_exposure(ctx):
    rows = ctx.issues()
    open_ = [r for r in rows if r["_status"] == "Open"]
    start, end = ctx.window(30)
    pts = days(start, end)
    sev = Counter(r.get("ISSUE_SEVERITY") for r in open_)
    pdf, path = open_pdf(ctx, "risk-exposure", "Risk Exposure", [("Severity Source", "Snyk")], (start, end))
    pdf.tiles([{"label": "Open issues", "value": len(open_)}] +
              [{"label": s, "value": sev[s], "sev": s} for s in SEVERITIES] +
              [{"label": "Impacted assets", "value": len({r["ASSET_ID"] for r in open_ if r.get("ASSET_ID")})}])
    trend = {s: [sum(1 for r in rows if r.get("ISSUE_SEVERITY") == s and is_open_at(r, d)) for d in pts] for s in SEVERITIES}
    pdf.chart_block("Open issues by Selected Severity",
                    "Trend of open issues based on when issues were first introduced and last resolved.",
                    labels(pts), [(s, SEV_COLOR[s], trend[s]) for s in SEVERITIES], w=W_FULL, h=260, fill=False)
    out = [path]
    cols = [("Critical", 0.12, "num"), ("High", 0.12, "num"), ("Medium", 0.12, "num"), ("Low", 0.12, "num"),
            ("Impacted Assets", 0.14, "num")]
    for title, key, slug in [("Introduction Category", "INTRODUCTION_CATEGORY", "introduction-category"),
                             ("Snyk Product", "PRODUCT_NAME", "product"), ("Project Target", "PROJECT_TARGET_DISPLAY_NAME", "target")]:
        data = breakdown(open_, key)
        pdf.section(f"Risk breakdown by {title}", "A breakdown of impacted assets and open issues according to the selected severity source")
        pdf.table([(title, 0.38, "text")] + cols, [[k] + v + [a] for k, v, a in data])
        out.append(write_csv(ctx.path(f"risk-exposure_by-{slug}", "csv"), [title.upper()] + [s.upper() for s in SEVERITIES] + ["IMPACTED_ASSETS"],
                             ([k] + v + [a] for k, v, a in data)))
    pdf.save()
    ctx.summary["risk-exposure"] = {"open": len(open_), **{s.lower(): sev[s] for s in SEVERITIES},
                                    "impacted_assets": len({r["ASSET_ID"] for r in open_ if r.get("ASSET_ID")})}
    return out


def vulnerabilities_detail(ctx):
    open_ = ctx.issues(["Open"])
    vulns = defaultdict(list)
    for r in open_: vulns[r.get("PROBLEM_ID")].append(r)
    table = []
    for pid, rs in vulns.items():
        r = rs[0]
        table.append({"type": r.get("ISSUE_TYPE"), "title": r.get("PROBLEM_TITLE"), "id": pid, "sev": r.get("ISSUE_SEVERITY"),
                      "score": int(float(r.get("SCORE") or 0)), "cve": ", ".join(jlist(r.get("CVE"))) or "Not Available",
                      "cwe": ", ".join(jlist(r.get("CWE"))), "product": r.get("PRODUCT_NAME"), "url": r.get("VULN_DB_URL"),
                      "targets": len({x.get("PROJECT_TARGET_DISPLAY_NAME") for x in rs}),
                      "projects": len({x.get("PROJECT_PUBLIC_ID") for x in rs}), "issues": len(rs)})
    table.sort(key=lambda v: (-v["projects"], -v["issues"], -v["score"]))
    by_type = Counter(v["type"] for v in table)
    pdf, path = open_pdf(ctx, "vulnerabilities-detail", "Vulnerabilities Detail", [("Issue Status", "Open")])
    pdf.tiles([{"label": "Total issues", "value": len(open_)}, {"label": "Unique vulns", "value": len(table)}] +
              [{"label": t.title(), "value": n} for t, n in by_type.most_common()])
    limit = ctx.args.max_rows or len(table)
    pdf.section("Vulnerability Details", f"Sorted by projects affected. Showing {min(limit, len(table)):,} of {len(table):,}; the CSV has all rows.")
    pdf.table([("Issue", 0.25, "link"), ("Severity", 0.06, "sev"), ("Score", 0.05, "num"), ("CVE", 0.14, "text"),
               ("CWE", 0.1, "text"), ("Snyk Product", 0.12, "text"), ("Targets", 0.09, "num"), ("Projects", 0.09, "num"),
               ("Issue Count", 0.1, "num")],
              [[(f"{v['title']}  {v['id']}", v["url"]), v["sev"], v["score"], v["cve"], v["cwe"], v["product"],
                v["targets"], v["projects"], v["issues"]] for v in table[:limit]])
    pdf.save()
    csv_path = write_csv(ctx.path("vulnerabilities-detail", "csv"),
                         ["ISSUE_TYPE", "ISSUE", "PROBLEM_ID", "SEVERITY", "SCORE", "CVE", "CWE", "SNYK_PRODUCT", "TARGETS",
                          "PROJECTS", "ISSUE_COUNT", "VULN_DB_URL"],
                         ([v["type"], v["title"], v["id"], v["sev"], v["score"], v["cve"], v["cwe"], v["product"],
                           v["targets"], v["projects"], v["issues"], v["url"]] for v in table))
    ctx.summary["vulnerabilities-detail"] = {"total_issues": len(open_), "unique_vulns": len(table), **dict(by_type)}
    return [path, csv_path]


W_FULL = W - 2 * M
REPORTS = {"risk-exposure": ("Risk Exposure", risk_exposure),
           "vulnerabilities-detail": ("Vulnerabilities Detail", vulnerabilities_detail)}
