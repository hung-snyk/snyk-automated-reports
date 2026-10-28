"""Pull Request Checks Usage & Performance (pr_checks and pr_checks_project_adoption datasets)."""
from collections import Counter, defaultdict

from ..common import change, parse_dt, write_csv
from ..pdf import M, SERIES, W
from .base import days, labels, open_pdf

PRODUCTS = [("Snyk Code", "Repos with Snyk Code PR scan"), ("Snyk Open Source", "Repos with Open Source PR scan")]


def status(r):
    if (r.get("MARKED_AS_SUCCESS") or "").lower() == "true": return "Marked successful"
    return {"success": "Auto-successful", "failure": "Failed", "error": "Error"}.get(r.get("PR_CHECK_STATE"), "Error")


def pr_checks_usage(ctx):
    start, end = ctx.window(30)
    span = end - start
    rows = ctx.data("pr_checks")
    for r in rows: r["_t"], r["_st"] = parse_dt(r.get("PR_CHECK_CREATED_AT")), status(r)
    cur = [r for r in rows if r["_t"] and start <= r["_t"] <= end]
    prev = [r for r in rows if r["_t"] and start - span <= r["_t"] < start]
    ok = lambda rs: sum(r["_st"] in ("Auto-successful", "Marked successful") for r in rs)
    rate = lambda rs: round(ok(rs) / len(rs) * 100) if rs else 0
    sc, sp = Counter(r["_st"] for r in cur), Counter(r["_st"] for r in prev)
    pct = lambda c, n, tot: round(c[n] / tot * 100) if tot else 0
    pdf, path = open_pdf(ctx, "pr-checks-usage", "Pull Request Checks Usage & Performance", date_range=(start, end))
    pdf.tiles([{"label": "Total PR checks", "value": len(cur), "badge": (change(len(cur), len(prev)), False)},
               {"label": "PR check success rate", "value": f"{rate(cur)}%", "badge": (rate(cur) - rate(prev), False),
                "sub": f"{ok(cur)} PR checks"}], w=700)
    pdf.section("Performance and status")
    items = [("Successful", ok(cur), ok(prev), False)] + \
            [(n, sc[n], sp[n], n in ("Failed", "Error")) for n in ("Auto-successful", "Marked successful", "Failed", "Error")]
    pdf.tiles([{"label": n, "value": f"{round(c / len(cur) * 100) if cur else 0}%",
                "badge": ((round(c / len(cur) * 100) if cur else 0) - (round(p / len(prev) * 100) if prev else 0), bad),
                "sub": f"{c} PR checks"} for n, c, p, bad in items])
    pts = days(start, end)
    states = ["Auto-successful", "Marked successful", "Failed", "Error"]
    pdf.chart_block("PR checks by status over time", "Daily PR checks per status.", labels(pts),
                    [(s, col, [sum(1 for r in cur if r["_st"] == s and r["_t"].date() == d.date()) for d in pts])
                     for s, col in zip(states, [SERIES[2], SERIES[4], SERIES[0], SERIES[1]])], w=W - 2 * M, h=200, fill=False)
    by_prod = defaultdict(Counter)
    for r in cur: by_prod[r.get("PRODUCT_NAME") or "Unknown"][r["_st"]] += 1
    pdf.section("PR check status by Snyk Product")
    pdf.table([("Snyk Product", 0.4, "text"), ("All Checks", 0.15, "num"), ("Successful", 0.15, "num"), ("Failed", 0.15, "num"),
               ("Error", 0.15, "num")],
              [[p, sum(c.values()), c["Auto-successful"] + c["Marked successful"], c["Failed"], c["Error"]] for p, c in by_prod.items()],
              w=900)
    errs = Counter(r.get("ERROR_MESSAGE") or "Unknown error" for r in cur if r["_st"] == "Error")
    pdf.section("Error PR checks by error message")
    pdf.table([("Error Message", 0.75, "text"), ("Total PR Checks", 0.25, "num")], [[m, n] for m, n in errs.most_common()], w=900)

    # adoption: latest settings per project
    # PROJECT_DELETED holds a deletion timestamp; deleted projects drop out, as in the UI
    adoption = [a for a in ctx.data("pr_checks_project_adoption") if (a.get("IS_CURRENT_SETTINGS") or "").lower() == "true"
                and not a.get("PROJECT_DELETED")]
    repos = defaultdict(dict)
    for a in adoption:
        # an empty project setting inherits the integration's PR-check setting
        enabled = (a.get("TEST_PULL_REQUESTS") or "inherit").lower() not in ("false", "disabled", "0")
        repos[a.get("REPOSITORY_NAME") or "Unknown"][a.get("PRODUCT_NAME")] = repos[a.get("REPOSITORY_NAME") or "Unknown"].get(
            a.get("PRODUCT_NAME"), False) or enabled
        repos[a.get("REPOSITORY_NAME") or "Unknown"]["_source"] = a.get("SOURCE_INTEGRATION_TYPE") or ""
    prs = lambda rs: {(r.get("REPOSITORY_NAME"), r.get("PULL_REQUEST")) for r in rs}
    failed_prs = lambda rs: {(r.get("REPOSITORY_NAME"), r.get("PULL_REQUEST")) for r in rs if r["_st"] == "Failed"}
    tiles = []
    for prod, label in PRODUCTS:
        have = [r for r in repos.values() if prod in r]
        on = sum(1 for r in have if r[prod])
        tiles.append({"label": label, "value": f"{round(on / len(have) * 100) if have else 0}%", "sub": f"{on} of {len(have)} repositories"})
    tiles += [{"label": "Total Pull-requests", "value": len(prs(cur)), "badge": (change(len(prs(cur)), len(prs(prev))), False)},
              {"label": "PRs with failed checks", "value": len(failed_prs(cur)), "badge": (change(len(failed_prs(cur)), len(failed_prs(prev))), True),
               "sub": f"{round(len(failed_prs(cur)) / len(prs(cur)) * 100) if prs(cur) else 0}% of pull-requests"}]
    pdf.new_page()
    pdf.section("Pull-request overview & adoption")
    pdf.tiles(tiles)
    on_off = lambda v: "Enabled" if v else ("Disabled" if v is not None else "Not applicable")
    pdf.section("PR scanning adoption by Repository")
    adopt_rows = sorted([[name, r.get("_source", ""), on_off(r.get("Snyk Code")), on_off(r.get("Snyk Open Source"))]
                         for name, r in repos.items()], key=lambda x: x[0])
    pdf.table([("Repository", 0.46, "text"), ("Source", 0.18, "text"), ("Snyk Code PR Scan Status", 0.18, "text"),
               ("Open Source PR Scan Status", 0.18, "text")], adopt_rows)
    perf = defaultdict(list)
    for r in cur: perf[r.get("REPOSITORY_NAME") or "Unknown"].append(r)
    perf_rows = sorted(([n, len(prs(rs)), len(failed_prs(rs)), f"{len(failed_prs(rs)) / len(prs(rs)) * 100:.1f}%"]
                        for n, rs in perf.items()), key=lambda x: (-x[2] / max(x[1], 1), x[0]))
    pdf.section("PR scanning performance by Repository")
    pdf.table([("Repository", 0.46, "text"), ("Total Pull-Requests", 0.18, "num"), ("PRs With Failed Checks", 0.18, "num"),
               ("% PRs With Failed Checks", 0.18, "right")], perf_rows)
    pdf.save()
    out = [path, write_csv(ctx.path("pr-checks-usage_performance-by-repository", "csv"),
                           ["REPOSITORY", "TOTAL_PULL_REQUESTS", "PRS_WITH_FAILED_CHECKS", "PCT_FAILED"], perf_rows),
           write_csv(ctx.path("pr-checks-usage_adoption-by-repository", "csv"),
                     ["REPOSITORY", "SOURCE", "SNYK_CODE_PR_SCAN", "OPEN_SOURCE_PR_SCAN"], adopt_rows)]
    ctx.summary["pr-checks-usage"] = {"total": len(cur), "success_rate_pct": rate(cur), "failed": sc["Failed"],
                                      "pull_requests": len(prs(cur)), "prs_failed": len(failed_prs(cur)),
                                      **{t["label"]: t["sub"] for t in tiles[:2]}}
    return out


REPORTS = {"pr-checks-usage": ("Pull Request Checks Usage & Performance", pr_checks_usage)}
