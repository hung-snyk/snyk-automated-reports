"""Developer IDE and CLI usage, and Repositories Tested in CI/CD (usage dataset)."""
from collections import Counter, defaultdict
from datetime import timedelta

from ..common import change, jlist, parse_dt, write_csv
from ..panels import d
from ..pdf import M, SERIES, W
from .base import labels, open_pdf, period, week_starts

IDES = {"VS_CODE": "VS Code IDEs", "JETBRAINS": "JetBrains IDEs", "VISUAL_STUDIO": "Visual Studio", "ECLIPSE": "Eclipse"}
PRODUCT_TAGS = {"code": "Snyk Code", "oss": "Snyk Open Source", "iac": "Snyk IaC", "secrets": "Snyk Secrets",
                "container": "Snyk Container"}
CICD_PRODUCTS = ["Snyk Code", "Snyk Open Source", "Snyk IaC", "Snyk Container", "Snyk Secrets"]


def prep(ctx, start, end):
    rows = []
    for r in ctx.data("usage"):
        r["_t"] = parse_dt(r.get("INTERACTION_TIMESTAMP"))
        r["_cat"] = jlist(r.get("INTERACTION_CATEGORIES"))
        if r["_t"]: rows.append(r)
    return rows


def environment(r):
    """Classification that reproduces the UI's counts: agentic = MCP-tagged events,
    IDE = language-server scans, everything else is counted as CLI."""
    if "mcp" in r["_cat"]: return "Agentic integrations"
    if r.get("RUNTIME_APPLICATION_NAME") == "snyk-ls" and r.get("INTERACTION_TYPE") == "Scan done": return "Snyk IDE plugins"
    return "Snyk CLI"


def product(r):
    if r.get("PRODUCT_DISPLAY_NAME"): return r["PRODUCT_DISPLAY_NAME"]
    return next((PRODUCT_TAGS[c] for c in r["_cat"] if c in PRODUCT_TAGS), None)


def group(rows, key):
    g = defaultdict(list)
    for r in rows:
        k = key(r)
        if k: g[k].append(r)
    return sorted(([k, len({x.get("USER_EMAIL") for x in rs}), len(rs)] for k, rs in g.items()), key=lambda t: (-t[2], t[0]))


def dev_ide_cli_usage(ctx):
    start, end = ctx.window(30)
    rows = [r for r in prep(ctx, start, end) if start <= r["_t"] <= end and r.get("INTERACTION_STAGE") != "cicd"]
    for r in rows: r["_env"] = environment(r)
    env = Counter(r["_env"] for r in rows)
    pdf, path = open_pdf(ctx, "dev-ide-cli-usage", "Developer IDE and CLI usage", date_range=(start, end))
    pdf.tiles([{"label": "Developers", "value": len({r.get("USER_EMAIL") for r in rows if r.get("USER_EMAIL")})},
               {"label": "IDE scans", "value": env["Snyk IDE plugins"] + env["Agentic integrations"]},
               {"label": "CLI scans", "value": env["Snyk CLI"]}, {"label": "Agentic scans", "value": env["Agentic integrations"]}])
    cols = lambda first: [(first, 0.5, "text"), ("Developers", 0.25, "num"), ("Scans", 0.25, "num")]
    by_agent = group([r for r in rows if r["_env"] == "Agentic integrations"], lambda r: r.get("RUNTIME_ENVIRONMENT_NAME") or "Not reported")
    by_product = group(rows, product)
    layers = ctx.experimental("IDE/CLI agent and product tables")
    if layers:   # the export has no agent name, and no product for non-scan events; the UI's own panels do
        f = dict(date_range_start=d(start), date_range_end=d(end))
        by_agent = sorted(([r["RUNTIME_ENVIRONMENT_NAME"], r["UNIQUE_DEVELOPERS"], r["TOTAL_SCANS"]]
                           for r in layers.rows("table_unique_developers_by_agent", **f)), key=lambda t: (-t[2], t[0]))
        by_product = sorted(([r["PRODUCT"], r["UNIQUE_DEVELOPERS"], r["TOTAL_SCANS"]]
                             for r in layers.rows("table_unique_developers_by_product", **f)), key=lambda t: (-t[2], t[0]))
    tables = [("Environment usage by developers", "Environment", group(rows, lambda r: r["_env"])),
              ("Developers running scans by IDE", "IDE",
               group([r for r in rows if r["_env"] == "Snyk IDE plugins"], lambda r: IDES.get(r.get("RUNTIME_INTEGRATION_NAME"), "Other IDEs"))),
              ("Developers running scans by Agentic integration", "Agentic Integration", by_agent),
              ("Developers running scans by Snyk Product", "Product Name", by_product)]
    out = [path]
    for title, first, data in tables:
        pdf.section(title)
        pdf.table(cols(first), data, w=900)
        out.append(write_csv(ctx.path(f"dev-ide-cli-usage_by-{first.lower().replace(' ', '-')}", "csv"),
                             [first.upper(), "DEVELOPERS", "SCANS"], data))
    by_org, by_user = defaultdict(list), defaultdict(list)
    for r in rows:
        by_org[r.get("ORG_DISPLAY_NAME") or r.get("ORG_SLUG")].append(r)
        by_user[(r.get("USER_NAME"), r.get("USER_EMAIL"))].append(r)
    org_rows = sorted(([o, f"{max(x['_t'] for x in rs):%b %d, %Y}", len(rs)] for o, rs in by_org.items()), key=lambda t: -t[2])
    user_rows = sorted(([n or "", e or "", f"{max(x['_t'] for x in rs):%b %d, %Y}", len(rs)] for (n, e), rs in by_user.items()),
                       key=lambda t: -t[3])
    pdf.section("Developer adoption rankings", "Adoption by organizations")
    pdf.table([("Organization", 0.5, "text"), ("Last Scan", 0.25, "text"), ("Scans", 0.25, "num")], org_rows, w=900)
    pdf.section("Adoption by individual users")
    pdf.table([("User", 0.3, "text"), ("Email", 0.3, "text"), ("Last Scan", 0.2, "text"), ("Scans", 0.2, "num")], user_rows, w=900)
    pdf.save()
    out.append(write_csv(ctx.path("dev-ide-cli-usage_by-user", "csv"), ["USER", "EMAIL", "LAST_SCAN", "SCANS"], user_rows))
    ctx.summary["dev-ide-cli-usage"] = {"developers": len({r.get("USER_EMAIL") for r in rows if r.get("USER_EMAIL")}),
                                        "ide_scans": env["Snyk IDE plugins"] + env["Agentic integrations"],
                                        "cli_scans": env["Snyk CLI"], "agentic_scans": env["Agentic integrations"]}
    return out


def test_usage_in_cicd(ctx):
    """Committed-repository counts come from SCM commit data that the Export API does not have; they are
    included only with --experimental."""
    start, end = ctx.window(30)
    span = period(start, end)
    rows = [r for r in prep(ctx, start, end) if r.get("INTERACTION_STAGE") == "cicd" and "test" in r["_cat"]]
    for r in rows: r["_prod"] = product(r)
    cur = [r for r in rows if start <= r["_t"] <= end]
    prev = [r for r in rows if start - span <= r["_t"] < start]
    repos = lambda rs, p: len({r.get("INTERACTION_TARGET_ID") for r in rs if r["_prod"] == p})
    ok = lambda rs: sum((r.get("INTERACTION_STATUS") or "").lower() in ("success", "succeeded") for r in rs)
    pdf, path = open_pdf(ctx, "test-usage-in-cicd-pipelines", "Repositories Tested in CI/CD", date_range=(start, end))
    pdf.section("Repositories tested during date range")
    pdf.tiles([{"label": p, "value": repos(cur, p), "badge": (change(repos(cur, p), repos(prev, p)), False),
                "sub": f"{repos(prev, p)} previous period"} for p in CICD_PRODUCTS])
    weeks = week_starts(start, end)
    wk = lambda w: [r for r in cur if w <= r["_t"] < w + timedelta(days=7)]
    series = [("Tested repositories", SERIES[2], [len({r.get("INTERACTION_TARGET_ID") for r in wk(w)}) for w in weeks])]
    layers, committed = ctx.experimental("CI/CD committed repositories"), {}
    if layers:
        f = dict(cli_calendar_start=d(start), cli_calendar_end=d(end))
        by_day = {r["DAY"]: r["TOTAL_REPOS_WITH_RECENT_COMMITS"] or 0 for r in layers.rows("line_repos_with_recent_commits_vs_test_repos", **f)}
        series.append(("Repositories with recent commits", SERIES[4], [by_day.get(d(w), 0) for w in weeks]))
        committed = {r["ORG_DISPLAY_NAME"]: r["COMMITTED_REPOSITORIES_CURRENT"] or 0 for r in layers.rows("table_adoption_by_orgs", **f)}
    pdf.chart_block("Repository Test Adoption", "Repositories tested in CI/CD per week" +
                    (", compared with repositories with recent commits" if committed else ""), labels(weeks), series,
                    advance=False, label_every=1, fill=False)
    pdf.chart_block("Test Success Rate Trend", "The success rate of tests in CI/CD pipelines across the selected date range",
                    labels(weeks), [("Success rate %", SERIES[3], [round(ok(wk(w)) / len(wk(w)) * 100) if wk(w) else 0 for w in weeks])],
                    x=W / 2 + 6, advance=False, label_every=1, fill=False)
    pdf.new_page()
    by_org = defaultdict(list)
    for r in cur: by_org[r.get("ORG_DISPLAY_NAME") or r.get("ORG_SLUG")].append(r)
    for o in committed: by_org.setdefault(o, [])
    org_rows = [[o, len({r.get("INTERACTION_TARGET_ID") for r in rs})] + ([committed.get(o, 0)] if committed else []) +
                [f"{ok(rs) / len(rs) * 100:.0f}%" if rs else "-"] for o, rs in by_org.items()]
    pdf.section("Adoption by Organization")
    pdf.table([("Organization", 0.4, "text"), ("Tested Repositories", 0.2, "num")] +
              ([("Committed Repositories", 0.2, "num")] if committed else []) + [("Success Rate", 0.2, "right")], org_rows, w=900)
    by_repo = defaultdict(list)
    for r in cur: by_repo[r.get("INTERACTION_TARGET_ID") or "Unknown"].append(r)
    repo_rows = [[t, f"{max(r['_t'] for r in rs):%b %d, %Y}", rs[0].get("ORG_DISPLAY_NAME") or ""] +
                 ["Tested" if any(r["_prod"] == p for r in rs) else "-" for p in CICD_PRODUCTS] for t, rs in by_repo.items()]
    pdf.section("Repository Test Summary", "Review of the tests performed on repositories by CI/CD pipelines within selected date range")
    pdf.table([("Repository", 0.3, "text"), ("Last Test", 0.1, "text"), ("Organization", 0.1, "text")] +
              [(p, 0.1, "text") for p in CICD_PRODUCTS], repo_rows, empty="No data to display.")
    pdf.save()
    csv_path = write_csv(ctx.path("test-usage-in-cicd-pipelines", "csv"),
                         ["REPOSITORY", "LAST_TEST", "ORGANIZATION"] + [p.upper() for p in CICD_PRODUCTS], repo_rows)
    ctx.summary["test-usage-in-cicd-pipelines"] = {**{p: repos(cur, p) for p in CICD_PRODUCTS},
                                                   "tested_repos": len({r.get("INTERACTION_TARGET_ID") for r in cur}),
                                                   **({"committed_repos": sum(committed.values())} if committed else {})}
    return [path, csv_path]


REPORTS = {"dev-ide-cli-usage": ("Developer IDE and CLI usage", dev_ide_cli_usage),
           "test-usage-in-cicd-pipelines": ("Repositories Tested in CI/CD", test_usage_in_cicd)}
