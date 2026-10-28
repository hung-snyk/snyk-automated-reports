"""Optional: Snyk Analytics' internal reporting API, the "layers" behind each UI panel.

It is undocumented and versioned as experimental (2023-02-24~experimental), so Snyk can change or remove it
without notice. It is only used when asked for:
  --internal-api  fills panels the Export API has no data for (and the Snyk Generated Pull Requests report)
  verify()        compares this tool's headline numbers with what the UI computes (used by a maintainer-only check)
"""
import json, time, urllib.error, urllib.request

from .api import fail, log

LAYER_VERSION = "2023-02-24~experimental"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None


class Layers:
    def __init__(self, base, scope, scope_id, token, timeout=300):
        self.base, self.token, self.timeout = base, token, timeout
        self.root = f"/hidden/{scope}/{scope_id}/reporting/layers"
        self._open = urllib.request.build_opener(_NoRedirect).open
        self._cache = {}

    def _req(self, method, path, body=None):
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"token {self.token}", "Content-Type": "application/vnd.api+json"})
        for attempt in range(4):
            try:
                with self._open(req, timeout=120) as r:
                    return r.status, r.read().decode()
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 504) and attempt < 3:
                    time.sleep(2 ** attempt * 3); continue
                return e.code, e.read().decode()[:500]
            except urllib.error.URLError as e:
                if attempt < 3: time.sleep(2 ** attempt * 3); continue
                fail(f"cannot reach {self.base}: {e.reason}")

    def rows(self, layer, **filters):
        """Render one panel and return its rows as plain dicts (column -> value)."""
        key = (layer, json.dumps(filters, sort_keys=True))
        if key in self._cache: return self._cache[key]
        body = {"output": "dataframe", "layer": layer,
                "filters": {k: {"operator": "include", "value": v} for k, v in filters.items() if v not in (None, "", [])}}
        status, text = self._req("POST", f"{self.root}/{layer}/renders?version={LAYER_VERSION}", body)
        if status != 202: raise LayerError(f"{layer}: HTTP {status} {text[:200]}")
        location, deadline = json.loads(text)["location"], time.time() + self.timeout
        while True:
            status, text = self._req("GET", location)
            if status != 202: break
            if time.time() > deadline: raise LayerError(f"{layer}: timed out")
            time.sleep(1.5)
        if status != 200: raise LayerError(f"{layer}: HTTP {status} {text[:200]}")
        res = json.loads(text).get("results") or {}
        out = [{k: (v or {}).get("value") for k, v in r.items()} for r in res.get("rows", [])]
        self._cache[key] = out
        return out


class LayerError(Exception):
    pass


def d(t):
    return t.strftime("%Y-%m-%d")


def verify(ctx):
    """Compare headline numbers in ctx.summary with the UI's own panels. Returns [(report, metric, ours, ui)]."""
    L, s, out = ctx.layers(), ctx.summary, []

    def add(report, metric, ours, ui):
        out.append((report, metric, ours, ui))

    def first(rows, col, default=None):
        return rows[0].get(col, default) if rows else default

    checks = []
    if "issues-summary" in s:
        a, b = ctx.window(30); f = dict(dashboard_start=d(a), dashboard_end=d(b)); x = s["issues-summary"]
        for metric, layer in [("open", "dashboard_kpi_open_issues"), ("new", "dashboard_kpi_new_issues"),
                              ("resolved", "dashboard_kpi_resolved_issues")]:
            checks.append(lambda metric=metric, layer=layer, f=f, x=x: (
                add("issues-summary", metric, x[metric], first(L.rows(layer, **f), "CURRENT_COUNT")),
                add("issues-summary", f"previous {metric}", x[f"prev_{metric}"], first(L.rows(layer, **f), "PAST_COUNT"))))
    if "analytics-overview" in s:
        a, b = ctx.window(30); f = dict(dashboard_start=d(a), dashboard_end=d(b)); x = s["analytics-overview"]
        checks.append(lambda f=f, x=x: (
            add("analytics-overview", "unique vulnerabilities", x["unique_vulns"], first(L.rows("dashboard_kpi_unique_vulns", **f), "CURRENT_COUNT")),
            add("analytics-overview", "ignored", x["ignored"], first(L.rows("dashboard_kpi_ignored_issues", **f), "CURRENT_COUNT")),
            [add("analytics-overview", f"developers, week of {r['SCAN_WEEK']}", x["weekly_developers"].get(r["SCAN_WEEK"]), r["COUNT_DEVS"])
             for r in L.rows("dashboard_line_ide_developers", **f)]))
    for slug, layer in [("owasp-top-10-2025", "table_owasp_2025"), ("cwe-top-25-2023", "table_cwe_top_25_2023"),
                        ("cwe-top-10-kev-2023", "table_cwe_top_10_kev_2023")]:
        if slug in s:
            a, b = ctx.window(30)
            checks.append(lambda slug=slug, layer=layer, a=a, b=b: [
                add(slug, r["CONTROL_FULL_NAME"], s[slug]["controls"].get(r["CONTROL_FULL_NAME"], s[slug]["total"]
                    if r["CONTROL_FULL_NAME"] == "All Controls" else None), r["TOTAL"])
                for r in L.rows(layer, issue_status=["Open"], introduced_start=d(a), introduced_end=d(b))])
    if "pci-dss-v4.0.1" in s:
        a, b = ctx.window(30); x = s["pci-dss-v4.0.1"]
        checks.append(lambda a=a, b=b, x=x: [
            add("pci-dss-v4.0.1", label, x[key], sum(r[col] or 0 for r in L.rows(
                "table_attack_category_breakdown", issue_status=["Open"], issue_severity=x["severities"],
                introduced_start=d(a), introduced_end=d(b)) if r.get("ATTACK_CATEGORY") != "Total"))
            for label, key, col in [("under 15 days", "under_15", "FIFTEEN"), ("15-30 days", "15_30", "FIFTEEN_THIRTY"),
                                    ("over 30 days", "over_30", "THIRTY")]])
    if "sla-management" in s:
        x = s["sla-management"]
        f = {"issue_severity": x["severities"], **{f"sla_targets_{k.lower()}": str(v[0]) for k, v in x["targets"].items()},
             **{f"sla_at_risk_{k.lower()}": str(v[1]) for k, v in x["targets"].items()}}
        cols = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        status_total = lambda rows, st: sum(sum(r[c] or 0 for c in cols) for r in rows if r["SLA_STATUS"].lower() == st)
        checks.append(lambda f=f, x=x: [
            add("sla-management", f"open {label}", x[key], status_total(L.rows("open_issues_sla_severity_breakdown_v2", **f), st))
            for label, key, st in [("within SLA", "open_within_sla", "within sla"), ("at risk", "open_at_risk", "at risk"),
                                   ("breached", "open_breached", "breached")]] + [
            add("sla-management", "resolved within SLA", x["resolved_within_sla"],
                status_total(L.rows("resolved_issues_sla_severity_breakdown_v2", **f), "within sla"))])
    if "dev-ide-cli-usage" in s:
        a, b = ctx.window(30); x = s["dev-ide-cli-usage"]
        checks.append(lambda a=a, b=b, x=x: [
            add("dev-ide-cli-usage", label, x[key], first(L.rows("big_numbers_developer_scan_counts_v2", date_range_start=d(a), date_range_end=d(b)), col))
            for label, key, col in [("developers", "developers", "TOTAL_DEVELOPERS_RUNNING_SCANS"), ("IDE scans", "ide_scans", "SCANS_USING_IDE"),
                                    ("CLI scans", "cli_scans", "SCANS_USING_CLI"), ("agentic scans", "agentic_scans", "SCANS_USING_AGENTS")]])
    if "pr-checks-usage" in s:
        a, b = ctx.window(30); x = s["pr-checks-usage"]; f = dict(pr_check_usage_start=d(a), pr_check_usage_end=d(b))
        checks.append(lambda f=f, x=x: (
            add("pr-checks-usage", "total PR checks", x["total"], first(L.rows("big_num_pr_checks_usage_banner_metrics", **f), "TOTAL_PR_CHECKS_CURRENT")),
            add("pr-checks-usage", "pull requests", x["pull_requests"], first(L.rows("big_num_pr_checks_pull_request_overview_adoption_metrics", **f), "TOTAL_PULL_REQUESTS_CURRENT")),
            add("pr-checks-usage", "repos with Snyk Code PR checks", x["code_repos_enabled"],
                first(L.rows("big_num_pr_checks_pull_request_overview_adoption_metrics", **f), "TOTAL_SNYK_CODE_REPO_PR_CHECKS_ENABLED_CURRENT"))))
    if "test-usage-in-cicd-pipelines" in s:
        a, b = ctx.window(30)
        checks.append(lambda a=a, b=b: add("test-usage-in-cicd-pipelines", "tested repositories", s["test-usage-in-cicd-pipelines"]["tested_repos"],
                                           sum(r["TESTED_REPOS_CURRENT"] or 0 for r in L.rows("table_adoption_by_orgs", cli_calendar_start=d(a), cli_calendar_end=d(b)))))
    for check in checks:
        try: check()
        except LayerError as e: log(f"verify: {e}")
    return out
