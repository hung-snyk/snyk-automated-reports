"""Snyk Generated Pull Requests. No public API exposes Snyk-created PRs, so this report needs --internal-api
(the UI's undocumented reporting API)."""
from ..common import write_csv
from ..internal import LayerError, d
from .base import open_pdf


def snyk_generated_prs(ctx):
    layers = ctx.internal()
    if not layers:
        ctx.skipped["snyk-generated-prs"] = "needs --internal-api (no public API exposes Snyk-generated PR data)"
        return []
    start, end = ctx.window(90)
    f = dict(pr_activity_start=d(start), pr_activity_end=d(end))
    try:
        big = (layers.rows("prs_big_numbers", **f) or [{}])[0]
        by_status = layers.rows("table_pr_by_status", **f)
        issues = layers.rows("prs_issues_table", **f)
        repos = layers.rows("table_pr_repo_breakdown", **f)
    except LayerError as e:
        ctx.skipped["snyk-generated-prs"] = f"internal API error: {e}"
        return []
    hours = big.get("HOURS_TO_MERGE")
    ttm = "No merges" if hours is None else (f"{hours / 24:.1f} days" if hours >= 24 else f"{hours:.1f} hours")
    pct = lambda v: f"{(v or 0) * 100:.2f}%" if (v or 0) <= 1 else f"{v:.2f}%"
    pdf, path = open_pdf(ctx, "snyk-generated-prs", "Snyk Generated Pull Requests", date_range=(start, end))
    pdf.tiles([{"label": "Created Snyk PRs", "value": big.get("TOTAL_PRS_OPENED") or 0,
                "sub": "Total pull requests created by Snyk during the selected timeframe"},
               {"label": "Merged Snyk PRs", "value": big.get("MERGED_PRS") or 0,
                "sub": "Merged, out of the ones created by Snyk during the selected timeframe"},
               {"label": "Mean time to merge", "value": ttm, "sub": "Time to merge pull requests"}], w=1100)
    status_rows = [[r["PR_TYPE"], r["OPEN"], r["MERGED"], r["CLOSED"], r["TOTAL_PRS"], pct(r["MERGE_RATE"])] for r in by_status]
    pdf.section("Pull requests by status", "Current status of pull requests created in the selected timeframe.")
    pdf.table([("PR Type", 0.3, "text"), ("Open", 0.12, "num"), ("Merged", 0.12, "num"), ("Closed", 0.12, "num"),
               ("Total By Type", 0.17, "num"), ("Merge Rate", 0.17, "right")], status_rows, w=1000)
    issue_rows = [[r["SEVERITY_LEVEL"], r["MERGED_ISSUES"], r["OPEN_ISSUES"], r["TOTAL_ISSUES"]] for r in issues]
    pdf.section("Open vs Fixed issues in Snyk PRs", "The counts only consider issues with an associated Snyk PR.")
    pdf.table([("Severity", 0.34, "text"), ("Fixed Issues", 0.22, "num"), ("Open Issues (In Snyk PRs)", 0.22, "num"),
               ("Open Issues (In Total)", 0.22, "num")], issue_rows, w=1000)
    repo_rows = [[r["PR_TARGET"], r["TOTAL_PRS"], r["OPEN"], r["MERGED"], r["CLOSED"], pct(r["MERGE_RATE"])] for r in repos]
    pdf.section("Adoption by repository")
    pdf.table([("Projects / Repository", 0.4, "text"), ("Total PRs", 0.12, "num"), ("Open PRs", 0.12, "num"),
               ("Merged PRs", 0.12, "num"), ("Closed PRs", 0.12, "num"), ("PRs Merge Rate", 0.12, "right")], repo_rows)
    pdf.save()
    out = [path, write_csv(ctx.path("snyk-generated-prs_by-status", "csv"),
                           ["PR_TYPE", "OPEN", "MERGED", "CLOSED", "TOTAL", "MERGE_RATE"], status_rows),
           write_csv(ctx.path("snyk-generated-prs_by-repository", "csv"),
                     ["REPOSITORY", "TOTAL_PRS", "OPEN", "MERGED", "CLOSED", "MERGE_RATE"], repo_rows)]
    ctx.summary["snyk-generated-prs"] = {"created": big.get("TOTAL_PRS_OPENED") or 0, "merged": big.get("MERGED_PRS") or 0,
                                         "source": "internal reporting API"}
    return out


REPORTS = {"snyk-generated-prs": ("Snyk Generated Pull Requests", snyk_generated_prs)}
