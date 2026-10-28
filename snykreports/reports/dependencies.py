"""Dependencies and licenses (v1 dependencies API; org scope only)."""
from collections import Counter

from ..common import parse_dt, write_csv
from ..pdf import M, W
from .base import open_pdf


def vulns(d):
    return f"C {d.get('issuesCritical', 0)} · H {d.get('issuesHigh', 0)} · M {d.get('issuesMedium', 0)} · L {d.get('issuesLow', 0)}"


def published(d):
    t = parse_dt(d.get("latestVersionPublishedDate") or d.get("firstPublishedDate") or "")
    return f"{t:%b %d, %Y}" if t else ""


def dependencies_and_licenses(ctx):
    if not ctx.args.org_id and not ctx.args.from_raw:
        ctx.skipped["dependencies-and-licenses"] = "needs --org-id (the dependencies API is org-scoped)"
        return []
    deps = ctx.data("dependencies")
    deps.sort(key=lambda d: (-len(d.get("projects", [])), d.get("name", "")))
    licenses = Counter(l.get("license") or l.get("title") for d in deps for l in d.get("licenses", []))
    pdf, path = open_pdf(ctx, "dependencies-and-licenses", "Dependencies and licenses")
    with_issues = sum(1 for d in deps if any(d.get(k) for k in ("issuesCritical", "issuesHigh", "issuesMedium", "issuesLow")))
    pdf.tiles([{"label": "Dependencies", "value": len(deps)}, {"label": "With known vulnerabilities", "value": with_issues},
               {"label": "Distinct licenses", "value": len(licenses)}], w=1000)
    pdf.section("Licenses", "Dependencies per license (top 15).")
    pdf.table([("License", 0.7, "text"), ("Dependencies", 0.3, "num")], [[l, n] for l, n in licenses.most_common(15)], w=800)
    limit = ctx.args.max_rows or len(deps)
    pdf.section("Dependencies", f"Sorted by projects. Showing {min(limit, len(deps)):,} of {len(deps):,}; the CSV has all rows.")
    pdf.table([("Dependency", 0.2, "text"), ("Version", 0.08, "text"), ("Latest Version", 0.09, "text"),
               ("Last Publish", 0.09, "text"), ("Vulnerabilities", 0.16, "text"), ("License", 0.2, "text"),
               ("Projects", 0.07, "num"), ("Dependencies With Issues", 0.11, "num")],
              [[d.get("name"), d.get("version"), d.get("latestVersion") or "", published(d), vulns(d),
                ", ".join(l.get("license") or "" for l in d.get("licenses", [])), len(d.get("projects", [])),
                len(d.get("dependenciesWithIssues", []))] for d in deps[:limit]])
    pdf.save()
    csv_path = write_csv(ctx.path("dependencies-and-licenses", "csv"),
                         ["DEPENDENCY", "VERSION", "TYPE", "LATEST_VERSION", "LAST_PUBLISH", "CRITICAL", "HIGH", "MEDIUM", "LOW",
                          "LICENSES", "PROJECTS", "DEPENDENCIES_WITH_ISSUES"],
                         ([d.get("name"), d.get("version"), d.get("type"), d.get("latestVersion") or "", published(d),
                           d.get("issuesCritical", 0), d.get("issuesHigh", 0), d.get("issuesMedium", 0), d.get("issuesLow", 0),
                           ", ".join(l.get("license") or "" for l in d.get("licenses", [])), len(d.get("projects", [])),
                           len(d.get("dependenciesWithIssues", []))] for d in deps))
    ctx.summary["dependencies-and-licenses"] = {"dependencies": len(deps), "with_vulnerabilities": with_issues}
    return [path, csv_path]


REPORTS = {"dependencies-and-licenses": ("Dependencies and licenses", dependencies_and_licenses)}
