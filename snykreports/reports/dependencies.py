"""Dependencies and licenses (v1 dependencies and licenses APIs; an org, or every org in a group)."""
from collections import defaultdict

from ..api import LICENSE_RANK
from ..common import dependency_type_filtered, parse_dt, write_csv
from ..pdf import M, W
from .base import open_pdf


def vulns(d):
    return f"C {d.get('issuesCritical', 0)} · H {d.get('issuesHigh', 0)} · M {d.get('issuesMedium', 0)} · L {d.get('issuesLow', 0)}"


def published(d):
    t = parse_dt(d.get("latestVersionPublishedDate") or d.get("firstPublishedDate") or "")
    return f"{t:%b %d, %Y}" if t else ""


def license_names(d):
    return ", ".join(l.get("license") or "" for l in d.get("licenses", []))


def license_severity(d):
    """Most severe license-policy rating among the dependency's licenses ("" when saved before policies were fetched)."""
    sevs = [l["severity"] for l in d.get("licenses", []) if l.get("severity") in LICENSE_RANK]
    return max(sevs, key=LICENSE_RANK.get).capitalize() if sevs else ""


def dependencies_and_licenses(ctx):
    deps = ctx.data("dependencies")
    deps.sort(key=lambda d: (-len(d.get("projects", [])), d.get("name", "")))
    # per license: policy rating, and the (filtered) dependencies and projects that use it
    lic = defaultdict(lambda: {"severity": "", "instructions": "", "deps": set(), "projects": set()})
    for d in deps:
        for l in d.get("licenses", []):
            e = lic[l.get("license") or l.get("title")]
            e["severity"], e["instructions"] = l.get("severity", e["severity"]), l.get("instructions", e["instructions"])
            e["deps"].add(d["id"]); e["projects"].update(p.get("id") for p in d.get("projects", []))
    lic_rows = sorted(lic.items(), key=lambda kv: (-LICENSE_RANK.get(kv[1]["severity"], -1), -len(kv[1]["deps"]), kv[0]))
    shown = [] if dependency_type_filtered(ctx.args) else [("Dependency Type", "All except dockerfile (UI default)")]
    pdf, path = open_pdf(ctx, "dependencies-and-licenses", "Dependencies and licenses", shown)
    with_issues = sum(1 for d in deps if any(d.get(k) for k in ("issuesCritical", "issuesHigh", "issuesMedium", "issuesLow")))
    with_license_issues = sum(1 for d in deps if license_severity(d) not in ("", "None"))
    pdf.tiles([{"label": "Dependencies", "value": len(deps)}, {"label": "With known vulnerabilities", "value": with_issues},
               {"label": "With license issues", "value": with_license_issues},
               {"label": "Distinct licenses", "value": len(lic)}], w=1000)
    pdf.section("Licenses", "Severity is the org's license policy. Sorted by severity, then dependencies.")
    pdf.table([("License", 0.5, "text"), ("Severity", 0.16, "text"), ("Dependencies", 0.17, "num"), ("Projects", 0.17, "num")],
              [[name, e["severity"].capitalize(), len(e["deps"]), len(e["projects"])] for name, e in lic_rows], w=800)
    limit = ctx.args.max_rows or len(deps)
    pdf.section("Dependencies", f"Sorted by projects. Showing {min(limit, len(deps)):,} of {len(deps):,}; the CSV has all rows.")
    pdf.table([("Dependency", 0.19, "text"), ("Version", 0.08, "text"), ("Latest Version", 0.08, "text"),
               ("Last Publish", 0.09, "text"), ("Vulnerabilities", 0.15, "text"), ("License", 0.17, "text"),
               ("License Severity", 0.08, "text"), ("Projects", 0.06, "num"), ("Dependencies With Issues", 0.1, "num")],
              [[d.get("name"), d.get("version"), d.get("latestVersion") or "", published(d), vulns(d), license_names(d),
                license_severity(d), len(d.get("projects", [])), len(d.get("dependenciesWithIssues", []))] for d in deps[:limit]])
    pdf.save()
    csv_path = write_csv(ctx.path("dependencies-and-licenses", "csv"),
                         ["DEPENDENCY", "VERSION", "TYPE", "LATEST_VERSION", "LAST_PUBLISH", "CRITICAL", "HIGH", "MEDIUM", "LOW",
                          "LICENSES", "LICENSE_SEVERITY", "PROJECTS", "DEPENDENCIES_WITH_ISSUES"],
                         ([d.get("name"), d.get("version"), d.get("type"), d.get("latestVersion") or "", published(d),
                           d.get("issuesCritical", 0), d.get("issuesHigh", 0), d.get("issuesMedium", 0), d.get("issuesLow", 0),
                           license_names(d), license_severity(d), len(d.get("projects", [])),
                           len(d.get("dependenciesWithIssues", []))] for d in deps))
    lic_csv = write_csv(ctx.path("licenses", "csv"), ["LICENSE", "SEVERITY", "INSTRUCTIONS", "DEPENDENCIES", "PROJECTS"],
                        ([name, e["severity"], e["instructions"], len(e["deps"]), len(e["projects"])] for name, e in lic_rows))
    ctx.summary["dependencies-and-licenses"] = {"dependencies": len(deps), "with_vulnerabilities": with_issues,
                                                "with_license_issues": with_license_issues}
    return [path, csv_path, lic_csv]


REPORTS = {"dependencies-and-licenses": ("Dependencies and licenses", dependencies_and_licenses)}
