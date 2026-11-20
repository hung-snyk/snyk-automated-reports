"""Report registry. Each module exposes REPORTS = {slug: (title, build_fn)}; build_fn(ctx) returns paths."""
from . import compliance, dependencies, issues, overview, prchecks, prevention, risk, sla, usage, zeroday

REPORTS = {}
for _m in (overview, issues, risk, sla, zeroday, compliance, prevention, prchecks, usage, dependencies):
    REPORTS.update(_m.REPORTS)

# Snyk Analytics reports with no supported data source: --list shows them as not available, and a run skips them.
UNSUPPORTED = {"snyk-generated-prs": "Snyk has no supported API for Snyk-generated pull request data; "
                                     "use the report in the Snyk web UI"}
