"""Report registry. Each module exposes REPORTS = {slug: (title, build_fn)}; build_fn(ctx) returns paths."""
from . import compliance, dependencies, issues, prchecks, prevention, risk, sla, usage, zeroday

REPORTS = {}
for _m in (issues, risk, sla, zeroday, compliance, prevention, prchecks, usage, dependencies):
    REPORTS.update(_m.REPORTS)

# The UI's Snyk Generated Pull Requests report has no public data source (no Export API dataset or REST endpoint).
UNSUPPORTED = {"snyk-generated-prs": "no public API exposes Snyk-generated pull request data"}
