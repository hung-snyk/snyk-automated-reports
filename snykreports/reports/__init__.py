"""Report registry. Each module exposes REPORTS = {slug: (title, build_fn)}; build_fn(ctx) returns paths."""
from . import compliance, dependencies, issues, overview, prchecks, prevention, prs, risk, sla, usage, zeroday

REPORTS = {}
for _m in (overview, issues, risk, sla, zeroday, compliance, prevention, prchecks, prs, usage, dependencies):
    REPORTS.update(_m.REPORTS)

# Reports with no data source at all.
UNSUPPORTED = {}
# Reports the Export API can't build; they're hidden from --list and refused unless --internal-api is on.
INTERNAL_ONLY = {"snyk-generated-prs"}
