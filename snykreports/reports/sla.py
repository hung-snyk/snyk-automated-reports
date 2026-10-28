"""SLA Management. Targets default to the UI's (days to fix, "at risk" days before breach)."""
from collections import Counter, defaultdict

from ..api import fail
from ..common import SEVERITIES, floor_days, is_open_at, write_csv
from ..pdf import M, W
from .base import days, labels, open_pdf, period

DEFAULT_TARGETS = {"Critical": (15, 3), "High": (30, 10), "Medium": (90, 20), "Low": (180, 30)}
STATUS_COLOR = {"Within SLA": "#4aa58f", "At risk": "#e8833a", "Breached": "#e0314b"}


def parse_targets(spec):
    targets = dict(DEFAULT_TARGETS)
    for part in filter(None, (spec or "").split(",")):
        try:
            sev, val = part.split("=")
            target, risk = (val.split(":") + ["0"])[:2]
            targets[sev.strip().title()] = (int(target), int(risk))
        except ValueError:
            fail(f"--sla expects e.g. critical=15:3,high=30:10, got {part!r}")
    return targets


def open_status(r, t, targets):
    target, risk = targets[r.get("ISSUE_SEVERITY")]
    age = floor_days(r["_open_from"], t)
    return ("Breached" if age > target else "At risk" if age >= target - risk else "Within SLA"), age, target - age


def sla_fields(r, t, targets):
    """The SLA columns --filter can use, as of t. A resolved issue keeps the status it was resolved with, which,
    as in the UI, is "At risk" when it was resolved within its target but inside the at-risk days."""
    if r["_res"]:
        target, risk = targets[r["ISSUE_SEVERITY"]]
        age = (r["_res"].date() - r["_intro"].date()).days   # calendar days, which matches the UI's "At Risk" boundary
        st, left = ("Breached" if age > target else "At risk" if age >= target - risk else "Within SLA"), target - age
    else:
        st, age, left = open_status(r, t, targets)
    return {"SLA_STATUS": st, "ISSUE_AGE": age, "TIME_UNTIL_BREACH": left}


def sla_management(ctx):
    targets = parse_targets(ctx.args.sla)
    sevs = ctx.args.severity or ["Critical", "High"]
    start, end = ctx.window(90)
    rows = [r for r in ctx.issues() if r.get("ISSUE_SEVERITY") in sevs]
    rows = ctx.filter_computed(rows, lambda r: sla_fields(r, end, targets))
    open_ = [r for r in rows if r["_status"] == "Open"]
    resolved = [r for r in rows if r["_res"]]
    in_sla = lambda r: floor_days(r["_intro"], r["_res"]) <= targets[r["ISSUE_SEVERITY"]][0]
    ok = sum(1 for r in resolved if in_sla(r))
    pct = lambda n, d: f"{n / d * 100:.1f}%" if d else "0%"

    pdf, path = open_pdf(ctx, "sla-management", "SLA Management", [("Issue Severity", ", ".join(sevs))])
    pdf.section("SLA Targets")
    pdf.tiles([{"label": s, "value": f"{targets[s][0]} days", "sev": s, "sub": f'"At risk" {targets[s][1]} days prior'}
               for s in SEVERITIES])
    pdf.section("Resolved issues SLA performance")
    pdf.tiles([{"label": "Resolved within SLA", "value": pct(ok, len(resolved)), "sub": f"{ok:,} of {len(resolved):,} resolved"},
               {"label": "Resolved out of SLA", "value": pct(len(resolved) - ok, len(resolved)),
                "sub": f"{len(resolved) - ok:,} of {len(resolved):,} resolved"}], w=700)
    pdf.new_page()

    statuses = list(STATUS_COLOR)
    cur = [(r, *open_status(r, end, targets)) for r in open_]
    by_sev = {s: Counter(st for r, st, _, _ in cur if r["ISSUE_SEVERITY"] == s) for s in sevs}
    pts = days(start, end)
    trend = {st: [0] * len(pts) for st in statuses}
    for i, d in enumerate(pts):
        for r in rows:
            if is_open_at(r, d): trend[open_status(r, d, targets)[0]][i] += 1
    pdf.section("Open Issues - SLA severity breakdown", "SLA status of open issues per severity")
    pdf.table([("Severity", 0.4, "text")] + [(s, 0.2, "num") for s in statuses],
              [[s] + [by_sev[s][st] for st in statuses] for s in sevs], w=900)
    pdf.chart_block("SLA trend", f"Cumulative SLA status of open issues over the last {period(start, end).days} days",
                    labels(pts), [(st, STATUS_COLOR[st], trend[st]) for st in statuses], w=W - 2 * M, h=230, fill=False)
    by_target = defaultdict(Counter)
    for r, st, _, _ in cur: by_target[r.get("PROJECT_TARGET_DISPLAY_NAME") or "Unknown"][st] += 1
    targets_rows = sorted(([t] + [c[st] for st in statuses] for t, c in by_target.items()), key=lambda x: (-x[3], -x[2], x[0]))
    pdf.section("SLA Breakdown by Target")
    pdf.table([("Target Name", 0.46, "text")] + [(s, 0.18, "num") for s in statuses], targets_rows)
    flagged = sorted((x for x in cur if x[1] != "Within SLA"),
                     key=lambda x: (x[1] != "Breached", -float(x[0].get("SCORE") or 0), -x[2]))
    limit = ctx.args.max_rows or len(flagged)
    pdf.section("Breached and at risk open issues", f"Showing {min(limit, len(flagged)):,} of {len(flagged):,}; the CSV has all rows.")
    until = lambda left: f"{-left} days overdue" if left < 0 else f"{left} days"
    pdf.table([("Severity", 0.07, "sev"), ("Project", 0.27, "link"), ("Issue Name", 0.27, "link"), ("Score", 0.07, "num"),
               ("Age (Days)", 0.09, "num"), ("SLA Status", 0.11, "text"), ("Time Until Breach", 0.12, "right")],
              [[r["ISSUE_SEVERITY"], (r.get("PROJECT_NAME"), r.get("PROJECT_URL")), (r.get("PROBLEM_TITLE"), r.get("ISSUE_URL")),
                int(float(r.get("SCORE") or 0)), age, st, until(left)] for r, st, age, left in flagged[:limit]])

    res_sev = {s: Counter("Within SLA" if in_sla(r) else "Breached" for r in resolved if r["ISSUE_SEVERITY"] == s) for s in sevs}
    pdf.section("Resolved Issues - SLA severity breakdown", "Retrospective view of resolved issues' SLA status per severity")
    pdf.table([("Severity", 0.4, "text"), ("Resolved within SLA", 0.3, "num"), ("Resolved out of SLA", 0.3, "num")],
              [[s, res_sev[s]["Within SLA"], res_sev[s]["Breached"]] for s in sevs], w=900)
    window_res = [r for r in resolved if start <= r["_res"] <= end]
    pdf.chart_block("SLA trend (resolved)", f"Cumulative SLA status of issues resolved in the last {period(start, end).days} days",
                    labels(pts), [("Resolved within SLA", STATUS_COLOR["Within SLA"],
                                   [sum(1 for r in window_res if r["_res"] <= d and in_sla(r)) for d in pts]),
                                  ("Resolved out of SLA", STATUS_COLOR["Breached"],
                                   [sum(1 for r in window_res if r["_res"] <= d and not in_sla(r)) for d in pts])],
                    w=W - 2 * M, h=230, fill=False)
    pdf.save()
    out = [path,
           write_csv(ctx.path("sla-management_breached-at-risk", "csv"),
                     ["SEVERITY", "PROJECT", "ISSUE", "SCORE", "AGE_DAYS", "SLA_STATUS", "DAYS_UNTIL_BREACH", "ISSUE_URL"],
                     ([r["ISSUE_SEVERITY"], r.get("PROJECT_NAME"), r.get("PROBLEM_TITLE"), r.get("SCORE"), age, st, left,
                       r.get("ISSUE_URL")] for r, st, age, left in flagged)),
           write_csv(ctx.path("sla-management_by-target", "csv"), ["TARGET"] + [s.upper() for s in statuses], targets_rows)]
    ctx.summary["sla-management"] = {"resolved": len(resolved), "resolved_within_sla": ok, "severities": sevs, "targets": targets,
                                     **{f"open_{st.lower().replace(' ', '_')}": sum(c[st] for c in by_sev.values()) for st in statuses}}
    return out


REPORTS = {"sla-management": ("SLA Management", sla_management)}
