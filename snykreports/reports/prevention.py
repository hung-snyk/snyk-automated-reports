"""Prevention: findings fixed at the point of creation (prevention_events dataset)."""
from collections import Counter, defaultdict

from ..common import change, parse_dt, write_csv
from ..pdf import M, SERIES, W
from .base import open_pdf, period

SURFACES = [("Snyk Studio", "MCP"), ("IDE", "IDE"), ("Local CLI", "CLI"), ("PR Check", "PR_CHECK")]


def stats(events):
    fixed = {e["FINDING_BRANCH_KEY"] for e in events if e["EVENT_TYPE"] == "fixed"}
    seen = {e["FINDING_BRANCH_KEY"] for e in events}
    return len(fixed), (len(fixed) / len(seen) * 100 if seen else 0.0)


def months(start, end):
    out, (y, m) = [], (start.year, start.month)
    while (y, m) <= (end.year, end.month):
        out.append((y, m)); y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    return out


def prevention(ctx):
    start, end = ctx.window(90)
    span = period(start, end)
    rows = ctx.data("prevention_events")
    if not ctx.keeps_ignored("IS_SUPPRESSED"): rows = [e for e in rows if (e.get("IS_SUPPRESSED") or "").lower() != "true"]
    for e in rows: e["_t"] = parse_dt(e.get("EVENT_TIMESTAMP"))
    cur = [e for e in rows if e["_t"] and start <= e["_t"] <= end]
    prev = [e for e in rows if e["_t"] and start - span <= e["_t"] < start]
    (fixes, rate), (pfixes, prate) = stats(cur), stats(prev)
    by_stage = Counter(e.get("SDLC_STAGE") for e in cur if e["EVENT_TYPE"] == "fixed")
    pdf, path = open_pdf(ctx, "prevention", "Prevention", date_range=(start, end))
    pdf.tiles([{"label": "Total fixes", "value": fixes, "badge": (change(fixes, pfixes), False), "sub": f"{pfixes:,} previous period"},
               {"label": "Fix rate", "value": f"{rate:.1f}%", "badge": (change(round(rate, 1), round(prate, 1)), False),
                "sub": f"{prate:.1f}% previous period"}], w=700)
    pdf.section("Fixes by Developer surface")
    pdf.tiles([{"label": name, "value": by_stage[key]} for name, key in SURFACES])
    ms = months(start, end)
    monthly = [stats([e for e in cur if (e["_t"].year, e["_t"].month) == m]) for m in ms]
    pdf.chart_block("Fix trends (monthly)", "Findings fixed per month, and the share of findings fixed.",
                    [f"{m:02d}/{y}" for y, m in ms], [("Fixes", SERIES[2], [f for f, _ in monthly]),
                                                     ("Fix rate %", SERIES[3], [round(r, 1) for _, r in monthly])],
                    w=W - 2 * M, h=220, fill=False, label_every=1)
    repos = defaultdict(list)
    for e in cur: repos[e.get("GIT_REPO") or "Unknown"].append(e)
    table = sorted(([repo, *stats(es)] for repo, es in repos.items()), key=lambda t: (-t[1], -t[2], t[0]))
    pdf.section("Fix breakdown by Repositories")
    pdf.table([("Repository", 0.6, "text"), ("Total Findings Fixed", 0.2, "num"), ("Fix Rate", 0.2, "right")],
              [[r, f, f"{p:.1f}%"] for r, f, p in table])
    pdf.save()
    csv_path = write_csv(ctx.path("prevention_by-repository", "csv"), ["REPOSITORY", "FINDINGS_FIXED", "FIX_RATE_PCT"],
                         ([r, f, round(p, 1)] for r, f, p in table))
    ctx.summary["prevention"] = {"fixes": fixes, "fix_rate_pct": round(rate, 1),
                                 **{name: by_stage[key] for name, key in SURFACES}}
    return [path, csv_path]


REPORTS = {"prevention": ("Prevention", prevention)}
