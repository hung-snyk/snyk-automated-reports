"""Shared context, data loading and helpers for the report modules."""
import copy, csv, json, math, os, re
from datetime import datetime, timedelta, timezone

from . import api

SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
DATE_FILTER = {"issues": "introduced", "prevention_events": "event"}   # every other dataset uses "updated"
# --filter columns that are also sent to the Export API. Only filters whose API values are the column's values
# (or matched case-insensitively by the API) are listed, so the API never returns fewer rows than the local filter keeps.
API_FILTERS = {
    # ISSUE_STATUS is filtered locally only: issues are also the source for project joins (VIA_PROJECT), and
    # sending it to the API would drop projects whose issues are all resolved from those joins
    "issues": {"PRODUCT_NAME": "product_name", "PROJECT_TYPE": "project_type",
               "PROJECT_ORIGIN": "project_origin", "PROJECT_TARGET_REF": "project_target_ref",
               "PROJECT_TARGET_DISPLAY_NAME": "project_target_display_name",
               "PROJECT_ENVIRONMENTS": "environment", "PROJECT_LIFECYCLES": "lifecycle"},
    "prevention_events": {"PRODUCT_NAME": "product_name", "EVENT_TYPE": "event_type", "EFFECTIVE_SEVERITY": "effective_severity",
                          "SDLC_STAGE": "sdlc_stage", "GIT_REPO": "git_repo", "GIT_BRANCH": "git_branch",
                          "TEST_USER_EMAIL": "test_user_email"},
}
ORGS_FILTER = {"issues", "usage", "prevention_events"}   # datasets whose group exports take an "orgs" filter
# Where project and asset attributes missing from a dataset come from, joined on PROJECT_PUBLIC_ID. Only these
# column prefixes are joined, so an issue filter such as ISSUE_SEVERITY doesn't narrow PR checks to matching projects.
VIA_PROJECT = {"pr_checks": ["pr_checks_project_adoption", "issues"], "pr_checks_project_adoption": ["issues"]}
PROJECT_ATTRS = ("PROJECT_", "ASSET_", "PARENT_ASSET_", "REPOSITORY_FRESHNESS", "ORG_")
# A filter column a dataset names differently: (its column, how to convert the values).
ALIASES = {"prevention_events": {"ISSUE_SEVERITY": ("EFFECTIVE_SEVERITY", str.upper)},
           "usage": {"PRODUCT_NAME": ("PRODUCT_DISPLAY_NAME", None)}}
COMPUTED = {"ISSUE_AGE", "SLA_STATUS", "TIME_UNTIL_BREACH"}   # computed by SLA Management, which applies them itself
PRESETS = {"last7days": "Last 7 days", "lastmonth": "Last month", "last30days": "Last 30 days", "last90days": "Last 90 days",
           "last365days": "Last 365 days", "monthtodate": "Month to date", "yeartodate": "Year to date"}


class Filter:
    """One --filter, like a UI report filter. COLUMN=a,b keeps rows matching any value and != drops them;
    ~ and !~ do the same for text the value contains (any case). >=, <= and =LO..HI compare numbers or YYYY-MM-DD
    dates, and a date column also takes the UI's presets (=last30days, =yeartodate, ...).
    List cells (CWE, PROJECT_TAGS, ...) match when any item matches; an empty value matches an empty cell."""

    def __init__(self, spec):
        m = re.fullmatch(r"\s*([A-Za-z][A-Za-z0-9_]*)\s*(!~|~|!=|>=|<=|=)(.*)", spec)
        if not m: raise ValueError(f"--filter {spec!r}: expected COLUMN=VALUE[,VALUE], COLUMN!=..., COLUMN~TEXT, "
                                   "COLUMN>=N, COLUMN<=N or COLUMN=LO..HI")
        self.spec, self.column, self.op, val = spec.strip(), m[1].upper(), m[2], m[3].strip()
        self.values, self.lo, self.hi, self.preset = [v.strip() for v in val.split(",")], None, None, None
        if self.op in (">=", "<="):
            self.lo, self.hi = (self.bound(val, False), None) if self.op == ">=" else (None, self.bound(val, True))
        elif self.op == "=" and ".." in val:
            lo, hi = val.split("..", 1)
            if not lo.strip() and not hi.strip():
                raise ValueError(f"--filter {spec!r}: give at least one end of the range, e.g. SCORE=700.. or SCORE=..900")
            self.lo, self.hi = self.bound(lo, False) if lo.strip() else None, self.bound(hi, True) if hi.strip() else None
            if type(self.lo) is not type(self.hi) and None not in (self.lo, self.hi):
                raise ValueError(f"--filter {spec!r}: both ends must be numbers or both dates")
        elif self.op == "=" and val.lower().replace(" ", "") in PRESETS:
            self.preset = val.lower().replace(" ", "")   # dates are set by resolve(), once the report's end day is known
        else:
            return
        self.op = "range"

    def bound(self, s, upper):
        s = s.strip()
        try: return float(s)
        except ValueError: pass
        try: day = datetime.strptime(s, "%Y-%m-%d")
        except ValueError: raise ValueError(f"--filter {self.spec!r}: {s!r} is not a number or a YYYY-MM-DD date") from None
        return datetime.combine(day, datetime.max.time() if upper else datetime.min.time(), timezone.utc).replace(microsecond=0)

    def resolve(self, end_day):
        """Turn a date preset into dates ending on the report's end day, the way the UI's date pickers do."""
        if not self.preset: return
        if self.preset == "lastmonth":
            first = end_day.replace(day=1)
            start, end = (first - timedelta(days=1)).replace(day=1), first - timedelta(days=1)
        else:
            start = {"monthtodate": end_day.replace(day=1), "yeartodate": end_day.replace(month=1, day=1)}.get(
                self.preset) or end_day - timedelta(days=int(re.sub(r"\D", "", self.preset)))
            end = end_day
        self.lo, self.hi = self.bound(f"{start}", False), self.bound(f"{end}", True)

    @staticmethod
    def cells(v):
        if isinstance(v, (int, float)): return [str(v)]
        v = (v or "").strip()
        if not v.startswith("["): return [v] if v else []
        return [f"{i.get('key')}:{i.get('value')}" if isinstance(i, dict) else str(i) for i in jlist(v)]

    def match(self, v):
        if self.op == "range":
            if self.lo is None and self.hi is None: api.fail(f"filter {self.spec}: date preset was never resolved")
            dates = isinstance(self.lo or self.hi, datetime)
            try: x = parse_dt(v) if dates else float(v)
            except (TypeError, ValueError): return False
            return x is not None and (self.lo is None or x >= self.lo) and (self.hi is None or x <= self.hi)
        cells = self.cells(v)
        if self.op in ("~", "!~"):
            hit = any(t.lower() in c.lower() for c in cells for t in self.values if t)
            return hit if self.op == "~" else not hit
        hit = any(c in self.values for c in cells) or (not cells and "" in self.values)
        return hit if self.op == "=" else not hit

    def label(self):
        """(name, value) for the PDF header's filter list."""
        acronyms = {"Sla", "Cve", "Cwe", "Cvss", "Epss", "Nvd", "Id", "Sdlc", "Jira", "Url"}
        name = " ".join(w.upper() if w in acronyms else w for w in self.column.replace("_", " ").title().split())
        if self.op == "range":
            show = lambda b: f"{b:%Y-%m-%d}" if isinstance(b, datetime) else f"{b:g}"
            span = f"{show(self.lo)} to {show(self.hi)}" if self.lo is not None and self.hi is not None else \
                f">= {show(self.lo)}" if self.lo is not None else f"<= {show(self.hi)}"
            return name, f"{PRESETS[self.preset]} ({span})" if self.preset else span
        shown = ", ".join(v or "(empty)" for v in self.values)
        return name, {"=": shown, "!=": f"not {shown}", "~": f"contains {shown}", "!~": f"does not contain {shown}"}[self.op]


def dependency_type_filtered(args):
    """True when --filter picks dependency types itself, replacing the UI's default (every type but dockerfile)."""
    return any(f.column == "DEPENDENCY_TYPE" for f in args.filter)


def dependency_view(d):
    """The Dependencies and licenses report's filterable fields, named like export columns."""
    return {"DEPENDENCY_NAME": d.get("name"), "DEPENDENCY_VERSION": d.get("version"), "DEPENDENCY_TYPE": d.get("type"),
            "ISSUE_SEVERITY": json.dumps([s for s in SEVERITIES if d.get(f"issues{s}")]),
            "LICENSE": json.dumps([l.get("license") or l.get("title") for l in d.get("licenses", [])]),
            "PROJECT_NAME": json.dumps([p.get("name") for p in d.get("projects", [])]),
            "PROJECT_PUBLIC_ID": json.dumps([p.get("id") for p in d.get("projects", [])]),
            "IS_DEPRECATED": str(bool(d.get("isDeprecated"))).lower()}


def parse_dt(s):
    if not s: return None
    s = s.strip().replace("Z", "").replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try: return datetime.strptime(s[:26], fmt).replace(tzinfo=timezone.utc)
        except ValueError: pass
    return None


def jlist(s):
    try: v = json.loads(s) if s else []
    except ValueError: return [s] if s else []
    return v if isinstance(v, list) else [v]


def cwe_ids(r):
    out = set()
    for c in jlist(r.get("CWE")):
        try: out.add(int(str(c).split("-")[1]))
        except (IndexError, ValueError): pass
    return out


def change(cur, prev):
    """Percent change the way the Snyk UI shows it (a zero baseline counts as 1)."""
    if cur == prev: return 0
    return round((cur - prev) / prev * 100) if prev else round(cur * 100)


def days_between(a, b):
    return (b - a).total_seconds() / 86400


def prepare_issues(rows):
    for r in rows:
        r["_intro"] = parse_dt(r.get("FIRST_INTRODUCED"))
        r["_status"] = r.get("ISSUE_STATUS") or r.get("ISSUE_STATUS_INDICATOR") or ""
        r["_res"] = parse_dt(r.get("LAST_RESOLVED")) if r["_status"] == "Resolved" else None
        # An issue that was fixed and came back is open (and new, and ageing) from its latest introduction, as in the UI.
        last = parse_dt(r.get("LAST_INTRODUCED"))
        r["_open_from"] = max(r["_intro"], last) if r["_intro"] and last else r["_intro"]
    return [r for r in rows if r["_intro"]]


def is_open_at(r, t):
    return r["_open_from"] <= t and not (r["_res"] and r["_res"] <= t)


class Ctx:
    """Run settings plus lazily loaded datasets, shared by every report."""

    def __init__(self, args, out, end_day):
        self.args, self.out, self.end_day = args, out, end_day
        self.stamp = end_day.strftime("%m_%d_%Y")
        self._cache, self._layers = {}, None
        self._raw = {}
        for f in args.filter: f.resolve(end_day)
        self.summary, self.skipped = {}, {}   # headline numbers per report, and reports skipped with a reason

    def layers(self):
        """Client for the experimental Analytics API (see panels.py); only used with --experimental."""
        if self._layers is None:
            from .panels import Layers
            a = self.args
            token = os.environ.get("SNYK_TOKEN") or api.fail("set SNYK_TOKEN (environment or .env)")
            scope, sid = ("orgs", a.org_id) if a.scope == "org" else ("groups", a.group_id)
            if not sid: api.fail(f"--experimental needs --{a.scope}-id")
            api.scope_root(api.REGIONS[a.region], scope, sid)   # validates the id
            self._layers = Layers(api.REGIONS[a.region], scope, sid, token)
        return self._layers

    def experimental(self, panel=None):
        """The panel-data client when --experimental is on. Pass `panel` for data that --filter/--product should
        narrow: the UI's panels can't apply those, so on a filtered run the panel falls back to the export."""
        if not self.args.experimental: return None
        if panel and (self.args.filter or self.args.product):
            api.log(f"{panel}: built from the export, because --filter/--product can't be applied to the UI's panel")
            return None
        return self.layers()

    def window(self, default_days):
        """Window for a "last N days" preset, as the UI computes it: from the start of (end day - N) through the
        end of the end day. So "last 30 days" on Oct 28 is Sep 28 - Oct 28, both included (31 calendar days);
        the UI's Issues Summary, Overview and compliance pages all send these dates. Don't change this to N - 1."""
        days = self.args.days or default_days
        start = datetime.combine(self.end_day - timedelta(days=days), datetime.min.time(), timezone.utc)
        end = datetime.combine(self.end_day, datetime.max.time(), timezone.utc).replace(microsecond=0)
        return start, end

    # ---- data
    def raw_path(self, name, ext="csv"):
        return os.path.join(self.args.from_raw or os.path.join(self.out, "raw"), f"{name}.{ext}")

    def data(self, name):
        if name in self._cache: return self._cache[name]
        a = self.args
        if name == "issues" and a.from_csv:
            rows = read_csv(os.path.realpath(a.from_csv))
        elif a.from_raw:
            path = self.raw_path(name, "json" if name == "dependencies" else "csv")
            if not os.path.isfile(path): api.fail(f"{path} not found (run once with --save-raw)")
            with open(path, encoding="utf-8-sig") as f:
                rows = json.load(f) if name == "dependencies" else list(csv.DictReader(f))
        else:
            rows = self.fetch(name)
        self._raw[name] = rows   # before --filter, for joins that need other filters' rows
        rows = self.apply_filters(name, rows, dependency_view if name == "dependencies" else None)
        if name == "dependencies" and not dependency_type_filtered(a):
            rows = [d for d in rows if d.get("type") != "dockerfile"]   # the UI's default "Project type" leaves Dockerfile out
        if name == "issues":
            rows = prepare_issues(rows)
            if a.product: rows = [r for r in rows if r.get("PRODUCT_NAME") in a.product]
        self._cache[name] = rows
        return rows

    def fetch(self, name):
        a = self.args
        token = os.environ.get("SNYK_TOKEN") or api.fail("set SNYK_TOKEN (environment or .env)")
        base = api.REGIONS[a.region]
        scope, sid = ("orgs", a.org_id) if a.scope == "org" else ("groups", a.group_id)
        if name == "dependencies":
            orgs = [a.org_id] if a.scope == "org" else api.list_group_orgs(base, a.group_id, token)
            rows = api.merge_dependencies([api.with_license_policy(api.list_dependencies(base, o, token),
                                                                   api.list_licenses(base, o, token)) for o in orgs])
        else:
            to = datetime.combine(self.end_day, datetime.max.time(), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            frm = "2000-01-01T00:00:00Z" if name == "issues" else \
                (self.end_day - timedelta(days=a.lookback_days)).strftime("%Y-%m-%dT00:00:00Z")
            filters = {DATE_FILTER.get(name, "updated"): {"from": frm, "to": to}}
            if name == "issues" and a.product: filters["product_name"] = a.product
            if not a.save_raw:   # saved data stays unfiltered, so --from-raw can apply any filters later
                for f in (self.alias(name, f) for f in a.filter):
                    key = API_FILTERS.get(name, {}).get(f.column) or \
                        ("orgs" if f.column == "ORG_PUBLIC_ID" and a.scope == "group" and name in ORGS_FILTER else None)
                    # the API has no "not" or ranges, and a repeated column is narrowed locally
                    if key and key not in filters and f.op == "=" and "" not in f.values: filters[key] = f.values
            rows = api.run_export(base, scope, sid, token, filters, dataset=name)
        if a.save_raw:
            os.makedirs(os.path.join(self.out, "raw"), exist_ok=True)
            path = os.path.join(self.out, "raw", f"{name}.{'json' if name == 'dependencies' else 'csv'}")
            if name == "dependencies":
                # deepcode ignore PT: the output folder is the operator's own --out choice; filename is generated
                with open(path, "w", encoding="utf-8") as f: json.dump(rows, f)
            elif rows:
                write_csv(path, list(rows[0]), ([r.get(k) for k in rows[0]] for r in rows), raw=True)
        return rows

    def alias(self, name, f):
        col, conv = ALIASES.get(name, {}).get(f.column, (None, None))
        if not col: return f
        g = copy.copy(f)
        g.column, g.values = col, [conv(v) for v in f.values] if conv else f.values
        return g

    def unfiltered(self, name):
        self.data(name)
        return self._raw[name]

    def apply_filters(self, name, rows, view=None):
        if not self.args.filter or not rows: return rows
        view = view or (lambda r: r)
        cols, missing = set(view(rows[0])), []
        for f in self.args.filter:
            f = self.alias(name, f) if f.column not in cols else f
            if f.column in COMPUTED: continue   # only SLA Management has these, and applies them itself (filter_computed)
            if f.column not in cols:
                missing.append(f); continue
            if f.op == "=":
                seen = {c for r in rows for c in Filter.cells(view(r).get(f.column))} | ({""} if "" in f.values else set())
                for v in (v for v in f.values if v not in seen):
                    api.log(f"filter {f.spec}: no {name} rows have {f.column} {v!r}" +
                            (f" (values seen: {', '.join(sorted(seen)[:8])})" if seen else ""))
            rows = [r for r in rows if f.match(view(r).get(f.column))]
        for src in VIA_PROJECT.get(name, []) if "PROJECT_PUBLIC_ID" in cols else []:
            if not missing: break
            src_rows = self.unfiltered(src)
            use = [f for f in missing if src_rows and f.column in src_rows[0] and f.column.startswith(PROJECT_ATTRS)]
            if not use: continue
            # projects with a row in src that matches these filters; project and asset attributes repeat on every row
            keep = {r.get("PROJECT_PUBLIC_ID") for r in src_rows if all(f.match(r.get(f.column)) for f in use)}
            rows = [r for r in rows if r.get("PROJECT_PUBLIC_ID") in keep]
            missing = [f for f in missing if f not in use]
        for f in missing: api.log(f"filter {f.spec}: {name} has no {f.column} column; not applied to it")
        return rows

    def filter_computed(self, rows, fields):
        """Apply the filters on columns a report computes itself (COMPUTED); fields(row) returns those columns."""
        fs = [copy.copy(f) for f in self.args.filter if f.column in COMPUTED]
        for f in fs: f.values = [v.lower() for v in f.values]   # any case: the UI writes "At Risk", the report "At risk"
        low = lambda v: v.lower() if isinstance(v, str) else v
        return [r for r in rows if all(f.match(low(v.get(f.column))) for v in [fields(r)] for f in fs)] if fs else rows

    def issues(self, statuses=None):
        rows = self.data("issues")
        if not self.args.include_ignored: rows = [r for r in rows if r["_status"] != "Ignored"]
        return [r for r in rows if r["_status"] in statuses] if statuses else rows

    # ---- output
    def path(self, slug, ext):
        return os.path.join(self.out, f"snyk_{slug}_{self.stamp}.{ext}")


def read_csv(path):
    if not os.path.isfile(path): api.fail(f"file not found: {path}")
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


FORMATS = {"pdf", "csv", "json"}   # set from --format by the CLI
_tables = None                     # tables of the report being built, collected for its JSON file


def begin_report():
    global _tables
    _tables = []


def end_report():
    """Tables written since begin_report(), as [(csv file name, header, rows)]."""
    global _tables
    tables, _tables = _tables or [], None
    return tables


def write_csv(path, header, body, raw=False):
    """Write a report table as CSV (if --format includes csv) and keep it for the report's JSON file.
    raw=True is for datasets saved by --save-raw, which are always written. Returns the path, or None."""
    rows = [list(r) for r in body]
    if not raw and _tables is not None:
        _tables.append((os.path.basename(path), list(header), rows))
    if not raw and "csv" not in FORMATS:
        return None
    # deepcode ignore PT: the output folder is the operator's own --out choice; filename is generated
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(header); w.writerows(rows)
    return path


def ceil_days(a, b):
    return math.ceil(days_between(a, b))


def floor_days(a, b):
    return math.floor(days_between(a, b))
