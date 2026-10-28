"""Shared context, data loading and helpers for the report modules."""
import csv, json, math, os
from datetime import datetime, timedelta, timezone

from . import api

SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
DATE_FILTER = {"issues": "introduced", "prevention_events": "event"}   # every other dataset uses "updated"


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
    return [r for r in rows if r["_intro"]]


def is_open_at(r, t):
    return r["_intro"] <= t and not (r["_res"] and r["_res"] <= t)


class Ctx:
    """Run settings plus lazily loaded datasets, shared by every report."""

    def __init__(self, args, out, end_day):
        self.args, self.out, self.end_day = args, out, end_day
        self.stamp = end_day.strftime("%m_%d_%Y")
        self._cache = {}
        self.summary, self.skipped = {}, {}   # headline numbers per report, and reports skipped with a reason

    def window(self, default_days):
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
        if name == "issues":
            rows = prepare_issues(rows)
            if a.product: rows = [r for r in rows if r.get("PRODUCT_NAME") in a.product]
        self._cache[name] = rows
        return rows

    def fetch(self, name):
        a = self.args
        token = os.environ.get("SNYK_TOKEN") or api.fail("set SNYK_TOKEN (environment or .env)")
        base, scope, sid = api.REGIONS[a.region], ("orgs" if a.org_id else "groups"), (a.org_id or a.group_id)
        if name == "dependencies":
            if not a.org_id: api.fail("the dependencies report needs --org-id")
            rows = api.list_dependencies(base, a.org_id, token)
        else:
            to = datetime.combine(self.end_day, datetime.max.time(), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            frm = "2000-01-01T00:00:00Z" if name == "issues" else \
                (self.end_day - timedelta(days=a.lookback_days)).strftime("%Y-%m-%dT00:00:00Z")
            filters = {DATE_FILTER.get(name, "updated"): {"from": frm, "to": to}}
            if name == "issues" and a.product: filters["product_name"] = a.product
            rows = api.run_export(base, scope, sid, token, filters, dataset=name)
        if a.save_raw:
            os.makedirs(os.path.join(self.out, "raw"), exist_ok=True)
            path = os.path.join(self.out, "raw", f"{name}.{'json' if name == 'dependencies' else 'csv'}")
            if name == "dependencies":
                # deepcode ignore PT: the output folder is the operator's own --out choice; filename is generated
                with open(path, "w", encoding="utf-8") as f: json.dump(rows, f)
            elif rows:
                write_csv(path, list(rows[0]), ([r.get(k) for k in rows[0]] for r in rows))
        return rows

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


def write_csv(path, header, body):
    # deepcode ignore PT: the output folder is the operator's own --out choice; filename is generated
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(header); w.writerows(body)
    return path


def ceil_days(a, b):
    return math.ceil(days_between(a, b))


def floor_days(a, b):
    return math.floor(days_between(a, b))
