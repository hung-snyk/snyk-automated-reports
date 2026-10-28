"""Snyk API client: Export API jobs (REST) and the v1 dependencies and licenses listings."""
import csv, io, json, sys, time, uuid, urllib.error, urllib.parse, urllib.request

API_VERSION = "2024-10-15"
REGIONS = {"us": "https://api.snyk.io", "eu": "https://api.eu.snyk.io",
           "au": "https://api.au.snyk.io", "us2": "https://api.us.snyk.io"}


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def fail(msg):
    log(f"error: {msg}")
    sys.exit(1)


def call(method, url, token, body=None, content_type="application/vnd.api+json"):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"token {token}", "Content-Type": content_type,
                                          "Accept": content_type})
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and attempt < 4:
                wait = int(e.headers.get("Retry-After") or 2 ** attempt * 5)
                log(f"HTTP {e.code}, retrying in {wait}s"); time.sleep(wait); continue
            fail(f"HTTP {e.code} from {url}: {e.read().decode()[:500]}")
        except urllib.error.URLError as e:
            if attempt < 4: time.sleep(2 ** attempt * 5); continue
            fail(f"cannot reach {url}: {e.reason}")


def scope_root(base, scope, scope_id):
    try: scope_id = str(uuid.UUID(scope_id))   # keeps the id from altering the API path
    except ValueError: fail(f"--{scope[:-1]}-id must be a UUID, got {scope_id!r}")
    return f"{base}/rest/{scope}/{scope_id}"


def run_export(base, scope, scope_id, token, filters, dataset="issues", columns=None, poll=10, timeout=3600):
    """Start an export job, wait for it, and return the CSV rows as dicts."""
    root, q = scope_root(base, scope, scope_id), f"?version={API_VERSION}"
    attrs = {"formats": ["csv"], "dataset": dataset, "filters": filters}
    if columns: attrs["columns"] = columns   # omitted = every column in the dataset
    export_id = call("POST", f"{root}/export{q}", token, {"data": {"type": "resource", "attributes": attrs}})["data"]["id"]
    log(f"{dataset}: export {export_id} started")
    deadline = time.time() + timeout
    while True:
        st = call("GET", f"{root}/jobs/export/{export_id}{q}", token)["data"]["attributes"]["status"]
        if st == "FINISHED": break
        if st == "ERRORED": fail(f"{dataset} export failed (ERRORED)")
        if time.time() > deadline: fail(f"timed out waiting for the {dataset} export")
        time.sleep(poll)
    attrs = call("GET", f"{root}/export/{export_id}{q}", token)["data"]["attributes"]
    rows = []
    for res in attrs.get("results", []):
        url = res.get("url") or res.get("signed_url")
        if not url: fail(f"unexpected result entry (no url): {res}")
        if urllib.parse.urlparse(url).scheme != "https": fail(f"refusing non-https download link: {url}")
        # deepcode ignore Ssrf: pre-signed https link returned by the Snyk API, not user input
        with urllib.request.urlopen(url, timeout=300) as r:   # pre-signed; no auth header
            rows += list(csv.DictReader(io.StringIO(r.read().decode("utf-8-sig"))))
    log(f"{dataset}: {len(rows)} rows (API row_count={attrs.get('row_count')})")
    return rows


def list_dependencies(base, org_id, token, per_page=1000):
    """All dependencies of an org from the v1 API (used by the Dependencies and licenses report)."""
    try: org_id = str(uuid.UUID(org_id))
    except ValueError: fail(f"--org-id must be a UUID, got {org_id!r}")
    out, page = [], 1
    while True:
        j = call("POST", f"{base}/v1/org/{org_id}/dependencies?sortBy=projects&order=desc&page={page}&perPage={per_page}",
                 token, {}, content_type="application/json")
        out += j.get("results", [])
        if not j.get("results") or len(out) >= j.get("total", 0): break
        page += 1
    log(f"dependencies: {len(out)} rows for org {org_id}")
    return out


LICENSE_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}


def license_key(name):
    """Dependencies write compound licenses as "(MIT OR X11)"; the licenses API as "MIT OR X11"."""
    name = (name or "").strip()
    return name[1:-1] if name.startswith("(") and name.endswith(")") else name


def list_licenses(base, org_id, token):
    """The org's licenses from the v1 API, with the severity its license policy gives each one."""
    try: org_id = str(uuid.UUID(org_id))
    except ValueError: fail(f"--org-id must be a UUID, got {org_id!r}")
    out = call("POST", f"{base}/v1/org/{org_id}/licenses?sortBy=license&order=asc", token, {},
               content_type="application/json").get("results", [])
    log(f"licenses: {len(out)} rows for org {org_id}")
    return out


def with_license_policy(deps, licenses):
    """Copy each license's policy severity and instructions onto the dependencies that carry it."""
    policy = {license_key(l["id"]): l for l in licenses}
    for d in deps:
        for l in d.get("licenses", []):
            p = policy.get(license_key(l.get("license")))
            if p: l.update(severity=p.get("severity") or "none", instructions=p.get("instructions") or "")
    return deps


def scope_name(base, scope, scope_id, token):
    """Display name of an org or group (scope is "orgs" or "groups"); "Snyk" if it can't be read."""
    try:
        return call("GET", f"{scope_root(base, scope, scope_id)}?version={API_VERSION}", token)["data"]["attributes"]["name"]
    except (SystemExit, KeyError, TypeError):
        log(f"warning: couldn't read the {scope[:-1]}'s name from Snyk; the report header shows 'Snyk'")
        return "Snyk"


def list_group_orgs(base, group_id, token):
    url = f"{scope_root(base, 'groups', group_id)}/orgs?version={API_VERSION}&limit=100"
    ids = []
    while url:
        j = call("GET", url, token)
        ids += [o["id"] for o in j.get("data", [])]
        nxt = (j.get("links") or {}).get("next")
        url = f"{base}/rest{nxt.removeprefix('/rest')}" if nxt and nxt.startswith("/") else nxt
    log(f"group has {len(ids)} orgs")
    return ids


def merge_dependencies(per_org):
    """Combine per-org dependency lists: one row per package@version, projects concatenated.
    Orgs can have different license policies; a license keeps its most severe rating. Issue counts and
    dependenciesWithIssues depend on each org's projects, so they take the highest count and the union."""
    merged = {}
    for deps in per_org:
        for d in deps:
            m = merged.setdefault(d["id"], dict(d, projects=[], dependenciesWithIssues=[],
                                                licenses=[dict(l) for l in d.get("licenses", [])]))
            m["projects"] = m["projects"] + d.get("projects", [])
            m["dependenciesWithIssues"] = list(dict.fromkeys(m["dependenciesWithIssues"] + d.get("dependenciesWithIssues", [])))
            for k in ("issuesCritical", "issuesHigh", "issuesMedium", "issuesLow"):
                m[k] = max(m.get(k) or 0, d.get(k) or 0)
            theirs = {l.get("license"): l for l in d.get("licenses", [])}
            for l in m["licenses"]:
                t = theirs.get(l.get("license"), {})
                if LICENSE_RANK.get(t.get("severity"), -1) > LICENSE_RANK.get(l.get("severity"), -1):
                    l.update(severity=t["severity"], instructions=t.get("instructions", ""))
    return list(merged.values())
