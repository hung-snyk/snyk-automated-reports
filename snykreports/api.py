"""Snyk API client: Export API jobs (REST) and the v1 dependencies listing."""
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
    log(f"dependencies: {len(out)} rows")
    return out
