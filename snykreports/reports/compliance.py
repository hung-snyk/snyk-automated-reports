"""Compliance reports: OWASP Top 10 (2025), CWE Top 25 (2023), CWE Top 10 KEV (2023), PCI-DSS v4.0.1.

Default filters match the UI: open issues introduced in the last 30 days (PCI-DSS: critical only)."""
from collections import Counter
from datetime import timedelta

from ..common import SEVERITIES, cwe_ids, is_open_at, write_csv
from ..pdf import M, SERIES, W, stacked
from .base import days, labels, open_pdf

# "List of Mapped CWEs" from each category page of github.com/OWASP/Top10 (2025/docs/en).
OWASP_2025 = [
    ("A01 Broken Access Control", [22, 23, 36, 59, 61, 65, 200, 201, 219, 276, 281, 282, 283, 284, 285, 352, 359, 377, 379, 402, 424, 425, 441, 497, 538, 540, 548, 552, 566, 601, 615, 639, 668, 732, 749, 862, 863, 918, 922, 1275]),
    ("A02 Security Misconfiguration", [5, 11, 13, 15, 16, 260, 315, 489, 526, 547, 611, 614, 776, 942, 1004, 1174]),
    ("A03 Software Supply Chain Failures", [447, 1035, 1104, 1329, 1357, 1395]),
    ("A04 Cryptographic Failures", [261, 296, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 334, 335, 336, 337, 338, 340, 342, 347, 523, 757, 759, 760, 780, 916, 1240, 1241]),
    ("A05 Injection", [20, 74, 76, 77, 78, 79, 80, 83, 86, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 103, 104, 112, 113, 114, 115, 116, 129, 159, 470, 493, 500, 564, 610, 643, 644, 917]),
    ("A06 Insecure Design", [73, 183, 256, 266, 269, 286, 311, 312, 313, 316, 362, 382, 419, 434, 436, 444, 451, 454, 472, 501, 522, 525, 539, 598, 602, 628, 642, 646, 653, 656, 657, 676, 693, 799, 807, 841, 1021, 1022, 1125]),
    ("A07 Authentication Failures", [258, 259, 287, 288, 289, 290, 291, 293, 294, 295, 297, 298, 299, 300, 302, 303, 304, 305, 306, 307, 308, 309, 346, 350, 384, 521, 613, 620, 640, 798, 940, 941, 1390, 1391, 1392, 1393]),
    ("A08 Software or Data Integrity Failures", [345, 353, 426, 427, 494, 502, 506, 509, 565, 784, 829, 830, 915, 926]),
    ("A09 Security Logging and Alerting Failures", [117, 221, 223, 532, 778]),
    ("A10 Mishandling of Exceptional Conditions", [209, 215, 234, 235, 248, 252, 274, 280, 369, 390, 391, 394, 396, 397, 460, 476, 478, 484, 550, 636, 703, 754, 755, 756]),
]
CWE_TOP_25_2023 = [
    (787, "Out-of-bounds Write"), (79, "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)"),
    (89, "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)"), (416, "Use After Free"),
    (78, "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)"),
    (20, "Improper Input Validation"), (125, "Out-of-bounds Read"),
    (22, "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)"), (352, "Cross-Site Request Forgery (CSRF)"),
    (434, "Unrestricted Upload of File with Dangerous Type"), (862, "Missing Authorization"), (476, "NULL Pointer Dereference"),
    (287, "Improper Authentication"), (190, "Integer Overflow or Wraparound"), (502, "Deserialization of Untrusted Data"),
    (77, "Improper Neutralization of Special Elements used in a Command (Command Injection)"),
    (119, "Improper Restriction of Operations within the Bounds of a Memory Buffer"), (798, "Use of Hard-coded Credentials"),
    (918, "Server-Side Request Forgery (SSRF)"), (306, "Missing Authentication for Critical Function"),
    (362, "Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)"),
    (269, "Improper Privilege Management"), (94, "Improper Control of Generation of Code (Code Injection)"),
    (863, "Incorrect Authorization"), (276, "Incorrect Default Permissions"),
]
CWE_TOP_10_KEV_2023 = [
    (416, "Use After Free"), (122, "Heap-based Buffer Overflow"), (787, "Out-of-bounds Write"), (20, "Improper Input Validation"),
    (78, "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)"),
    (502, "Deserialization of Untrusted Data"), (918, "Server-Side Request Forgery (SSRF)"),
    (843, "Access of Resource Using Incompatible Type (Type Confusion)"),
    (22, "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)"),
    (306, "Missing Authentication for Critical Function"),
]
# Snyk's CWE mapping for the PCI-DSS 6.2.4 attack categories (docs.snyk.io, compliance reports).
PCI_CATEGORIES = [
    ("Injection Attacks", [89, 90, 91, 77, 470]),
    ("Attacks on Data and Data Structures", [120, 476, 415, 362]),
    ("Attacks on Cryptography Usage", [327, 330, 347, 319, 321]),
    ("Attacks on Business Logic", [918, 352, 79, 346, 285, 200]),
    ("Attacks on Access Control Mechanisms", [287, 284, 863, 639, 306, 303, 862]),
]
PCI_AGES = [("Under 15 Days Old", 0, 14), ("15-30 Days Old", 15, 30), ("Over 30 Days Old", 31, 10**6)]


def scoped(ctx, severities=None):
    start, end = ctx.window(30)
    rows = [r for r in ctx.issues(ctx.default_statuses("Open")) if start <= r["_intro"] <= end]
    if severities: rows = [r for r in rows if r.get("ISSUE_SEVERITY") in severities]
    for r in rows: r["_cwes"] = cwe_ids(r)
    return rows, start, end


def sev_counts(rows):
    c = Counter(r.get("ISSUE_SEVERITY") for r in rows)
    return [c[s] for s in SEVERITIES] + [len(rows)]


def control_report(ctx, slug, title, controls, with_cwe):
    """controls = [(name, cwe or [cwes])]; counts each issue once per matching control."""
    rows, start, end = scoped(ctx)
    table, matched = [], set()
    for i, (name, cwes) in enumerate(controls, 1):
        cw = {cwes} if isinstance(cwes, int) else set(cwes)
        hit = [r for r in rows if r["_cwes"] & cw]
        matched.update(id(r) for r in hit)
        label = f"{i} {name}" if with_cwe else name
        table.append([label] + ([f"CWE-{cwes}"] if with_cwe else []) + sev_counts(hit))
    total = sev_counts([r for r in rows if id(r) in matched])
    pdf, path = open_pdf(ctx, slug, title, [("Issue Status", "Open")], (start, end))
    pdf.tiles([{"label": s, "value": v, "sev": s} for s, v in zip(SEVERITIES, total)] +
              [{"label": "Total issues", "value": total[-1]}])
    pdf.section("Distribution of controls", "Open issues per control, by severity.")
    pdf.hbars([(t[0], t[-5:-1]) for t in table if t[-1]] or [("No issues", [0, 0, 0, 0])])
    pdf.section("Control details")
    cols = [("Control", 0.44 if with_cwe else 0.52, "text")] + ([("CWE", 0.08, "text")] if with_cwe else []) + \
           [(s, 0.08, "num") for s in SEVERITIES] + [("Total", 0.08, "num")]
    pdf.table(cols, table + [["All Controls"] + ([""] if with_cwe else []) + total])
    pdf.save()
    head = ["CONTROL"] + (["CWE"] if with_cwe else []) + [s.upper() for s in SEVERITIES] + ["TOTAL"]
    csv_path = write_csv(ctx.path(slug, "csv"), head, table + [["All Controls"] + ([""] if with_cwe else []) + total])
    ctx.summary[slug] = dict(zip(["critical", "high", "medium", "low", "total"], total), controls={t[0]: t[-1] for t in table})
    return [path, csv_path]


def pci_age(r, t):
    return (t - r["_intro"]).days


def pci_dss(ctx):
    sevs = ctx.args.severity or ["Critical"]
    rows, start, end = scoped(ctx, sevs)
    cats = PCI_CATEGORIES + [("Attacks via High-Risk Vulnerabilities", None)]

    def in_cat(r, cwes):
        # Snyk does not document what puts an issue in "high-risk"; the UI showed none for any scope we
        # checked (CISA KEV issues included), so the category stays empty rather than guessed
        return False if cwes is None else bool(r["_cwes"] & set(cwes))
    # like the UI, an issue counts once, in the first matching category (in the order above)
    category = {id(r): next((n for n, c in cats if in_cat(r, c)), None) for r in rows}
    elected = [r for r in rows if category[id(r)]]
    table = []
    for name, cwes in cats:
        ages = [pci_age(r, end) for r in rows if category[id(r)] == name]
        table.append([name] + [sum(lo <= a <= hi for a in ages) for _, lo, hi in PCI_AGES])
    total = [sum(t[i] for t in table) for i in range(1, 4)]
    violations = sum(1 for r in elected if pci_age(r, end) > 30)
    week_ago = end - timedelta(days=7)
    prev_viol = sum(1 for r in elected if is_open_at(r, week_ago) and pci_age(r, week_ago) > 30)
    pts = days(start, end)
    trend = [[sum(1 for r in elected if is_open_at(r, d) and lo <= pci_age(r, d) <= hi) for d in pts] for _, lo, hi in PCI_AGES]
    pdf, path = open_pdf(ctx, "pci-dss-v4.0.1", "PCI-DSS v4.0.1",
                         [("Issue Status", "Open"), ("Issue Severity", ", ".join(sevs))], (start, end))
    delta = violations - prev_viol
    pdf.tiles([{"label": "Vulnerabilities over 30 days old", "value": violations,
                "sub": "No change in the last 7 days" if not delta else f"{delta:+d} in the last 7 days"}], w=420)
    pdf.chart_block("PCI-DSS Readiness Trend", "Overall compliance to requirements 6.2.4 and 6.3.3 over time",
                    labels(pts), list(zip([a[0] for a in PCI_AGES][::-1], [SERIES[2], SERIES[1], SERIES[0]],
                                          stacked(trend[::-1]))), w=W - 2 * M, h=240)
    pdf.section("Vulnerability breakdown by Attack Category", "Vulnerabilities aging based on requirements 6.2.4 and 6.3.3")
    pdf.table([("Attack Category", 0.46, "text")] + [(a[0], 0.18, "num") for a in PCI_AGES], table + [["Total"] + total])
    pdf.save()
    csv_path = write_csv(ctx.path("pci-dss-v4.0.1", "csv"), ["ATTACK_CATEGORY"] + [a[0].upper() for a in PCI_AGES],
                         table + [["Total"] + total])
    ctx.summary["pci-dss-v4.0.1"] = {"violations": violations, "under_15": total[0], "15_30": total[1], "over_30": total[2],
                                     "severities": sevs}
    return [path, csv_path]


REPORTS = {
    "owasp-top-10-2025": ("OWASP Top 10 (2025)", lambda ctx: control_report(ctx, "owasp-top-10-2025", "OWASP Top 10 (2025)", OWASP_2025, False)),
    "cwe-top-25-2023": ("CWE Top 25 (2023)", lambda ctx: control_report(ctx, "cwe-top-25-2023", "CWE Top 25 (2023)",
                                                                        [(n, c) for c, n in CWE_TOP_25_2023], True)),
    "cwe-top-10-kev-2023": ("CWE Top 10 KEV (2023)", lambda ctx: control_report(ctx, "cwe-top-10-kev-2023", "CWE Top 10 KEV (2023)",
                                                                                [(n, c) for c, n in CWE_TOP_10_KEV_2023], True)),
    "pci-dss-v4.0.1": ("PCI-DSS v4.0.1", pci_dss),
}
