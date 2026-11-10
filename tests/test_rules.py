"""Tests for the date-window, open-at, MTTR, SLA and PR-check adoption rules, and CSV cell safety. Run: python -m unittest discover -s tests"""
import unittest
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

from snykreports.common import Ctx, ceil_days, change, is_open_at, prepare_issues, safe_cell, unsafe_cell
from snykreports.reports.base import days, period, week_starts
from snykreports.reports.issues import bucket_of, period_stats
from snykreports.reports.overview import MTTR_BUCKETS
from snykreports.reports.prchecks import repo_adoption
from snykreports.reports.sla import open_status, parse_targets, sla_fields

END = date(2026, 10, 28)


def at(s):
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def ctx(days=None):
    return Ctx(SimpleNamespace(filter=[], days=days), "/nonexistent", END)


def issue(intro, last_intro=None, resolved=None, severity="High"):
    return prepare_issues([{"FIRST_INTRODUCED": intro, "LAST_INTRODUCED": last_intro or intro, "ISSUE_SEVERITY": severity,
                            "ISSUE_STATUS": "Resolved" if resolved else "Open", "LAST_RESOLVED": resolved or ""}])[0]


class Window(unittest.TestCase):
    # The UI's "Last N Days" preset runs from (end day - N) through the end day, both included: on Oct 28,
    # "Last 30 Days" sends start=2026-09-28, end=2026-10-28 (31 calendar days). Matching it is what makes
    # new/previous-period counts equal the UI's, so these tests pin that rule.
    def test_last_n_days_matches_the_ui_preset(self):
        for n in (1, 7, 30, 90):
            start, end = ctx(n).window(30)
            self.assertEqual(end, at("2026-10-28 23:59:59"))
            self.assertEqual(start, datetime.combine(END - timedelta(days=n), datetime.min.time(), timezone.utc))
            self.assertEqual(period(start, end), timedelta(days=n + 1))

    def test_default_applies_without_days(self):
        start, _ = ctx().window(30)
        self.assertEqual(start.date(), date(2026, 9, 28))

    def test_chart_has_one_point_per_window_day(self):
        start, end = ctx().window(30)
        pts = days(start, end)
        self.assertEqual(len(pts), 31)
        self.assertEqual([p.date() for p in pts], [start.date() + timedelta(days=i) for i in range(31)])
        self.assertEqual(pts[0], at("2026-09-28 23:59:59"))
        self.assertEqual(pts[-1], end)

    def test_week_buckets_cover_the_window(self):
        start, end = ctx().window(30)
        weeks = week_starts(start, end)
        self.assertEqual(weeks[0], start)
        self.assertLessEqual(weeks[-1], end)
        self.assertGreater(weeks[-1] + timedelta(days=7), end)

    def test_previous_period_is_the_same_length(self):
        start, end = ctx().window(30)
        prev_start = start - period(start, end)
        self.assertEqual(prev_start.date(), date(2026, 8, 28))
        self.assertEqual((start - prev_start).days, 31)


class OpenAt(unittest.TestCase):
    def test_open_from_introduction_until_resolution(self):
        r = issue("2026-10-01 10:00:00", resolved="2026-10-10 12:00:00")
        self.assertFalse(is_open_at(r, at("2026-10-01 09:59:59")))
        self.assertTrue(is_open_at(r, at("2026-10-01 10:00:00")))
        self.assertTrue(is_open_at(r, at("2026-10-10 11:59:59")))
        self.assertFalse(is_open_at(r, at("2026-10-10 12:00:00")))

    def test_reopened_issue_is_open_from_latest_introduction(self):
        r = issue("2026-01-01 00:00:00", last_intro="2026-10-20 00:00:00")
        self.assertEqual(r["_open_from"], at("2026-10-20 00:00:00"))
        self.assertFalse(is_open_at(r, at("2026-10-19 23:59:59")))

    def test_resolved_date_ignored_unless_status_is_resolved(self):
        r = prepare_issues([{"FIRST_INTRODUCED": "2026-10-01", "ISSUE_STATUS": "Open", "LAST_RESOLVED": "2026-10-05"}])[0]
        self.assertIsNone(r["_res"])
        self.assertTrue(is_open_at(r, at("2026-10-28 00:00:00")))

    def test_period_stats_counts_new_and_resolved_in_window(self):
        rows = [issue("2026-10-05 00:00:00"), issue("2026-09-01 00:00:00", resolved="2026-10-06 00:00:00"),
                issue("2026-09-01 00:00:00")]
        s = period_stats(rows, at("2026-10-01 00:00:00"), at("2026-10-28 23:59:59"))
        self.assertEqual((s["new"], s["resolved"]), (1, 1))


class Mttr(unittest.TestCase):
    def bucket(self, days_to_fix):
        return next(n for n, lo, hi in MTTR_BUCKETS if lo <= days_to_fix < hi)

    def test_overview_buckets(self):
        self.assertEqual(self.bucket(14.9), "Less than 15 days")
        self.assertEqual(self.bucket(15), "15-30 days")
        self.assertEqual(self.bucket(30), "15-30 days")
        self.assertEqual(self.bucket(30.5), "More than 30 days")

    def test_issues_summary_buckets_use_whole_days(self):
        self.assertEqual(ceil_days(at("2026-10-01 00:00:00"), at("2026-10-15 00:00:01")), 15)
        self.assertEqual([bucket_of(a) for a in (0, 14, 15, 30, 31, -1)], [2, 2, 1, 1, 0, 2])


class Sla(unittest.TestCase):
    targets = parse_targets(None)

    def test_open_status_boundaries(self):   # High: 30 days, at risk from 20
        r = issue("2026-10-01 00:00:00")
        self.assertEqual(open_status(r, at("2026-10-20 23:00:00"), self.targets)[0], "Within SLA")
        self.assertEqual(open_status(r, at("2026-10-21 00:00:00"), self.targets)[0], "At risk")
        self.assertEqual(open_status(r, at("2026-10-31 00:00:00"), self.targets)[0], "At risk")
        self.assertEqual(open_status(r, at("2026-11-01 00:00:00"), self.targets)[0], "Breached")

    def test_resolved_issue_keeps_status_at_resolution(self):
        r = issue("2026-09-01 00:00:00", resolved="2026-09-20 00:00:00")
        self.assertEqual(sla_fields(r, at("2027-01-01 00:00:00"), self.targets)["SLA_STATUS"], "Within SLA")
        late = issue("2026-08-01 00:00:00", resolved="2026-09-15 00:00:00")
        self.assertEqual(sla_fields(late, at("2026-09-16 00:00:00"), self.targets)["SLA_STATUS"], "Breached")

    def test_custom_targets(self):
        t = parse_targets("critical=7:2,high=14")
        self.assertEqual((t["Critical"], t["High"], t["Low"]), ((7, 2), (14, 0), (180, 30)))


class Adoption(unittest.TestCase):
    integrations = [{"ORG_SOURCE_PUBLIC_ID": "gh-on", "IS_PULL_REQUEST_TEST_CODE_ENABLED": "true",
                     "IS_PULL_REQUEST_TEST_OPEN_SOURCE_ENABLED": "true"},
                    {"ORG_SOURCE_PUBLIC_ID": "gh-code-off", "IS_PULL_REQUEST_TEST_CODE_ENABLED": "false",
                     "IS_PULL_REQUEST_TEST_OPEN_SOURCE_ENABLED": "true"}]

    def project(self, repo, product, source, own=""):
        return {"REPOSITORY_NAME": repo, "PRODUCT_NAME": product, "ORG_SOURCE_PUBLIC_ID": source, "TEST_PULL_REQUESTS": own,
                "SOURCE_INTEGRATION_TYPE": "github"}

    def test_blank_setting_inherits_the_integration_flag_for_its_product(self):
        repos = repo_adoption([self.project("a", "Snyk Code", "gh-code-off"), self.project("a", "Snyk Open Source", "gh-code-off"),
                               self.project("b", "Snyk Code", "gh-on")], self.integrations)
        self.assertEqual((repos["a"]["Snyk Code"], repos["a"]["Snyk Open Source"], repos["b"]["Snyk Code"]), (False, True, True))

    def test_project_setting_overrides_the_integration(self):
        repos = repo_adoption([self.project("a", "Snyk Code", "gh-on", "false"), self.project("b", "Snyk Code", "gh-code-off", "true")],
                              self.integrations)
        self.assertEqual((repos["a"]["Snyk Code"], repos["b"]["Snyk Code"]), (False, True))

    def test_repository_is_on_when_any_project_is(self):
        repos = repo_adoption([self.project("a", "Snyk Code", "gh-on", "false"), self.project("a", "Snyk Code", "gh-on")],
                              self.integrations)
        self.assertTrue(repos["a"]["Snyk Code"])

    def test_unknown_integration_counts_as_off(self):
        self.assertFalse(repo_adoption([self.project("a", "Snyk Code", "gone")], self.integrations)["a"]["Snyk Code"])

    def test_without_integration_data_blank_counts_as_on(self):
        self.assertTrue(repo_adoption([self.project("a", "Snyk Code", "gh-on")], [])["a"]["Snyk Code"])


class Change(unittest.TestCase):
    def test_zero_baseline_counts_as_one(self):
        self.assertEqual((change(5, 0), change(0, 0), change(15, 10), change(5, 10)), (500, 0, 50, -50))


class CsvCells(unittest.TestCase):
    # A name from a customer's repo can start like a spreadsheet formula; the report CSVs show it as text instead
    def test_formula_text_is_prefixed(self):
        for v in ("=HYPERLINK(\"x\")", "+1+1", "-2+cmd|' /C calc'!A0", "@SUM(A1)", "\tx", "\rx"):
            self.assertEqual(safe_cell(v), "'" + v)

    def test_numbers_and_plain_text_are_unchanged(self):
        for v in ("-12", "-0.5", "+3", "payments-api", "", 7, -7, None):
            self.assertEqual(safe_cell(v), v)

    def test_reading_back_undoes_the_prefix(self):
        for v in ("=x", "@y", "-a", "it's", "'quoted", "plain"):
            self.assertEqual(unsafe_cell(safe_cell(v)), v)


if __name__ == "__main__":
    unittest.main()
