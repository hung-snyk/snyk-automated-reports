"""Helpers shared by report modules."""
from datetime import timedelta

from ..pdf import Pdf


def open_pdf(ctx, slug, title, filters=(), date_range=None):
    """The report's PDF. Without "pdf" in --format it is still laid out but never saved, and path is None."""
    from ..common import FORMATS
    path = ctx.path(slug, "pdf")
    pdf = Pdf(path, title, enabled="pdf" in FORMATS)
    if not pdf.enabled: path = None
    a = ctx.args
    # an ISSUE_STATUS or IS_SUPPRESSED filter decides about ignored rows itself, and is listed below
    picks_status = any(f.column in ("ISSUE_STATUS", "IS_SUPPRESSED") for f in a.filter)
    filt = list(filters) + ([] if picks_status else [("Is Currently Ignored", str(a.include_ignored))])
    if a.product: filt.append(("Product", ", ".join(a.product)))
    filt += [f.label() for f in a.filter]
    end = date_range[1] if date_range else ctx.window(0)[1]
    pdf.header(a.org_name, title, a.generated_by, end, filt, date_range)
    return pdf, path


def period(start, end):
    """Length of a window of whole days; the previous period is the same length, ending at start."""
    return timedelta(days=(end.date() - start.date()).days + 1)


def days(start, end):
    """One point per calendar day of the window, at the end of that day; the last point is end."""
    return [min(start + timedelta(days=i + 1, seconds=-1), end) for i in range(period(start, end).days)]


def week_starts(start, end):
    """7-day buckets from start that cover the window."""
    return [start + timedelta(days=7 * i) for i in range((period(start, end).days + 6) // 7)]


def labels(points):
    return [f"{d:%d %b}" for d in points]
