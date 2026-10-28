"""Helpers shared by report modules."""
from datetime import timedelta

from ..pdf import Pdf


def open_pdf(ctx, slug, title, filters=(), date_range=None):
    path = ctx.path(slug, "pdf")
    pdf = Pdf(path, title)
    a = ctx.args
    filt = list(filters) + [("Is Currently Ignored", str(a.include_ignored))]
    if a.product: filt.append(("Product", ", ".join(a.product)))
    end = date_range[1] if date_range else ctx.window(0)[1]
    pdf.header(a.org_name, title, a.generated_by, end, filt, date_range)
    return pdf, path


def days(start, end):
    """Daily points after start up to and including end."""
    out = [start + timedelta(days=i + 1) for i in range((end - start).days)]
    if not out or out[-1] < end: out.append(end)
    return out


def labels(points):
    return [f"{d:%d %b}" for d in points]
