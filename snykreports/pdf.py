"""Native PDF building blocks shaped like the Snyk Analytics UI (1440x828 landscape pages)."""
import io

from reportlab.lib.colors import HexColor, white
from reportlab.lib.utils import simpleSplit
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfgen import canvas as rl_canvas

W, H = 1440, 828
M = 28                       # page margin
INK, MUTED, GRID, LINK, LINE = "#1c1c28", "#6b6b80", "#c9ccd4", "#1d5fe0", "#e3e6ea"
SERIES = ["#e0314b", "#e8833a", "#4aa58f", "#7b61d9", "#3b82c4", "#8f96a3"]
SEV_COLOR = {"Critical": "#7d1a2c", "High": "#d9354f", "Medium": "#e8833a", "Low": "#8f96a3"}
GOOD, BAD, FLAT = ("#e3f5ef", "#9fd9c4", "#1f7a5c"), ("#fde8ec", "#f5b5c0", "#c6283e"), ("#f3f4f6", "#d7d9de", "#555566")


def tint(hex_color, k=0.88):
    c = HexColor(hex_color)
    return HexColor("#%02x%02x%02x" % tuple(int((v + (1 - v) * k) * 255) for v in (c.red, c.green, c.blue)))


def fmt_axis(v):
    return f"{v / 1000:g}K" if v >= 10000 else f"{v:,.0f}" if v >= 1 or v == 0 else f"{v:g}"


def fmt_num(v):
    return f"{v:,}" if isinstance(v, int) else str(v)


def nice_max(v):
    if v <= 0: return 5, 1
    raw = v / 5
    mag = 10 ** (len(str(int(raw))) - 1) if raw >= 1 else 1
    step = max(next(m * mag for m in (1, 2, 2.5, 3, 5, 10) if m * mag >= raw), 1)
    return step * -(-v // step), step


class Pdf:
    """A canvas plus a vertical cursor (self.top, measured from the page top)."""

    def __init__(self, path, title, enabled=True):
        self.enabled = enabled   # when False the pages are drawn into memory and discarded
        self.c = rl_canvas.Canvas(path if enabled else io.BytesIO(), pagesize=(W, H), pageCompression=1)
        self.c.setTitle(title); self.c.setAuthor("snyk_reports.py")
        self.top, self._pending = M, None

    # ---- primitives
    def text(self, x, top, s, size=10, color=INK, bold=False, anchor="l"):
        c, font = self.c, "Helvetica-Bold" if bold else "Helvetica"
        c.setFont(font, size); c.setFillColor(HexColor(color))
        {"l": c.drawString, "r": c.drawRightString, "c": c.drawCentredString}[anchor](x, H - top - size, s)
        return c.stringWidth(s, font, size)

    def new_page(self):
        self.c.showPage(); self.top = M

    def need(self, h):
        if self.top + h > H - M: self.new_page()

    def save(self):
        self._flush(0)
        if self.enabled: self.c.save()

    def badge(self, x, top, pct, up_is_bad=True, size=8.5):
        """Pill with a trend glyph and percentage, coloured by whether the change is good or bad."""
        bg, border, fg = FLAT if pct == 0 else (BAD if (pct > 0) == up_is_bad else GOOD)
        label = f"{pct:+d}%" if pct else "0%"
        c = self.c
        w, h = c.stringWidth(label, "Helvetica-Bold", size) + 26, size + 8
        y = H - top - h
        c.setFillColor(HexColor(bg)); c.setStrokeColor(HexColor(border)); c.setLineWidth(0.8)
        c.roundRect(x, y, w, h, h / 2, stroke=1, fill=1)
        c.setStrokeColor(HexColor(fg)); c.setLineWidth(1.1)
        gx, gy = x + 7, y + h / 2
        if pct > 0:   c.lines([(gx, gy - 2.5, gx + 3.5, gy + 1), (gx + 3.5, gy + 1, gx + 5, gy - 0.5), (gx + 5, gy - 0.5, gx + 9, gy + 3)])
        elif pct < 0: c.lines([(gx, gy + 2.5, gx + 3.5, gy - 1), (gx + 3.5, gy - 1, gx + 5, gy + 0.5), (gx + 5, gy + 0.5, gx + 9, gy - 3)])
        else:         c.lines([(gx, gy, gx + 8, gy), (gx + 6, gy + 2, gx + 8, gy), (gx + 6, gy - 2, gx + 8, gy)])
        c.setFillColor(HexColor(fg)); c.setFont("Helvetica-Bold", size)
        c.drawString(x + 19, y + 4.6, label)
        return w

    def sev_chip(self, x, top, sev, size=13):
        c = self.c
        c.setFillColor(HexColor(SEV_COLOR.get(sev, MUTED)))
        c.roundRect(x, H - top - size, size, size, 2.5, stroke=0, fill=1)
        c.setFillColor(white); c.setFont("Helvetica-Bold", 8)
        c.drawCentredString(x + size / 2, H - top - size + 3.6, (sev or "?")[0])
        return size

    # ---- blocks
    def header(self, org, title, author, end, filters, date_range=None):
        """First page: branding, title, author and the filters, like the UI's PDF export."""
        c = self.c
        self.text(M, 30, "snyk", 22, INK, bold=True)
        c.linkURL("https://snyk.io", (W - M - 40, H - 52, W - M, H - 36))
        self.text(W - M, 38, "snyk.io", 10, LINK, bold=True, anchor="r")
        self.text(M, 84, org, 10, MUTED, bold=True)
        self.text(M, 112, title, 17)
        wx = self.text(M, 148, "Report Generated ", 9.5, MUTED)
        wx += self.text(M + wx, 148, f"{end:%b %d %Y}", 9.5, INK, bold=True)
        wx += self.text(M + wx, 148, " by ", 9.5, MUTED)
        self.text(M + wx, 148, author, 9.5, INK, bold=True)
        self.text(M, 178, "Filters Applied", 13)
        top = 204
        if date_range:
            self.text(M, top, "Date Range", 9.5, INK, bold=True)
            self.text(M + 74, top, f"Start {date_range[0]:%b %d, %Y}", 9.5, MUTED)
            self.text(M + 74, top + 17, f"End {date_range[1]:%b %d, %Y}", 9.5, MUTED)
        for i, (k, v) in enumerate(filters):
            t = top + 8 + 26 * i
            self.text(W / 2, t, k, 9.5, INK, bold=True, anchor="c"); self.text(W - M, t, v, 9.5, MUTED, anchor="r")
        self.new_page()

    def section(self, title, desc=None, x=M, advance=True):
        """Heading. With advance=True it is drawn by the next block, so it moves to a new page with that block."""
        hh = 48 if desc else 28
        if advance:
            self._flush(0)
            self._pending = (title, desc, x, hh)
            return self.top + hh
        self.text(x, self.top, title, 11.5)
        if desc: self.text(x, self.top + 22, desc, 9, MUTED)
        return self.top + hh

    def _flush(self, content_h):
        """Make room for content_h (plus any pending heading) and draw the heading."""
        pending, self._pending = self._pending, None
        hh = pending[3] if pending else 0
        self.need(hh + content_h)
        if pending:
            title, desc, x, _ = pending
            self.text(x, self.top, title, 11.5)
            if desc: self.text(x, self.top + 22, desc, 9, MUTED)
            self.top += hh

    def tiles(self, items, x=M, w=W - 2 * M, cols=None):
        """KPI tiles: dicts with label, value, optional badge=(pct, up_is_bad), sub, sev."""
        self._flush(100)
        n = cols or max(len(items), 1)
        for i, t in enumerate(items):
            tx = x + (i % n) * w / n
            top = self.top + (i // n) * 100
            lx = tx
            if t.get("sev"): lx += self.sev_chip(tx, top - 1, t["sev"]) + 6
            self.text(lx, top, t["label"], 11)
            vw = self.text(tx, top + 24, fmt_num(t["value"]), 26, INK, bold=True)
            if t.get("badge") is not None: self.badge(tx + vw + 6, top + 28, *t["badge"])
            if t.get("sub"): self.text(tx, top + 60, t["sub"], 10, MUTED)
        self.top += 100 * (-(-len(items) // n)) + 6

    def chart(self, x, top, w, h, labels, series, smooth=False, label_every=None, fill=True):
        """Line chart; series = [(name, color, values)], filled from each line to the axis
        (drawn largest first) so stacked series read as bands, like the Snyk UI."""
        c = self.c
        if not labels: return
        vmax, step = nice_max(max([max(v) for _, _, v in series if v] + [0]))
        pl, pb = 34, 18
        x0, x1, y0, y1 = x + pl, x + w, H - top - h + pb, H - top
        n = max(len(labels), 2)
        X = lambda i: x0 + i * (x1 - x0) / (n - 1)
        Y = lambda v: y0 + v * (y1 - y0) / vmax
        c.setLineWidth(0.6); c.setStrokeColor(HexColor(GRID)); c.setDash(2, 2)
        t = 0
        while t <= vmax + 1e-9:
            c.line(x0, Y(t), x1, Y(t))
            c.setFillColor(HexColor(MUTED)); c.setFont("Helvetica", 8)
            c.drawRightString(x0 - 6, Y(t) - 3, fmt_axis(t)); t += step
        c.setDash()
        every = label_every or max(1, round(len(labels) / 7))
        for i in range(0, len(labels), every):
            c.drawCentredString(X(i), y0 - 13, labels[i])

        def path(vals, close):
            p = c.beginPath(); pts = [(X(i), Y(v)) for i, v in enumerate(vals)]
            p.moveTo(*pts[0])
            for i in range(1, len(pts)):
                if smooth:   # Catmull-Rom through the points, as cubic Beziers kept within each segment's range
                    pa, pb_, pc, pd = pts[max(i - 2, 0)], pts[i - 1], pts[i], pts[min(i + 1, len(pts) - 1)]
                    lo, hi = min(pb_[1], pc[1]), max(pb_[1], pc[1])
                    clamp = lambda v: min(max(v, lo), hi)
                    p.curveTo(pb_[0] + (pc[0] - pa[0]) / 6, clamp(pb_[1] + (pc[1] - pa[1]) / 6),
                              pc[0] - (pd[0] - pb_[0]) / 6, clamp(pc[1] - (pd[1] - pb_[1]) / 6), *pc)
                else: p.lineTo(*pts[i])
            if close: p.lineTo(pts[-1][0], y0); p.lineTo(pts[0][0], y0); p.close()
            return p
        order = sorted(series, key=lambda s: -sum(s[2]))
        for _, col, vals in order:
            if vals and fill: c.setFillColor(tint(col)); c.drawPath(path(vals, True), stroke=0, fill=1)
        for _, col, vals in order:
            if not vals: continue
            c.setStrokeColor(HexColor(col)); c.setLineWidth(1.5); c.drawPath(path(vals, False), stroke=1, fill=0)
            c.setFillColor(white); c.setLineWidth(1.1)
            if len(vals) <= 120:
                for i, v in enumerate(vals): c.circle(X(i), Y(v), 2.1, stroke=1, fill=1)
        self.legend(x, H - y0 + 32, [(name, col) for name, col, _ in series])

    def legend(self, x, top, items):
        c, lx = self.c, x
        for name, col in items:
            ly = H - top
            c.setStrokeColor(HexColor(col)); c.setLineWidth(1.4); c.line(lx, ly + 3, lx + 16, ly + 3)
            c.setFillColor(white); c.circle(lx + 8, ly + 3, 3, stroke=1, fill=1)
            c.setFillColor(HexColor(MUTED)); c.setFont("Helvetica", 8.5); c.drawString(lx + 21, ly, name)
            lx += 34 + c.stringWidth(name, "Helvetica", 8.5)

    def chart_block(self, title, desc, labels, series, x=M, w=580, h=290, advance=True, **kw):
        """Section title + chart; with advance=False the cursor stays put so two blocks can share a row."""
        if advance: self._flush(h + 90)
        top = self.section(title, desc, x=x, advance=False)
        self.chart(x, top + 6, w, h, labels, series, **kw)
        if advance: self.top = top + h + 50

    def hbars(self, rows, x=M, w=640, keys=None, colors=None):
        """Horizontal stacked bars: rows = [(label, [values...])], one segment per key (default severities)."""
        keys = keys or list(SEV_COLOR)
        colors = colors or [SEV_COLOR[k] for k in keys]
        vmax = max([sum(v) for _, v in rows] + [1])
        lw, bh = 250, 13
        c = self.c
        self._flush(22 * min(len(rows), 3))
        for label, vals in rows:
            self.need(22)
            top = self.top
            self.text(x, top + 1, label[:52], 9, INK)
            bx = x + lw
            for v, col in zip(vals, colors):
                seg = v / vmax * (w - lw - 50)
                if seg > 0:
                    c.setFillColor(HexColor(col)); c.rect(bx, H - top - bh, seg, bh, stroke=0, fill=1); bx += seg
            self.text(bx + 6, top + 2, fmt_num(sum(vals)), 8.5, MUTED)
            self.top += 21
        lx = x + lw
        for k, col in zip(keys, colors):
            c.setFillColor(HexColor(col)); c.rect(lx, H - self.top - 16, 9, 9, stroke=0, fill=1)
            self.text(lx + 13, self.top + 6, k, 8.5, MUTED); lx += 26 + c.stringWidth(k, "Helvetica", 8.5)
        self.top += 30

    def table(self, columns, rows, x=M, w=W - 2 * M, empty="No results found"):
        """Paginated table. columns = [(label, width_fraction, kind)] with kind one of
        text | link (text, url) | num | badge (value, pct, up_is_bad) | sev | right."""
        c, fs, lh = self.c, 9.5, 12
        widths = [f * w for _, f, _ in columns]
        xs = [x + sum(widths[:i]) for i in range(len(columns))]

        layout = []
        for row in rows:
            cells = [wrap(v[0] if kind == "link" else v, cw - 24, fs) if kind in ("text", "link") else [""]
                     for (_, _, kind), cw, v in zip(columns, widths, row)]
            layout.append((cells, max(30, max(len(l) for l in cells) * lh + 14)))
        pending = self._pending
        total = (pending[3] if pending else 0) + 30 + sum(rh for _, rh in layout)
        if total <= H - 2 * M and self.top + total > H - M:
            self.new_page()   # a table that fits on one page (with its heading) is never split
        # never leave a header (or heading) at the bottom of a page with fewer than 5 rows under it
        self._flush(30 + sum(rh for _, rh in layout[:5]))

        def head(first_rows):
            self.need(30 + first_rows)
            t = self.top
            c.setFillColor(HexColor("#f6f7f9")); c.rect(x, H - t - 30, w, 30, stroke=0, fill=1)
            for (label, _, kind), cx, cw in zip(columns, xs, widths):
                right = kind in ("num", "badge", "right")
                self.text(cx + cw - 12 if right else cx + 12, t + 10, label, 9.5, INK, anchor="r" if right else "l")
            self.top += 30
            return t

        seg_top = head(sum(rh for _, rh in layout[:2]))
        if not rows:
            self.text(x + 12, self.top + 10, empty, 9.5, MUTED); self.top += 32
        for i, (row, (cells, rh)) in enumerate(zip(rows, layout)):
            rest, left = sum(r for _, r in layout[i:]), len(layout) - i
            # the last rows never sit alone on a page: up to two may use part of the bottom margin,
            # otherwise the last three move to the next page together
            fits_with_margin = left <= 2 and self.top + rest <= H - 10
            if not fits_with_margin and (self.top + rh > H - M or (left <= 3 and self.top + rest > H - M and i > 0)):
                c.setStrokeColor(HexColor(LINE)); c.setLineWidth(0.8)
                c.roundRect(x, H - self.top, w, self.top - seg_top, 6, stroke=1, fill=0)
                self.new_page(); seg_top = head(rh)
            t = self.top
            c.setStrokeColor(HexColor("#e9ebef")); c.setLineWidth(0.7); c.line(x, H - t, x + w, H - t)
            for (label, _, kind), cx, cw, v, lines in zip(columns, xs, widths, row, cells):
                mid = t + rh / 2
                if kind in ("text", "link"):
                    ty = mid - lh * len(lines) / 2 + 1
                    for j, ln in enumerate(lines):
                        self.text(cx + 12, ty + lh * j, ln, fs, LINK if kind == "link" else INK)
                    if kind == "link" and v[1]:
                        c.linkURL(v[1], (cx + 12, H - t - rh + 4, cx + cw - 12, H - t - 4), relative=0)
                elif kind == "num":
                    self.text(cx + cw - 12, mid - 5.5, fmt_num(v), fs, INK, anchor="r")
                elif kind == "right":
                    self.text(cx + cw - 12, mid - 5.5, str(v), fs, INK, anchor="r")
                elif kind == "badge":
                    val, pct, up_bad = v
                    bw = self.c.stringWidth(f"{pct:+d}%" if pct else "0%", "Helvetica-Bold", 8.5) + 26
                    self.badge(cx + cw - 12 - bw, mid - 8, pct, up_bad)
                    self.text(cx + cw - 20 - bw, mid - 5.5, fmt_num(val), fs, INK, anchor="r")
                elif kind == "sev":
                    self.sev_chip(cx + 12, mid - 6.5, v)
            self.top += rh
        c.setStrokeColor(HexColor(LINE)); c.setLineWidth(0.8)
        c.roundRect(x, H - self.top, w, self.top - seg_top, 6, stroke=1, fill=0)
        self.top += 24


def wrap(value, width, size, font="Helvetica", max_lines=4):
    """Word-wrap, breaking long unbroken strings (paths, package names) by character; ends with … if cut."""
    text = str(value if value is not None else "")
    width_of = lambda s: pdfmetrics.stringWidth(s, font, size)
    out = []
    for line in simpleSplit(text, font, size, width) or [""]:
        while width_of(line) > width and len(line) > 1:
            k = max(1, next((k for k in range(len(line), 0, -1) if width_of(line[:k]) <= width), 1))
            out.append(line[:k]); line = line[k:]
        out.append(line)
    if len(out) > max_lines:
        out = out[:max_lines]
        while out[-1] and width_of(out[-1] + "…") > width: out[-1] = out[-1][:-1]
        out[-1] += "…"
    return out


def stacked(bands):
    """Bucket counts (bottom band first) -> cumulative lines, so the top line is the total."""
    out, acc = [], [0] * len(bands[0])
    for b in bands:
        acc = [a + v for a, v in zip(acc, b)]; out.append(acc)
    return out
