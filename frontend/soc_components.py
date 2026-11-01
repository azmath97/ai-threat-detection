"""SOC dashboard presentation: KPI cards, confidence gauge, stage strip and Plotly charts.

Every function here only renders data handed to it by the backend; nothing is computed or hardcoded for display.
"""
import html

import plotly.graph_objects as go
import streamlit as st

from frontend import components as ui
from frontend.theme import SANS, SERIF, SOC_CSS

INK, ACCENT, GREY = "#17212B", "#1E6F5C", "#8B969E"
SEVERITY_COLOURS = {"normal": "#2F8466", "suspicious": "#D4A02D", "high_risk": "#D9742A", "critical": "#C2403A"}
SEVERITY_LABELS = {"normal": "Normal", "suspicious": "Suspicious", "high_risk": "High Risk", "critical": "Critical"}
FONT = SANS.replace('"', "")

ICONS = {   # 24x24 stroke icons (Lucide-style paths)
    "activity": "M22 12h-4l-3 9L9 3l-3 9H2",
    "briefcase": "M4 7h16a1 1 0 0 1 1 1v11a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V8a1 1 0 0 1 1-1zM9 7V4h6v3M3 13h18",
    "alert": "M12 3 2 20h20L12 3zM12 10v4M12 17h.01",
    "users": "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM22 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8",
    "database": "M12 8c4.4 0 8-1.1 8-2.5S16.4 3 12 3 4 4.1 4 5.5 7.6 8 12 8zM4 5.5v13C4 19.9 7.6 21 12 21s8-1.1 8-2.5v-13M4 12c0 1.4 3.6 2.5 8 2.5s8-1.1 8-2.5",
    "send": "M22 2 11 13M22 2l-7 20-4-9-9-4 20-7z",
    "shield": "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
}


def inject() -> None:
    ui.inject_css()
    st.markdown(SOC_CSS, unsafe_allow_html=True)


def severity_badge(level: str) -> str:
    return f'<span class="sev sev-{level}">{html.escape(SEVERITY_LABELS.get(level, level))}</span>'


def sparkline(values: list[float], colour: str = ACCENT) -> str:
    """Inline SVG trend line from real values (for example events per hour)."""
    if len(values) < 2:
        return ""
    lo, hi = min(values), max(values)
    span = (hi - lo) or 1
    pts = [(i * 96 / (len(values) - 1), 40 - (v - lo) / span * 36) for i, v in enumerate(values)]
    path = "M" + " L".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    return (f'<svg class="spark" viewBox="0 0 96 44" preserveAspectRatio="none"><path d="{path}" fill="none" stroke="{colour}" '
            f'stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>')


def kpi(label: str, value, sub: str = "", tone: str = "", icon: str = "", spark: list[float] | None = None) -> str:
    size = " long" if len(str(value)) > 14 else ""
    visual = ""
    if spark:
        visual = sparkline(spark, {"alert": SEVERITY_COLOURS["critical"], "warn": SEVERITY_COLOURS["high_risk"]}.get(tone, ACCENT))
    elif icon in ICONS:
        visual = f'<div class="k-icon"><svg viewBox="0 0 24 24"><path d="{ICONS[icon]}"/></svg></div>'
    return (f'<div class="kpi {tone}"><div class="k-text"><div class="k-label">{html.escape(label)}</div>'
            f'<div class="k-value{size}">{html.escape(str(value))}</div><div class="k-sub">{html.escape(sub)}</div></div>'
            f'<div class="k-visual">{visual}</div></div>')


def kpi_grid(tiles: list[tuple]) -> None:
    """Each tile: (label, value, sub, tone, icon, spark) - the last three are optional."""
    cards = "".join(kpi(*[str(x) if i < 3 else x for i, x in enumerate(t)]) for t in tiles)
    st.markdown(f'<div class="kpi-grid">{cards}</div>', unsafe_allow_html=True)


def meter(confidence: float, level: str, thresholds: dict) -> str:
    """Ring gauge plus a segmented bar; band widths come from the backend's configured thresholds."""
    s, h, c = thresholds["suspicious"], thresholds["high_risk"], thresholds["critical"]
    bands = [("normal", 0, s), ("suspicious", s, h), ("high_risk", h, c), ("critical", c, 100)]
    segments = "".join(f'<div class="band" style="width:{hi - lo}%;background:{SEVERITY_COLOURS[name]}"></div>' for name, lo, hi in bands)
    marks = "".join(f'<span style="left:{v}%">{v}</span>' for v in (0, s, h, c, 100))
    circumference = 2 * 3.14159265 * 56
    offset = circumference * (1 - min(max(confidence, 0), 100) / 100)
    ring = (f'<div class="m-ring"><svg viewBox="0 0 140 140"><circle class="track" cx="70" cy="70" r="56" fill="none" stroke-width="12"/>'
            f'<circle class="arc" cx="70" cy="70" r="56" fill="none" stroke-width="12" stroke-linecap="round" stroke="{SEVERITY_COLOURS[level]}" '
            f'stroke-dasharray="{circumference:.1f}" stroke-dashoffset="{offset:.1f}"/></svg>'
            f'<div class="m-score"><b>{confidence:.1f}</b><span class="m-of">of 100</span></div></div>')
    return (f'<div class="meter">{ring}<div class="m-body"><div class="m-head"><span class="m-title">Attack confidence</span>'
            f'{severity_badge(level)}</div><div class="m-bar">{segments}<div class="marker" style="left:calc({min(confidence, 100)}% - 1px)"></div></div>'
            f'<div class="m-scale">{marks}</div>'
            f'<div class="m-legend">Normal &lt; {s} &lt;= Suspicious &lt; {h} &lt;= High Risk &lt; {c} &lt;= Critical</div></div></div>')


def stage_strip(stages: list[dict]) -> str:
    cells = []
    for s in stages:
        css = "st reached" if s["reached"] else "st"
        if s["current"]:
            css = "st current"
        info = (f'{s["event_count"]} event{"s" if s["event_count"] != 1 else ""}<br>{ui.fmt_time(s["first_seen"]["local"])}'
                if s["reached"] else "not observed")
        cells.append(f'<div class="{css}"><div class="s-name">{html.escape(s["label"])}</div><div class="s-info">{info}</div></div>')
    return f'<div class="stages">{"".join(cells)}</div>'


def live_note(text: str) -> None:
    st.markdown(f'<div class="live-note"><span class="live-dot"></span>{html.escape(text)}</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------- charts
def _layout(fig: go.Figure, height: int, **kwargs) -> go.Figure:
    options = dict(
        height=height, margin=dict(l=44, r=18, t=46, b=34), paper_bgcolor="white", plot_bgcolor="white",
        font=dict(family=FONT, size=11, color=INK), showlegend=False,
        title=dict(font=dict(size=15, color=INK, family=SERIF.replace('"', "")), x=0.02, y=0.96),
    )
    options.update(kwargs)
    fig.update_layout(**options)
    fig.update_xaxes(showline=False, gridcolor="#F0EDE5", zeroline=False, tickfont=dict(color="#5E6B75"))
    fig.update_yaxes(showline=False, gridcolor="#F0EDE5", zeroline=False, tickfont=dict(color="#5E6B75"))
    return fig


def events_per_hour_chart(buckets: list[dict]) -> go.Figure:
    fig = go.Figure(go.Scatter(x=[b["hour"] for b in buckets], y=[b["count"] for b in buckets], mode="lines",
                               line=dict(color=ACCENT, width=3, shape="spline", smoothing=0.8),
                               fill="tozeroy", fillcolor="rgba(30,111,92,0.10)",
                               hovertemplate="%{x|%d %b %H:00}<br>%{y} events<extra></extra>"))
    fig.update_layout(title=dict(text="Security events per hour (last 24 h, UTC)"))
    return _layout(fig, 300)


def severity_chart(counts: dict) -> go.Figure:
    names = list(counts)
    total = sum(counts.values())
    fig = go.Figure(go.Pie(labels=[SEVERITY_LABELS[n] for n in names], values=[counts[n] for n in names], hole=0.7, sort=False,
                           marker=dict(colors=[SEVERITY_COLOURS[n] for n in names], line=dict(color="white", width=3)),
                           textinfo="none", hovertemplate="%{label}: %{value} employees<extra></extra>"))
    fig.add_annotation(text=f"<b style='font-size:26px'>{total}</b><br><span style='color:#5E6B75'>employees</span>", showarrow=False)
    fig.update_layout(title=dict(text="Employees by current severity"))
    return _layout(fig, 300, showlegend=True, legend=dict(orientation="h", y=-0.02, x=0.5, xanchor="center", font=dict(size=11)),
                   margin=dict(l=20, r=20, t=46, b=20))


def confidence_chart(points: list[dict], thresholds: dict) -> go.Figure:
    fig = go.Figure(go.Scatter(x=[p["time"]["local"] for p in points], y=[p["score"] for p in points], mode="lines+markers",
                               line=dict(color=ACCENT, width=3, shape="hv"), marker=dict(size=7, color="white", line=dict(color=ACCENT, width=2)),
                               fill="tozeroy", fillcolor="rgba(30,111,92,0.08)", text=[p["stage"] or "none" for p in points],
                               hovertemplate="%{x}<br>confidence %{y}<br>stage %{text}<extra></extra>"))
    for name in ("suspicious", "high_risk", "critical"):
        fig.add_hline(y=thresholds[name], line=dict(color=SEVERITY_COLOURS[name], width=1, dash="dot"),
                      annotation_text=SEVERITY_LABELS[name], annotation_position="top left", annotation_font_size=10)
    fig.update_layout(title=dict(text="Attack confidence over time (from stored assessments)"))
    fig.update_yaxes(range=[0, 100])
    return _layout(fig, 300)


def stage_lane_chart(stages: list[dict], events: list[dict]) -> go.Figure:
    """Events plotted on the lane of every stage they support, in time order."""
    labels = {s["stage"]: s["label"] for s in stages}
    xs, ys, text, colours = [], [], [], []
    for e in events:
        for stage in e.get("stages", []):
            xs.append(e["timestamp"]["local"])
            ys.append(labels[stage])
            text.append(f"#{e['event_id']} {e['event_type']} {e['resource'] or ''} ({e['outcome']})<br>{e['account']} from {e['source_ip']}")
            colours.append(SEVERITY_COLOURS["critical"] if e["outcome"] in ("denied", "failure") else ACCENT)
    fig = go.Figure(go.Scatter(x=xs, y=ys, mode="markers", text=text, hovertemplate="%{text}<extra></extra>",
                               marker=dict(size=12, color=colours, line=dict(color="white", width=2))))
    fig.update_yaxes(categoryorder="array", categoryarray=[s["label"] for s in reversed(stages)])
    current = next((s["label"] for s in stages if s["current"]), None)
    if current:
        fig.add_hrect(y0=[s["label"] for s in reversed(stages)].index(current) - 0.5,
                      y1=[s["label"] for s in reversed(stages)].index(current) + 0.5, fillcolor="#F8E1DE", opacity=0.7, line_width=0)
    fig.update_layout(title=dict(text="Events by attack stage (current stage shaded)"))
    return _layout(fig, 360, margin=dict(l=160, r=18, t=46, b=34))


COLUMNS = [("ip", "Employee accounts and source IP addresses"), ("session", "Sessions"),
           ("system", "Internal systems"), ("external", "External destinations")]
_COL_OF = {"account": 0, "privileged_account": 0, "ip": 0, "session": 1, "system": 2, "external": 3}
_STYLE = {
    "ip": ("square", 13, "#8B969E"), "session": ("circle", 10, "#2B5A78"), "account": ("circle", 15, INK),
    "privileged_account": ("diamond", 17, "#C2403A"), "system": ("square", 15, ACCENT), "external": ("triangle-up", 16, "#C2403A"),
}
_EDGE_COLOURS = {"created": "#C2403A", "transfer": "#C2403A", "data_flow": "#C2403A"}


def attack_graph(graph: dict) -> go.Figure:
    """Layered layout (by node type) of the relationships found in the stored events."""
    columns: dict[int, list[dict]] = {i: [] for i in range(len(COLUMNS))}
    order = {"account": 0, "privileged_account": 1, "ip": 2}
    for n in sorted(graph["nodes"], key=lambda n: (order.get(n["kind"], 0), n["id"])):
        columns[_COL_OF[n["kind"]]].append(n)
    tallest = max((len(v) for v in columns.values()), default=1) or 1
    pos = {}
    for col, nodes in columns.items():
        for i, n in enumerate(nodes):
            pos[n["id"]] = (col, (tallest - 1) / 2 - (i - (len(nodes) - 1) / 2) if len(nodes) > 1 else (tallest - 1) / 2)
    fig = go.Figure()
    groups = {}
    for e in graph["edges"]:
        if e["source"] not in pos or e["target"] not in pos:
            continue
        colour = _EDGE_COLOURS.get(e["kind"]) or ("#C2403A" if e["outcome"] in ("denied", "failure") else
                                                  "#D4A02D" if e["suspicious"] else "#CFC9BB")
        dash = "dash" if e["outcome"] in ("denied", "failure") else "solid"
        groups.setdefault((colour, dash), []).append(e)
    names = {"#C2403A": "Suspicious / denied / created", "#D4A02D": "Flagged activity", "#CFC9BB": "Normal activity"}
    shown = set()
    for (colour, dash), edges in groups.items():
        xs, ys = [], []
        for e in edges:
            (x0, y0), (x1, y1) = pos[e["source"]], pos[e["target"]]
            xs += [x0, x1, None]
            ys += [y0, y1, None]
        fig.add_trace(go.Scatter(x=xs, y=ys, mode="lines", line=dict(color=colour, width=1.6, dash=dash), hoverinfo="skip",
                                 name=names[colour], showlegend=names[colour] not in shown))
        shown.add(names[colour])
    mids = [e for e in graph["edges"] if e["label"] and e["source"] in pos and e["target"] in pos]
    for e in mids:
        fig.add_annotation(x=(pos[e["source"]][0] + pos[e["target"]][0]) / 2, y=(pos[e["source"]][1] + pos[e["target"]][1]) / 2,
                           text=e["label"], showarrow=False, font=dict(size=9, color="#5E6B75"), bgcolor="white",
                           borderpad=1, opacity=0.95)
    kinds = {"ip": "IP address", "session": "Session", "account": "Employee account", "privileged_account": "Privileged account",
             "system": "Internal system", "external": "External destination"}
    for kind, label in kinds.items():
        nodes = [n for n in graph["nodes"] if n["kind"] == kind]
        if not nodes:
            continue
        symbol, size, colour = _STYLE[kind]
        fig.add_trace(go.Scatter(
            x=[pos[n["id"]][0] for n in nodes], y=[pos[n["id"]][1] for n in nodes], mode="markers+text", name=label,
            text=[n["label"] for n in nodes], textposition="top center", textfont=dict(size=10, color=INK),
            marker=dict(symbol=symbol, size=size, color=colour,
                        line=dict(color=["#C2403A" if n["suspicious"] else "white" for n in nodes],
                                  width=[3 if n["suspicious"] else 1 for n in nodes])),
            hovertext=[f"{n['label']}<br>{kinds[kind]}" + ("<br>flagged by detection" if n["suspicious"] else "") for n in nodes],
            hoverinfo="text"))
    for i, (_, title) in enumerate(COLUMNS):
        fig.add_annotation(x=i, y=tallest - 0.35, text=f"<b>{title}</b>", showarrow=False, font=dict(size=11, color=GREY), yshift=18)
    fig.update_xaxes(visible=False, range=[-0.6, len(COLUMNS) - 0.4])
    fig.update_yaxes(visible=False, range=[-0.8, tallest + 0.2])
    return _layout(fig, max(420, 90 * tallest + 140), showlegend=True,
                   legend=dict(orientation="h", y=-0.04, x=0, font=dict(size=10)), margin=dict(l=10, r=10, t=20, b=40))
