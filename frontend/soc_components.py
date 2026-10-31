"""SOC dashboard presentation: KPI cards, confidence meter, stage strip and Plotly charts.

Every function here only renders data handed to it by the backend; nothing is computed or hardcoded for display.
"""
import html

import plotly.graph_objects as go
import streamlit as st

from frontend import components as ui

NAVY, BLUE, GREY, LINE = "#1B2A41", "#1F4E8C", "#7B8794", "#D5DAE1"
SEVERITY_COLOURS = {"normal": "#9FB3C8", "suspicious": "#E3B341", "high_risk": "#D9822B", "critical": "#B3342D"}
SEVERITY_LABELS = {"normal": "Normal", "suspicious": "Suspicious", "high_risk": "High Risk", "critical": "Critical"}

_CSS = """
<style>
  .block-container { max-width: 1480px; padding-top: 1.2rem; }
  section[data-testid="stSidebar"] { width: 232px !important; min-width: 232px !important; }
  section[data-testid="stSidebar"] .stButton { position: relative; z-index: 3; }
  section[data-testid="stSidebar"] .stButton > button { padding: .32rem .75rem; min-height: 2.1rem; }
  section[data-testid="stSidebar"] > div { padding-top: .4rem; }
  .org-sub { margin-bottom: .5rem !important; padding-bottom: .5rem !important; }
  .whoami { margin-top: .5rem !important; }
  .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: .6rem; margin: .2rem 0 .5rem 0; }
  .kpi { border: 1px solid var(--line); background: #fff; padding: .55rem .75rem; border-radius: 2px; min-height: 84px; }
  .kpi .k-label { color: var(--muted); font-size: .68rem; text-transform: uppercase; letter-spacing: .02em; word-break: normal; overflow-wrap: normal; }
  .kpi .k-value { color: var(--navy); font-size: 1.4rem; font-weight: 600; line-height: 1.3; word-break: normal; }
  .kpi .k-sub { color: var(--muted); font-size: .72rem; }
  .kpi .k-value.long { font-size: 1.02rem; line-height: 1.9; }
  section[data-testid="stSidebar"] .stButton > button:focus:not(:active):not([kind="primary"]) { background: transparent; box-shadow: none; }
  section[data-testid="stSidebar"] .stButton > button:hover:not([kind="primary"]) { background: #E7ECF2; }
  .kpi.alert .k-value { color: var(--red); }
  .kpi.warn .k-value { color: #9A4A00; }

  .meter { border: 1px solid var(--line); padding: .8rem 1rem; background: #fff; }
  .meter .m-head { display: flex; align-items: baseline; gap: .8rem; margin-bottom: .5rem; }
  .meter .m-score { font-size: 2.1rem; font-weight: 600; color: var(--navy); line-height: 1; }
  .meter .m-of { color: var(--muted); font-size: .8rem; }
  .sev { font-size: .78rem; font-weight: 600; padding: .1rem .5rem; border: 1px solid; border-radius: 2px; }
  .sev-normal { color: #3B4A5F; background: #EEF2F6; border-color: #C6D1DC; }
  .sev-suspicious { color: #7A5200; background: #FFF6DD; border-color: #E3B341; }
  .sev-high_risk { color: #8A3B00; background: #FDEBDC; border-color: #D9822B; }
  .sev-critical { color: #9F1F1B; background: #FCEBEA; border-color: #B3342D; }
  .m-bar { position: relative; display: flex; height: 16px; border: 1px solid var(--line); }
  .m-bar .band { height: 100%; }
  .m-bar .marker { position: absolute; top: -5px; width: 3px; height: 26px; background: var(--navy); }
  .m-scale { position: relative; height: 18px; font-size: .7rem; color: var(--muted); }
  .m-scale span { position: absolute; transform: translateX(-50%); }
  .m-legend { font-size: .72rem; color: var(--muted); margin-top: .3rem; }

  .stages { display: flex; border: 1px solid var(--line); margin: .3rem 0 .8rem 0; background: #fff; }
  .stages .st { flex: 1; padding: .45rem .5rem; border-right: 1px solid var(--line); min-width: 0; }
  .stages .st:last-child { border-right: none; }
  .stages .st .s-name { font-size: .74rem; color: var(--muted); font-weight: 600; }
  .stages .st .s-info { font-size: .7rem; color: var(--muted); margin-top: .15rem; min-height: 1.9em; }
  .stages .st.reached { background: #EDF2F8; }
  .stages .st.reached .s-name { color: var(--navy); }
  .stages .st.current { background: #FCEBEA; box-shadow: inset 0 -3px 0 var(--red); }
  .stages .st.current .s-name { color: var(--red); }

  .live-note { color: var(--muted); font-size: .74rem; margin-bottom: .4rem; }
  .live-dot { display: inline-block; width: 7px; height: 7px; background: #1E6B34; border-radius: 50%; margin-right: 5px; }
  .tag { font-size: .7rem; border: 1px solid var(--line); padding: 0 .3rem; color: var(--muted); border-radius: 2px; }
  div[data-testid="stPlotlyChart"] { border: 1px solid var(--line); background: #fff; }
</style>
"""


def inject() -> None:
    ui.inject_css()
    st.markdown(_CSS, unsafe_allow_html=True)


def severity_badge(level: str) -> str:
    return f'<span class="sev sev-{level}">{html.escape(SEVERITY_LABELS.get(level, level))}</span>'


def kpi(label: str, value, sub: str = "", tone: str = "") -> str:
    size = " long" if len(str(value)) > 14 else ""
    return (f'<div class="kpi {tone}"><div class="k-label">{html.escape(label)}</div>'
            f'<div class="k-value{size}">{html.escape(str(value))}</div><div class="k-sub">{html.escape(sub)}</div></div>')


def kpi_grid(tiles: list[tuple]) -> None:
    st.markdown(f'<div class="kpi-grid">{"".join(kpi(*[str(x) if i < 3 else x for i, x in enumerate(t)]) for t in tiles)}</div>',
                unsafe_allow_html=True)


def meter(confidence: float, level: str, thresholds: dict) -> str:
    """Flat segmented bar: band widths come from the backend's configured thresholds."""
    s, h, c = thresholds["suspicious"], thresholds["high_risk"], thresholds["critical"]
    bands = [("normal", 0, s), ("suspicious", s, h), ("high_risk", h, c), ("critical", c, 100)]
    segments = "".join(f'<div class="band" style="width:{hi - lo}%;background:{SEVERITY_COLOURS[name]}"></div>' for name, lo, hi in bands)
    marks = "".join(f'<span style="left:{v}%">{v}</span>' for v in (0, s, h, c, 100))
    return (f'<div class="meter"><div class="m-head"><span class="m-score">{confidence:.1f}</span><span class="m-of">/ 100</span>'
            f'{severity_badge(level)}</div><div class="m-bar">{segments}<div class="marker" style="left:calc({min(confidence, 100)}% - 1px)"></div></div>'
            f'<div class="m-scale">{marks}</div>'
            f'<div class="m-legend">Normal &lt; {s} &lt;= Suspicious &lt; {h} &lt;= High Risk &lt; {c} &lt;= Critical</div></div>')


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
        height=height, margin=dict(l=40, r=15, t=28, b=32), paper_bgcolor="white", plot_bgcolor="white",
        font=dict(family="Segoe UI, Arial, sans-serif", size=11, color=NAVY), showlegend=False,
    )
    options.update(kwargs)
    fig.update_layout(**options)
    fig.update_xaxes(showline=True, linecolor=LINE, gridcolor="#EEF1F4", zeroline=False)
    fig.update_yaxes(showline=True, linecolor=LINE, gridcolor="#EEF1F4", zeroline=False)
    return fig


def events_per_hour_chart(buckets: list[dict]) -> go.Figure:
    fig = go.Figure(go.Bar(x=[b["hour"] for b in buckets], y=[b["count"] for b in buckets], marker_color=BLUE))
    fig.update_layout(title=dict(text="Security events per hour (last 24 h, UTC)", font=dict(size=12)))
    return _layout(fig, 230)


def severity_chart(counts: dict) -> go.Figure:
    names = list(counts)
    fig = go.Figure(go.Bar(x=[SEVERITY_LABELS[n] for n in names], y=[counts[n] for n in names],
                           marker_color=[SEVERITY_COLOURS[n] for n in names]))
    fig.update_layout(title=dict(text="Employees by current severity", font=dict(size=12)))
    return _layout(fig, 230)


def confidence_chart(points: list[dict], thresholds: dict) -> go.Figure:
    fig = go.Figure(go.Scatter(x=[p["time"]["local"] for p in points], y=[p["score"] for p in points], mode="lines+markers",
                               line=dict(color=BLUE, width=2, shape="hv"), marker=dict(size=5, color=NAVY),
                               text=[p["stage"] or "none" for p in points],
                               hovertemplate="%{x}<br>confidence %{y}<br>stage %{text}<extra></extra>"))
    for name in ("suspicious", "high_risk", "critical"):
        fig.add_hline(y=thresholds[name], line=dict(color=SEVERITY_COLOURS[name], width=1, dash="dot"),
                      annotation_text=SEVERITY_LABELS[name], annotation_position="top left", annotation_font_size=10)
    fig.update_layout(title=dict(text="Attack confidence over time (from stored assessments)", font=dict(size=12)))
    fig.update_yaxes(range=[0, 100])
    return _layout(fig, 250)


def stage_lane_chart(stages: list[dict], events: list[dict]) -> go.Figure:
    """Events plotted on the lane of every stage they support, in time order."""
    labels = {s["stage"]: s["label"] for s in stages}
    xs, ys, text, colours = [], [], [], []
    for e in events:
        for stage in e.get("stages", []):
            xs.append(e["timestamp"]["local"])
            ys.append(labels[stage])
            text.append(f"#{e['event_id']} {e['event_type']} {e['resource'] or ''} ({e['outcome']})<br>{e['account']} from {e['source_ip']}")
            colours.append("#B3342D" if e["outcome"] in ("denied", "failure") else BLUE)
    fig = go.Figure(go.Scatter(x=xs, y=ys, mode="markers", text=text, hovertemplate="%{text}<extra></extra>",
                               marker=dict(size=11, color=colours, line=dict(color="white", width=1))))
    fig.update_yaxes(categoryorder="array", categoryarray=[s["label"] for s in reversed(stages)])
    current = next((s["label"] for s in stages if s["current"]), None)
    if current:
        fig.add_hrect(y0=[s["label"] for s in reversed(stages)].index(current) - 0.5,
                      y1=[s["label"] for s in reversed(stages)].index(current) + 0.5, fillcolor="#FCEBEA", opacity=0.6, line_width=0)
    fig.update_layout(title=dict(text="Events by attack stage (current stage shaded)", font=dict(size=12)))
    return _layout(fig, 340, margin=dict(l=150, r=15, t=28, b=32))


COLUMNS = [("ip", "Employee accounts and source IP addresses"), ("session", "Sessions"),
           ("system", "Internal systems"), ("external", "External destinations")]
_COL_OF = {"account": 0, "privileged_account": 0, "ip": 0, "session": 1, "system": 2, "external": 3}
_STYLE = {
    "ip": ("square", 13, "#7B8794"), "session": ("circle", 10, "#5B87B8"), "account": ("circle", 15, NAVY),
    "privileged_account": ("diamond", 17, "#B3342D"), "system": ("square", 15, "#1F4E8C"), "external": ("triangle-up", 16, "#B3342D"),
}
_EDGE_COLOURS = {"created": "#B3342D", "transfer": "#B3342D", "data_flow": "#B3342D"}


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
        colour = _EDGE_COLOURS.get(e["kind"]) or ("#B3342D" if e["outcome"] in ("denied", "failure") else
                                                  "#D9822B" if e["suspicious"] else "#B8C2CC")
        dash = "dash" if e["outcome"] in ("denied", "failure") else "solid"
        groups.setdefault((colour, dash), []).append(e)
    names = {"#B3342D": "Suspicious / denied / created", "#D9822B": "Flagged activity", "#B8C2CC": "Normal activity"}
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
                           text=e["label"], showarrow=False, font=dict(size=9, color="#5F6B7A"), bgcolor="white",
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
            text=[n["label"] for n in nodes], textposition="top center", textfont=dict(size=10, color=NAVY),
            marker=dict(symbol=symbol, size=size, color=colour,
                        line=dict(color=["#B3342D" if n["suspicious"] else "white" for n in nodes],
                                  width=[3 if n["suspicious"] else 1 for n in nodes])),
            hovertext=[f"{n['label']}<br>{kinds[kind]}" + ("<br>flagged by detection" if n["suspicious"] else "") for n in nodes],
            hoverinfo="text"))
    for i, (_, title) in enumerate(COLUMNS):
        fig.add_annotation(x=i, y=tallest - 0.35, text=f"<b>{title}</b>", showarrow=False, font=dict(size=11, color=GREY), yshift=18)
    fig.update_xaxes(visible=False, range=[-0.6, len(COLUMNS) - 0.4])
    fig.update_yaxes(visible=False, range=[-0.8, tallest + 0.2])
    return _layout(fig, max(420, 90 * tallest + 140), showlegend=True,
                   legend=dict(orientation="h", y=-0.04, x=0, font=dict(size=10)), margin=dict(l=10, r=10, t=20, b=40))
