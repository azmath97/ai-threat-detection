"""Shared presentation helpers: design system (theme, cards, tables), notices and layout blocks."""
from datetime import datetime

import streamlit as st

ORG_NAME = "Arden Bank"

_CSS = """
<style>
  :root { --bg:#F4F6F8; --card:#FFFFFF; --text:#1C252E; --muted:#637381; --line:#EDEFF2; --line-2:#DFE3E8;
          --green:#00A76F; --green-d:#007867; --green-bg:#E3F9EE; --amber:#B76E00; --amber-bg:#FFF5D6;
          --orange:#B54708; --orange-bg:#FFEBD9; --red:#B71D18; --red-bg:#FFE9E5; --blue:#006C9C; --blue-bg:#E0F6FB;
          --dark:#1C252E; --radius:16px;
          --shadow:0 0 2px 0 rgba(145,158,171,.20), 0 12px 24px -4px rgba(145,158,171,.12); }
  html, body, [class*="css"], .stApp { font-family: "Public Sans", "Inter", "Segoe UI", system-ui, -apple-system, Arial, sans-serif; color: var(--text); }
  .stApp { background: var(--bg); }
  #MainMenu, footer, [data-testid="stToolbar"], [data-testid="stDecoration"], [data-testid="stStatusWidget"] { display:none !important; }
  header[data-testid="stHeader"] { background: transparent; height: 0; }
  .block-container { padding-top: 1.8rem; padding-bottom: 2.5rem; max-width: 1240px; }

  h1, h2, h3 { color: var(--text); letter-spacing: 0; }
  div[data-testid="stMarkdownContainer"] h1 { font-size: 1.6rem !important; font-weight: 700 !important; line-height: 1.3 !important; margin: 0 0 .1rem 0 !important; padding: 0 !important; }
  div[data-testid="stMarkdownContainer"] h3 { font-size: 1.05rem !important; font-weight: 700 !important; line-height: 1.3 !important; margin: 1.6rem 0 .7rem 0 !important; padding: 0 !important; }
  div[data-testid="stMarkdownContainer"] h1 a, div[data-testid="stMarkdownContainer"] h3 a { display: none !important; }
  .page-sub { color: var(--muted); font-size: .9rem; margin: 0 0 1.1rem 0; }

  /* sidebar */
  section[data-testid="stSidebar"] { background: var(--card); border-right: 1px solid var(--line); }
  section[data-testid="stSidebar"] > div { padding-top: 1.1rem; }
  .brand { display: flex; align-items: center; gap: .65rem; padding: .1rem .35rem 1rem .35rem; }
  .brand-mark { width: 36px; height: 36px; border-radius: 10px; background: linear-gradient(135deg, #00C58A, #007867); color: #fff; font-weight: 800;
      display: flex; align-items: center; justify-content: center; font-size: 1.05rem; }
  .org-name { font-weight: 700; color: var(--text); font-size: 1rem; line-height: 1.2; }
  .org-sub { color: var(--muted); font-size: .76rem; }
  .nav-caption { color: #919EAB; font-size: .68rem; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; margin: 1.2rem 0 .5rem .5rem; }
  .whoami { color: var(--muted); font-size: .78rem; border-top: 1px dashed var(--line-2); padding-top: .8rem; margin-top: 1.2rem; line-height: 1.5; }
  .whoami b { color: var(--text); font-weight: 600; }
  section[data-testid="stSidebar"] .stButton > button { justify-content: flex-start; text-align: left; border: none; border-radius: 8px;
      background: transparent; color: var(--muted); font-weight: 600; padding: .5rem .8rem; box-shadow: none; min-height: 2.35rem; }
  section[data-testid="stSidebar"] .stButton > button:hover { background: rgba(145,158,171,.10); color: var(--text); }
  section[data-testid="stSidebar"] .stButton > button[kind="primary"] { background: rgba(0,167,111,.10); color: var(--green-d); font-weight: 700; }
  section[data-testid="stSidebar"] .stButton > button[kind="primary"]:hover { background: rgba(0,167,111,.16); }
  section[data-testid="stSidebar"] .stButton { margin-bottom: 0; }
  section[data-testid="stSidebar"] .stButton > button > div { justify-content: flex-start !important; width: 100%; gap: .6rem; }
  section[data-testid="stSidebar"] .stButton > button p { text-align: left !important; font-size: .9rem; }
  section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] { gap: .15rem; }

  /* controls */
  .stButton > button, .stDownloadButton > button, .stFormSubmitButton > button { border-radius: 8px; box-shadow: none; font-weight: 600;
      border: 1px solid rgba(145,158,171,.32); background: var(--card); color: var(--text); }
  .stButton > button:hover, .stDownloadButton > button:hover { border-color: var(--text); color: var(--text); }
  .stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primaryFormSubmit"], .stDownloadButton > button[kind="primary"] {
      background: var(--green); border-color: var(--green); color: #fff; font-weight: 700; }
  .stButton > button[kind="primary"]:hover, .stFormSubmitButton > button[kind="primaryFormSubmit"]:hover { background: var(--green-d); border-color: var(--green-d); color: #fff; }
  div[data-testid="stTextInputRootElement"], div[data-testid="stNumberInputContainer"], .stSelectbox div[data-baseweb="select"] > div {
      border-radius: 8px; border: 1px solid var(--line-2) !important; background: #fff; }
  div[data-testid="stTextInputRootElement"]:focus-within, div[data-testid="stNumberInputContainer"]:focus-within,
  .stSelectbox div[data-baseweb="select"]:focus-within > div { border-color: var(--green) !important; }
  div[data-testid="stForm"] { border: none; border-radius: var(--radius); padding: 1.4rem; background: var(--card); box-shadow: var(--shadow); }
  div[data-testid="stDataFrame"] { border-radius: var(--radius); }

  /* data grid (static HTML: no client-side export) */
  .grid-wrap { background: var(--card); border-radius: var(--radius); box-shadow: var(--shadow); max-height: 460px; overflow: auto; margin-bottom: .8rem; }
  table.grid { width: 100%; border-collapse: collapse; font-size: .875rem; }
  table.grid th { position: sticky; top: 0; text-align: left; background: #F4F6F8; color: var(--muted); font-weight: 600; font-size: .8rem;
      padding: .8rem 1rem; white-space: nowrap; }
  table.grid td { padding: .75rem 1rem; border-bottom: 1px dashed var(--line-2); }
  table.grid tbody tr:hover td { background: #FAFBFC; }
  table.grid tr:last-child td { border-bottom: none; }
  table.grid td.empty { color: var(--muted); text-align: center; padding: 1.6rem; }
  td.res-ok { color: var(--green-d); font-weight: 700; }
  td.res-bad { color: var(--red); font-weight: 700; }
  td.res-warn { color: var(--amber); font-weight: 700; }
  td.res-high { color: var(--orange); font-weight: 700; }

  /* notices */
  .notice { border-radius: 12px; padding: .8rem 1rem; margin: .6rem 0; font-size: .9rem; line-height: 1.5; }
  .notice.ok { background: var(--green-bg); color: var(--green-d); }
  .notice.warn { background: var(--amber-bg); color: var(--amber); }
  .notice.error { background: var(--red-bg); color: var(--red); }
  .notice.info { background: var(--blue-bg); color: var(--blue); }

  /* key / value table */
  table.kv { width: 100%; border-collapse: separate; border-spacing: 0; font-size: .9rem; margin-bottom: .6rem; background: var(--card);
      border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden; }
  table.kv th { text-align: left; width: 220px; color: var(--muted); font-weight: 600; padding: .7rem 1rem; border-bottom: 1px dashed var(--line-2); }
  table.kv td { padding: .7rem 1rem; border-bottom: 1px dashed var(--line-2); }
  table.kv tr:last-child th, table.kv tr:last-child td { border-bottom: none; }

  /* banner */
  .hero { border-radius: var(--radius); padding: 1.8rem 2rem; color: #fff; margin: .2rem 0 1.2rem 0; box-shadow: var(--shadow);
      background: radial-gradient(circle at 92% 12%, rgba(0,199,138,.38), transparent 46%), radial-gradient(circle at 70% 120%, rgba(0,120,103,.45), transparent 50%), var(--dark); }
  .hero .h-eyebrow { color: #5BE49B; font-size: .72rem; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
  .hero .h-title { font-size: 1.5rem; font-weight: 700; line-height: 1.3; margin: .35rem 0 .4rem 0; color: #fff; }
  .hero .h-text { color: #C4CDD5; font-size: .92rem; max-width: 640px; line-height: 1.55; }
  .hero .h-chips { margin-top: 1rem; display: flex; gap: .5rem; flex-wrap: wrap; }
  .hero .h-chip { background: rgba(255,255,255,.10); border-radius: 999px; padding: .25rem .8rem; font-size: .78rem; color: #E8EDF1; }
  .hero.alert { background: radial-gradient(circle at 92% 12%, rgba(255,86,48,.38), transparent 46%), radial-gradient(circle at 70% 120%, rgba(183,29,24,.45), transparent 50%), var(--dark); }
  .hero.alert .h-eyebrow { color: #FFAC82; }

  /* login */
  .login-brand { display: flex; align-items: center; gap: .7rem; margin-bottom: 1.2rem; }
  .login-title { font-size: 1.35rem; font-weight: 800; color: var(--text); line-height: 1.2; }
  .login-sub { color: var(--muted); font-size: .88rem; }
  .fine-print { color: var(--muted); font-size: .76rem; margin-top: 1rem; line-height: 1.5; }
  .sim-banner { background: var(--amber-bg); color: var(--amber); padding: .8rem 1.1rem; border-radius: 12px; font-weight: 700; font-size: .88rem; margin-bottom: 1.1rem; }
</style>
"""

ACTIVITY_LABELS = {
    "login": "Signed in",
    "login_failed": "Failed sign-in attempt",
    "logout": "Signed out",
    "resource_access": "Viewed",
    "file_download": "Downloaded",
    "data_export": "Exported",
    "directory_search": "Searched",
    "administrative_action": "Administrative action",
    "external_transfer": "External transfer",
    "permission_change_attempt": "Permission change request",
}
RESULT_LABELS = {"success": "Completed", "denied": "Denied", "failure": "Failed"}
ACCESS_LABELS = {"read": "Read", "write": "Read and write"}


def inject_css() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)


def page_header(title: str, subtitle: str = "") -> None:
    st.markdown(f"<h1>{title}</h1>", unsafe_allow_html=True)
    if subtitle:
        st.markdown(f'<div class="page-sub">{subtitle}</div>', unsafe_allow_html=True)


def notice(kind: str, text: str) -> None:
    """kind: ok | warn | error | info"""
    safe = text.replace("<", "&lt;").replace(">", "&gt;")
    st.markdown(f'<div class="notice {kind}">{safe}</div>', unsafe_allow_html=True)


def section(title: str) -> None:
    st.markdown(f"<h3>{title}</h3>", unsafe_allow_html=True)


def brand(subtitle: str) -> None:
    """Sidebar brand block."""
    st.markdown(f'<div class="brand"><div class="brand-mark">{ORG_NAME[0]}</div><div><div class="org-name">{ORG_NAME}</div>'
                f'<div class="org-sub">{_esc(subtitle)}</div></div></div>', unsafe_allow_html=True)


def login_header(subtitle: str) -> None:
    st.markdown(f'<div class="login-brand"><div class="brand-mark">{ORG_NAME[0]}</div><div><div class="login-title">{ORG_NAME}</div>'
                f'<div class="login-sub">{_esc(subtitle)}</div></div></div>', unsafe_allow_html=True)


def nav_caption(text: str) -> None:
    st.markdown(f'<div class="nav-caption">{_esc(text)}</div>', unsafe_allow_html=True)


def hero(eyebrow: str, title: str, text: str = "", chips: list[str] | None = None, tone: str = "") -> None:
    """Dark summary banner. Only ever shows text handed in by the caller."""
    chip_html = "".join(f'<span class="h-chip">{_esc(c)}</span>' for c in (chips or []))
    st.markdown(f'<div class="hero {tone}"><div class="h-eyebrow">{_esc(eyebrow)}</div><div class="h-title">{_esc(title)}</div>'
                f'<div class="h-text">{_esc(text)}</div><div class="h-chips">{chip_html}</div></div>', unsafe_allow_html=True)


def kv_table(rows: list[tuple[str, str]]) -> None:
    body = "".join(
        f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>" for k, v in rows
    )
    st.markdown(f'<table class="kv">{body}</table>', unsafe_allow_html=True)


def _esc(value) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def fmt_ts(iso: str | None, with_time: bool = True) -> str:
    if not iso:
        return "-"
    parsed = datetime.fromisoformat(iso)
    return parsed.strftime("%d %b %Y %H:%M" if with_time else "%d %b %Y")


def fmt_time(iso: str | None) -> str:
    """Compact timestamp with seconds, for event feeds."""
    return datetime.fromisoformat(iso).strftime("%d %b %H:%M:%S") if iso else "-"


def fmt_money(value: float, currency: str = "USD") -> str:
    return f"{currency} {value:,.2f}"


_RESULT_CLASS = {"Completed": "res-ok", "Denied": "res-bad", "Failed": "res-bad",
                 "Denied by backend": "res-bad", "Blocked": "res-warn",
                 "Critical": "res-bad", "High Risk": "res-high", "Suspicious": "res-warn",
                 "contained": "res-warn", "Done": "res-ok", "Pending": "res-warn",
                 "denied": "res-bad", "failure": "res-bad"}


def table(rows: list[dict], columns: dict[str, str], result_column: str | list[str] | None = None) -> None:
    """Static HTML table (no client-side export toolbar). `columns` maps field -> header.
    `result_column` names the column(s) whose values are colour-coded (status / severity)."""
    coded = {result_column} if isinstance(result_column, str) else set(result_column or [])
    head = "".join(f"<th>{_esc(h)}</th>" for h in columns.values())
    body = []
    for row in rows:
        cells = []
        for key in columns:
            value = row.get(key, "")
            css = _RESULT_CLASS.get(value, "") if key in coded else ""
            cells.append(f'<td class="{css}">{_esc(value)}</td>')
        body.append(f"<tr>{''.join(cells)}</tr>")
    if not body:
        body.append(f'<tr><td colspan="{len(columns)}" class="empty">No records</td></tr>')
    st.markdown(f'<div class="grid-wrap"><table class="grid"><thead><tr>{head}</tr></thead>'
                f'<tbody>{"".join(body)}</tbody></table></div>', unsafe_allow_html=True)


def activity_rows(events: list[dict], resource_names: dict[str, str]) -> list[dict]:
    return [
        {
            "time": fmt_ts(e["timestamp_local"]),
            "activity": ACTIVITY_LABELS.get(e["event_type"], e["event_type"]),
            "resource": resource_names.get(e["resource"], "-") if e["resource"] else "-",
            "records": e["records_accessed"],
            "result": RESULT_LABELS.get(e["outcome"], e["outcome"]),
        }
        for e in events
    ]
