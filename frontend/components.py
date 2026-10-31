"""Shared presentation helpers: enterprise theme, notices, tables."""
from datetime import datetime

import streamlit as st

ORG_NAME = "Meridian Trust Bank"

_CSS = """
<style>
  :root { --navy:#1B2A41; --text:#1F2933; --muted:#5F6B7A; --blue:#1F4E8C; --line:#D5DAE1; --panel:#F4F6F8;
          --green:#1E6B34; --green-bg:#EAF5EC; --amber:#7A5200; --amber-bg:#FFF6DD; --red:#9F1F1B; --red-bg:#FCEBEA; }
  html, body, [class*="css"], .stApp { font-family: "Segoe UI", Arial, Helvetica, sans-serif; color: var(--text); }
  #MainMenu, footer, [data-testid="stToolbar"], [data-testid="stDecoration"], [data-testid="stStatusWidget"] { display:none !important; }
  header[data-testid="stHeader"] { background: transparent; height: 0; }
  .block-container { padding-top: 1.6rem; padding-bottom: 2rem; max-width: 1180px; }

  h1, h2, h3 { color: var(--navy); font-weight: 600; letter-spacing: 0; }
  div[data-testid="stMarkdownContainer"] h1 { font-size: 1.45rem !important; line-height: 1.3 !important; margin: 0 0 .15rem 0 !important; padding: 0 !important; }
  div[data-testid="stMarkdownContainer"] h3 { font-size: 1.02rem !important; line-height: 1.3 !important; margin: 1.3rem 0 .5rem 0 !important;
      padding: 0 0 .3rem 0 !important; border-bottom: 1px solid var(--line); }
  div[data-testid="stMarkdownContainer"] h1 a, div[data-testid="stMarkdownContainer"] h3 a { display: none !important; }
  .page-sub { color: var(--muted); font-size: .88rem; margin: 0 0 1rem 0; }

  /* sidebar */
  section[data-testid="stSidebar"] { background: var(--panel); border-right: 1px solid var(--line); }
  section[data-testid="stSidebar"] > div { padding-top: 1rem; }
  .org-name { font-weight: 700; color: var(--navy); font-size: 1.02rem; line-height: 1.2; }
  .org-sub { color: var(--muted); font-size: .78rem; margin-bottom: 1rem; padding-bottom: .8rem; border-bottom: 1px solid var(--line); }
  .whoami { color: var(--muted); font-size: .78rem; border-top: 1px solid var(--line); padding-top: .7rem; margin-top: 1rem; line-height: 1.5; }
  .whoami b { color: var(--text); font-weight: 600; }
  section[data-testid="stSidebar"] .stButton > button { justify-content: flex-start; text-align: left; border: none; border-radius: 0;
      background: transparent; color: var(--text); font-weight: 500; padding: .45rem .75rem; box-shadow: none; border-left: 3px solid transparent; }
  section[data-testid="stSidebar"] .stButton > button:hover { background: #E7ECF2; color: var(--navy); }
  section[data-testid="stSidebar"] .stButton > button[kind="primary"] { background: #E3EAF3; color: var(--blue); border-left: 3px solid var(--blue); font-weight: 600; }
  section[data-testid="stSidebar"] .stButton { margin-bottom: 0; }
  section[data-testid="stSidebar"] .stButton > button > div { justify-content: flex-start !important; width: 100%; }
  section[data-testid="stSidebar"] .stButton > button p { text-align: left !important; font-size: .92rem; }
  section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] { gap: .1rem; }

  /* controls */
  .stButton > button, .stDownloadButton > button, .stFormSubmitButton > button { border-radius: 3px; box-shadow: none; font-weight: 500; }
  .stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"], .stDownloadButton > button[kind="primary"] { background: var(--blue); border-color: var(--blue); color: #fff; }
  .stTextInput input, .stSelectbox div[data-baseweb="select"] > div { border-radius: 3px; }
  div[data-testid="stForm"] { border: 1px solid var(--line); border-radius: 3px; padding: 1rem; background: #fff; }
  div[data-testid="stDataFrame"] { border: 1px solid var(--line); border-radius: 3px; }

  /* data grid (static HTML: no client-side export) */
  .grid-wrap { border: 1px solid var(--line); border-radius: 3px; max-height: 440px; overflow: auto; margin-bottom: .6rem; }
  table.grid { width: 100%; border-collapse: collapse; font-size: .88rem; }
  table.grid th { position: sticky; top: 0; text-align: left; background: var(--panel); color: var(--navy); font-weight: 600;
      padding: .45rem .65rem; border-bottom: 1px solid var(--line); white-space: nowrap; }
  table.grid td { padding: .4rem .65rem; border-bottom: 1px solid #E9ECF0; }
  table.grid tr:last-child td { border-bottom: none; }
  table.grid td.empty { color: var(--muted); text-align: center; }
  td.res-ok { color: var(--green); font-weight: 600; }
  td.res-bad { color: var(--red); font-weight: 600; }
  td.res-warn { color: var(--amber); font-weight: 600; }

  /* notices */
  .notice { border: 1px solid var(--line); border-left-width: 4px; border-radius: 2px; padding: .6rem .8rem; margin: .5rem 0; font-size: .9rem; }
  .notice.ok { border-left-color: var(--green); background: var(--green-bg); color: var(--green); }
  .notice.warn { border-left-color: #C58A00; background: var(--amber-bg); color: var(--amber); }
  .notice.error { border-left-color: var(--red); background: var(--red-bg); color: var(--red); }
  .notice.info { border-left-color: var(--blue); background: #EDF2F8; color: var(--navy); }

  /* key / value table */
  table.kv { width: 100%; border-collapse: collapse; font-size: .9rem; margin-bottom: .4rem; }
  table.kv th { text-align: left; width: 220px; color: var(--muted); font-weight: 500; padding: .42rem .6rem; border-bottom: 1px solid #E6E9EE; background: var(--panel); }
  table.kv td { padding: .42rem .6rem; border-bottom: 1px solid #E6E9EE; }

  /* login */
  .login-title { font-size: 1.25rem; font-weight: 700; color: var(--navy); margin-bottom: .1rem; }
  .login-sub { color: var(--muted); font-size: .88rem; margin-bottom: 1rem; }
  .fine-print { color: var(--muted); font-size: .76rem; margin-top: .8rem; line-height: 1.45; }
  .sim-banner { border: 2px solid #C58A00; background: var(--amber-bg); color: var(--amber); padding: .6rem .9rem; font-weight: 600; font-size: .9rem; margin-bottom: 1rem; }
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


def fmt_money(value: float, currency: str = "USD") -> str:
    return f"{currency} {value:,.2f}"


_RESULT_CLASS = {"Completed": "res-ok", "Denied": "res-bad", "Failed": "res-bad",
                 "Denied by backend": "res-bad", "Blocked": "res-warn"}


def table(rows: list[dict], columns: dict[str, str], result_column: str | None = None) -> None:
    """Static HTML table (no client-side export toolbar). `columns` maps field -> header."""
    head = "".join(f"<th>{_esc(h)}</th>" for h in columns.values())
    body = []
    for row in rows:
        cells = []
        for key in columns:
            value = row.get(key, "")
            css = _RESULT_CLASS.get(value, "") if key == result_column else ""
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
