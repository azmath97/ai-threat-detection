"""Shared presentation helpers: page furniture, notices, tables, feeds and layout blocks."""
from datetime import datetime

import streamlit as st

from frontend.theme import BASE_CSS

ORG_NAME = "Westbridge Bank"

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
    st.markdown(BASE_CSS, unsafe_allow_html=True)


def page_header(title: str, subtitle: str = "") -> None:
    st.markdown(f"<h1>{title}</h1>", unsafe_allow_html=True)
    if subtitle:
        st.markdown(f'<div class="page-sub">{subtitle}</div>', unsafe_allow_html=True)


def notice(kind: str, text: str) -> None:
    """kind: ok | warn | error | info"""
    st.markdown(f'<div class="notice {kind}">{_esc(text)}</div>', unsafe_allow_html=True)


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


def user_card(name: str, sub: str = "") -> None:
    """Signed-in user with an initials avatar, shown at the foot of the sidebar."""
    initials = "".join(part[0] for part in name.replace(".", " ").split()[:2]).upper() or "?"
    st.markdown(f'<div class="user-card"><div class="avatar">{_esc(initials)}</div><div><div class="u-name">{_esc(name)}</div>'
                f'<div class="u-sub">{_esc(sub)}</div></div></div>', unsafe_allow_html=True)


def hero(eyebrow: str, title: str, text: str = "", chips: list[str] | None = None, tone: str = "") -> None:
    """Dark summary banner. Only ever shows text handed in by the caller."""
    chip_html = "".join(f'<span class="h-chip">{_esc(c)}</span>' for c in (chips or []))
    st.markdown(f'<div class="hero {tone}"><div class="h-eyebrow">{_esc(eyebrow)}</div><div class="h-title">{_esc(title)}</div>'
                f'<div class="h-text">{_esc(text)}</div><div class="h-chips">{chip_html}</div></div>', unsafe_allow_html=True)


def kv_table(rows: list[tuple[str, str]]) -> None:
    body = "".join(f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>" for k, v in rows)
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


_PILL = {"Completed": "pill-ok", "Done": "pill-ok", "Denied": "pill-bad", "Failed": "pill-bad", "Denied by backend": "pill-bad",
         "Critical": "pill-bad", "denied": "pill-bad", "failure": "pill-bad", "High Risk": "pill-high", "Suspicious": "pill-warn",
         "Blocked": "pill-warn", "contained": "pill-warn", "Pending": "pill-warn", "Normal": "pill-ok"}


def table(rows: list[dict], columns: dict[str, str], result_column: str | list[str] | None = None) -> None:
    """Static HTML table (no client-side export toolbar). `columns` maps field -> header.
    `result_column` names the column(s) whose values are shown as status pills (result / severity)."""
    coded = {result_column} if isinstance(result_column, str) else set(result_column or [])
    head = "".join(f"<th>{_esc(h)}</th>" for h in columns.values())
    body = []
    for row in rows:
        cells = []
        for key in columns:
            value = row.get(key, "")
            if key in coded and value in _PILL:
                cells.append(f'<td><span class="pill {_PILL[value]}"><i></i>{_esc(value)}</span></td>')
            else:
                cells.append(f"<td>{_esc(value)}</td>")
        body.append(f"<tr>{''.join(cells)}</tr>")
    if not body:
        body.append(f'<tr><td colspan="{len(columns)}" class="empty">No records</td></tr>')
    st.markdown(f'<div class="grid-wrap"><table class="grid"><thead><tr>{head}</tr></thead>'
                f'<tbody>{"".join(body)}</tbody></table></div>', unsafe_allow_html=True)


def feed(items: list[dict]) -> None:
    """Vertical activity feed. Each item: title, sub (optional), time, tone ('' | 'warn' | 'bad')."""
    rows = "".join(
        f'<div class="f-row {i.get("tone", "")}"><div><div class="f-title">{_esc(i["title"])}</div>'
        f'<div class="f-sub">{_esc(i.get("sub", ""))}</div></div><div class="f-time">{_esc(i["time"])}</div></div>' for i in items)
    st.markdown(f'<div class="feed">{rows}</div>', unsafe_allow_html=True)
