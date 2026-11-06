"""Security Operations Centre dashboard (Streamlit).  Run:  streamlit run frontend/soc_dashboard.py --server.port 8503

Every figure, row, chart and graph is fetched from the backend (/api/soc/*). Live panels poll a cheap change token and
reload data only when something changed. They are Streamlit fragments, so a refresh never resets the page, filters or
the navigation.
"""
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st  # noqa: E402

from frontend import components as ui  # noqa: E402
from frontend import soc_auth_defense as auth_page  # noqa: E402
from frontend import soc_components as sc  # noqa: E402
from frontend.api_client import ApiClient, ApiError, env_seconds  # noqa: E402

st.set_page_config(page_title=f"{ui.ORG_NAME} - Security Operations", layout="wide", initial_sidebar_state="auto")
sc.inject()

PAGES = ["Security Overview", "Live Event Feed", "Attack Investigations", "Employee Risk Monitor", "Attack Timeline",
         "Attack Graph", "Authentication Defence", "Response Centre", "Audit Logs"]
# How often a dashboard session asks the backend for its cheap change token, and how long cached panels are reused.
# Set SOC_REFRESH_SECONDS / SOC_CACHE_SECONDS to tune the load on the backend; values below the minimum are raised to it.
LIVE_SECONDS = env_seconds("SOC_REFRESH_SECONDS", 3, 1)
CACHE_SECONDS = env_seconds("SOC_CACHE_SECONDS", 25, 5)
FEED_PAGE = 150          # rows per page of the live feed; "Show more" adds another page, up to the backend's page limit
FEED_MAX = 450
TIME_RANGES = {"Last 15 minutes": 15, "Last hour": 60, "Last 6 hours": 360, "Last 24 hours": 1440, "Last 7 days": 10080,
               "All time": None}
RISK_BANDS = {"All risk bands": None, "Normal": "normal", "Watch": "suspicious", "Elevated": "high_risk", "Alert": "critical"}
EVENT_TYPES = ["All event types", "login", "login_failed", "logout", "resource_access", "file_download", "data_export",
               "directory_search", "administrative_action", "external_transfer", "permission_change_attempt"]
COMPONENT_LABELS = {"rules": "Rule evidence (hand-assigned weights)", "ml": "Anomaly score (model output)"}
SCORE_TERMS = ("risk_score", "risk_band", "impact_severity", "evidence_strength", "anomaly_score", "rule_weight")
ACTION_LABELS = {"revoke_sessions": "Revoke sessions", "lock_account": "Disable account",
                 "restrict_access": "Restrict sensitive access", "remove_privileges": "Remove privileges",
                 "block_ip": "Block IP in this application", "isolate_system": "Isolate system record"}
EXPOSURE_ROWS = [("sensitive_records_accessed", "Sensitive records accessed"), ("records_exported", "Records exported"),
                 ("records_potentially_exposed", "Records potentially exposed"),
                 ("records_in_external_transfers", "Records in external transfers")]


# ------------------------------------------------------------------ session, API and caching
def api() -> ApiClient:
    return ApiClient(st.session_state.get("token"), "SOC Dashboard (Streamlit)")


def sign_out(message: str | None = None) -> None:
    if st.session_state.get("token"):
        try:
            api().logout()
        except ApiError:
            pass
    st.session_state.clear()
    if message:
        st.session_state["flash"] = message


def handle(exc: ApiError) -> None:
    if exc.status_code == 401:
        sign_out("Your session has expired. Please sign in again.")
        st.rerun()
    ui.notice("error", exc.detail)


def refresh_token() -> None:
    """One tiny request per refresh: the backend's change token."""
    try:
        st.session_state["_token"] = api().get("/api/soc/version")["token"]
    except ApiError as exc:
        handle(exc)


def cached(name: str, path: str, **params):
    """Fetch from the backend only if the change token moved (or the entry is older than CACHE_SECONDS)."""
    key = f"{name}|{sorted(params.items())}"
    store = st.session_state.setdefault("_cache", {})
    entry = store.get(key)
    if entry and entry[0] == st.session_state.get("_token") and time.time() - entry[1] < CACHE_SECONDS:
        return entry[2]
    try:
        data = api().get(path, **params)
    except ApiError as exc:
        handle(exc)
        return entry[2] if entry else None
    store[key] = (st.session_state.get("_token"), time.time(), data)
    return data


def live(render) -> None:
    """Run `render` as a self-refreshing fragment (paused while an action awaits confirmation)."""
    paused = bool(st.session_state.get("pending"))

    @st.fragment(run_every=None if paused else LIVE_SECONDS)
    def _fragment():
        refresh_token()
        render()

    _fragment()


def static(name: str, path: str):
    """Fetch rarely-changing reference data once per browser session (not on every change token)."""
    store = st.session_state.setdefault("_static", {})
    if name not in store:
        try:
            store[name] = api().get(path)
        except ApiError:
            return None
    return store[name]


def pselect(label, options, key, *, fmt=None, container=st):
    """Selectbox whose value survives navigation and refreshes."""
    store = st.session_state.setdefault("store", {})
    value = store.get(key)
    index = options.index(value) if value in options else 0

    def save():
        store[key] = st.session_state[f"w_{key}"]

    return container.selectbox(label, options, index=index, key=f"w_{key}", on_change=save, format_func=fmt or str)


def ptext(label, key, *, placeholder="", container=st):
    store = st.session_state.setdefault("store", {})

    def save():
        store[key] = st.session_state[f"w_{key}"]

    return container.text_input(label, value=store.get(key, ""), key=f"w_{key}", on_change=save, placeholder=placeholder)


def go(page: str, investigation: int | None = None) -> None:
    st.session_state.page = page
    if investigation is not None:
        st.session_state.selected_investigation = investigation
        st.session_state.setdefault("store", {})["scope"] = f"investigation:{investigation}"


def nav(page: str) -> None:
    st.session_state.page = page
    if page == "Attack Investigations":
        st.session_state.pop("selected_investigation", None)


def short(local: str | None) -> str:
    return ui.fmt_time(local) if local else "-"


def fmt_event(e: dict | None) -> str:
    return "-" if not e else f"#{e['event_id']} {e['event_type'].replace('_', ' ')} {short(e['timestamp']['local'])}"


def flash_notice() -> None:
    message = st.session_state.pop("flash_ok", None)
    if message:
        ui.notice("ok", message)


# ------------------------------------------------------------------ sign-in
def login_page() -> None:
    _, centre, _ = st.columns([1, 1.15, 1])
    with centre:
        st.markdown("<div style='height:3rem'></div>", unsafe_allow_html=True)
        ui.login_header("Security Operations - sign in")
        flash = st.session_state.pop("flash", None)
        if flash:
            ui.notice("info", flash)
        with st.form("soc_login"):
            employee_id = st.text_input("Employee ID")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign in", type="primary")
        if submitted:
            try:
                result = ApiClient(None, "SOC Dashboard (Streamlit)").login(employee_id.strip(), password)
            except ApiError as exc:
                ui.notice("error", exc.detail)
            else:
                probe = ApiClient(result["access_token"], "SOC Dashboard (Streamlit)")
                try:
                    probe.get("/api/soc/version")
                except ApiError as exc:
                    try:
                        probe.logout()
                    except ApiError:
                        pass
                    ui.notice("error", "This console is restricted to security administrators." if exc.status_code == 403 else exc.detail)
                else:
                    st.session_state.update(token=result["access_token"], page=PAGES[0],
                                            admin_id=result["employee"]["employee_code"])
                    st.rerun()
        st.markdown('<div class="fine-print">Authorised security personnel only. All actions are recorded in the audit log.</div>',
                    unsafe_allow_html=True)


# ------------------------------------------------------------------ 1. security overview
def render_overview() -> None:
    ov = cached("overview", "/api/soc/overview")
    if ov is None:
        return
    sc.live_note(f"Live - updated {short(ov['generated_at']['local'])} (every {LIVE_SECONDS} s when data changes)")
    k = ov["kpis"]
    threats = ov["threats"]
    if threats:
        top = threats[0]
        ui.hero("Threat posture", f"{len(threats)} active threat{'s' if len(threats) != 1 else ''} under watch",
                f"{top['employee_id']}: risk band {top['level_label']} (heuristic risk score {top['risk_score']:.1f}/100, not a probability), "
                f"impact severity {top['impact_label']}, evidence strength {top['strength_label']}. Currently at the "
                f"{top['stage_label']} stage. {top['exposure_label']}.",
                [f"{k['active_investigations']} active investigation{'s' if k['active_investigations'] != 1 else ''}",
                 f"{k['events_24h']:,} events in 24 h", f"Last event {short(top['last_event_at']['local'])}"],
                tone="alert" if top["level"] == "critical" else "")
    else:
        ui.hero("Threat posture", "No active threats", "No employee is above the Normal risk band. Detection is running on every new event.",
                [f"{k['total_events']:,} events in {ov.get('window_days', 30)} days", f"{k['events_24h']:,} in the last 24 h"])
    window = ov.get("window_days", 30)
    tiles = [
        ("Security events", f"{k['total_events']:,}", f"last {window} days; {k['events_24h']:,} in the last 24 h", "", "activity",
         [b["count"] for b in ov["events_per_hour"]]),
        ("Active investigations", k["active_investigations"], "open or contained", "warn" if k["active_investigations"] else "", "briefcase"),
        ("Active alerts", k["critical_alerts"], "Alert risk band", "alert" if k["critical_alerts"] else "", "alert"),
        ("Elevated or Alert band", k["high_risk_employees"], "employees by risk band", "warn" if k["high_risk_employees"] else "", "users"),
        ("Sensitive records accessed", f"{k['sensitive_records_accessed']:,}", f"last {window} days; {k['sensitive_records_24h']:,} in 24 h", "", "database"),
        ("Confirmed external transfers", k["confirmed_external_transfers"], f"last {window} days",
         "alert" if k["confirmed_external_transfers"] else "", "send"),
    ]
    sc.kpi_grid(tiles)
    score_guide()

    ui.section("Live risk assessment")
    if threats:
        ids = [t["employee_id"] for t in threats]
        chosen = pselect("Monitored employee", ids, "meter_emp",
                         fmt=lambda eid: next(f"{eid} - {t['level_label']} band, risk score {t['risk_score']:.1f}" for t in threats if t["employee_id"] == eid))
        t = next(x for x in threats if x["employee_id"] == chosen)
        left, right = st.columns([3, 2])
        left.markdown(sc.meter(t["risk_score"], t["level"], ov["thresholds"], t["impact_severity"], t["evidence_strength"]), unsafe_allow_html=True)
        with right:
            ui.kv_table([
                ("Employee ID", t["employee_id"]), ("Risk band", t["level_label"] + (" (limited by stage count)" if t.get("band_gated") else "")),
                ("Impact severity", t["impact_label"]), ("Evidence strength", t["strength_label"]),
                ("Current attack stage", t["stage_label"]),
                ("Last event", short(t["last_event_at"]["local"])), ("Data exposure", t["exposure_label"]),
                ("Detection states", "; ".join(s["label"] for s in t.get("states", []) if s["active"]) or "none"),
                ("Investigation", f"#{t['investigation_id']} ({t['investigation_status']})" if t["investigation_id"] else "none"),
            ])
        history = cached(f"history:{t['employee_pk']}", "/api/soc/risk-history", employee_id=t["employee_pk"], minutes=240)
        if history and len(history) >= 2:
            st.plotly_chart(sc.risk_chart(history, ov["thresholds"]), width="stretch", config={"displayModeBar": False})
    else:
        left, right = st.columns([3, 2])
        left.markdown(sc.meter(0, "normal", ov["thresholds"]), unsafe_allow_html=True)
        with right:
            ui.kv_table([("Employee ID", "-"), ("Risk band", "Normal"), ("Impact severity", "None"), ("Current attack stage", "None"), ("Last event", "-")])
        ui.notice("ok", "No employee is above the Normal risk band.")

    ui.section(f"Active threats ({len(threats)})")
    if threats:
        ui.table([{"employee": t["employee_id"], "band": t["level_label"], "score": f"{t['risk_score']:.1f}",
                   "impact": t["impact_label"], "strength": t["strength_label"], "stage": t["stage_label"], "exposure": t["exposure_label"], "last": short(t["last_event_at"]["local"]),
                   "investigation": f"#{t['investigation_id']} {t['investigation_status']}" if t["investigation_id"] else "-"}
                  for t in threats],
                 {"employee": "Employee ID", "band": "Risk band", "score": "Heuristic risk score (0-100)", "impact": "Impact severity",
                  "strength": "Evidence strength", "stage": "Current stage", "exposure": "Data exposure", "last": "Last event",
                  "investigation": "Investigation"}, result_column="band")
        with_inv = [t for t in threats if t["investigation_id"]]
        if with_inv:
            a, b = st.columns([3, 1], vertical_alignment="bottom")
            choice = a.selectbox("Open an investigation", [t["investigation_id"] for t in with_inv], key="ov_open",
                                 format_func=lambda i: next(f"Investigation {i} - {t['employee_id']}" for t in with_inv if t["investigation_id"] == i))
            if b.button("Open", key="ov_open_btn", width="stretch"):
                go("Attack Investigations", choice)
                st.rerun()
    else:
        st.caption("No active threats.")

    a, b = st.columns(2)
    a.plotly_chart(sc.events_per_hour_chart(ov["events_per_hour"]), width="stretch", config={"displayModeBar": False})
    b.plotly_chart(sc.severity_chart(ov["employees_by_risk_band"]), width="stretch", config={"displayModeBar": False})


def page_overview() -> None:
    ui.page_header("Security Overview", "Current threat posture across the organisation")
    live(render_overview)


def show_more_events() -> None:
    st.session_state["feed_limit"] = min(FEED_MAX, st.session_state.get("feed_limit", FEED_PAGE) + FEED_PAGE)


# ------------------------------------------------------------------ 2. live event feed
def page_feed() -> None:
    ui.page_header("Live Event Feed", "Every security event with its anomaly score, rule weight and attack stage")
    refresh_token()
    employees = cached("employees", "/api/soc/employees") or []
    cols = st.columns([1.2, 1.2, 1.4, 1.2, 1.4])
    emp = pselect("Employee", ["All employees"] + [e["employee_id"] for e in employees], "f_emp", container=cols[0])
    ip = ptext("IP address (prefix)", "f_ip", container=cols[1], placeholder="e.g. 185.220")
    etype = pselect("Event type", EVENT_TYPES, "f_type", container=cols[2], fmt=lambda v: v.replace("_", " "))
    sev = pselect("Risk band", list(RISK_BANDS), "f_sev", container=cols[3])
    rng = pselect("Time range", list(TIME_RANGES), "f_range", container=cols[4])

    def render():
        limit = st.session_state.get("feed_limit", FEED_PAGE)
        feed = cached("feed", "/api/soc/events", employee=None if emp.startswith("All") else emp, ip=ip.strip() or None,
                      event_type=None if etype.startswith("All") else etype, risk_band=RISK_BANDS[sev],
                      minutes=TIME_RANGES[rng], limit=limit)
        if feed is None:
            return
        rows = feed["rows"]
        sc.live_note(f"Live - latest event #{feed['latest_id']}; showing {len(rows)} most recent matching events")
        ui.table([{
            "time": short(r["timestamp"]["local"]), "employee": r["employee_id"], "type": r["event_type"].replace("_", " "),
            "ip": r["source_ip"], "resource": r["resource"] or "-", "status": r["outcome"],
            "anomaly": "-" if r["anomaly_score"] is None else f"{r['anomaly_score']:.2f}",
            "risk": r["risk_contribution"], "stage": r["stage_label"], "band": sc.SEVERITY_LABELS[r["risk_band"]],
            "impact": sc.IMPACT_LABELS.get(r.get("impact_severity") or "", "-"),
            "origin": "simulated" if r["synthetic"] else "live"} for r in rows],
            {"time": "Timestamp", "employee": "Employee ID", "type": "Event type", "ip": "Source IP", "resource": "Resource",
             "status": "Status", "anomaly": "Anomaly score (0-1, not a probability)", "risk": "Rule weight points (heuristic)",
             "stage": "Attack stage", "band": "Risk band after this event", "impact": "Impact severity", "origin": "Origin"},
            result_column=["status", "band"])
        if feed.get("has_more") and limit < FEED_MAX:
            st.button(f"Show {FEED_PAGE} more events", key="feed_more", on_click=show_more_events)

    live(render)


# ------------------------------------------------------------------ 3. attack investigations
def page_investigations() -> None:
    selected = st.session_state.get("selected_investigation")
    if selected:
        ui.page_header(f"Investigation {selected}", "Correlated evidence, explanation, containment and evidence export")
        st.button("Back to all investigations", key="inv_back", on_click=nav, args=("Attack Investigations",))
        refresh_token()
        flash_notice()
        if st.session_state.get("pending"):
            centre = cached("response", "/api/soc/response")
            if centre:
                confirmation_panel({o["action"]: o for o in centre["options"]})
        live(lambda: render_investigation(selected))
        return
    ui.page_header("Attack Investigations", "Active and historical investigations")
    refresh_token()
    view = pselect("Show", ["Active", "All", "Resolved"], "inv_view")
    live(lambda: render_investigation_list(view))


def render_investigation_list(view: str) -> None:
    rows = cached("inv_list", "/api/soc/investigations", status={"Active": "active", "Resolved": "resolved"}.get(view))
    if rows is None:
        return
    sc.live_note(f"Live - {len(rows)} investigation(s)")
    ui.table([{"id": r["id"], "employee": r["employee_id"], "score": f"{r['risk_score']:.1f}", "band": r["level_label"],
               "impact": r["impact_label"], "strength": r["strength_label"],
               "stage": r["stage_label"], "type": r["attack_type_label"], "first": fmt_event(r["first_event"]),
               "latest": fmt_event(r["latest_event"]),
               "exposure": f"{r['exposure_label']} ({r['records_exposed']:,} records)" if r["records_exposed"] else r["exposure_label"],
               "status": r["status"].title()} for r in rows],
             {"id": "ID", "employee": "Affected employee", "score": "Heuristic risk score (0-100)", "band": "Risk band",
              "impact": "Impact severity", "strength": "Evidence strength", "stage": "Current stage", "type": "Likely attack type", "first": "First suspicious event", "latest": "Latest event",
              "exposure": "Data exposure", "status": "Status"}, result_column="band")
    if rows:
        a, b = st.columns([3, 1], vertical_alignment="bottom")
        choice = a.selectbox("Select an investigation", [r["id"] for r in rows], key="inv_pick",
                             format_func=lambda i: next(f"Investigation {i} - {r['employee_id']} - {r['level_label']} band ({r['status']})"
                                                        for r in rows if r["id"] == i))
        if b.button("Open investigation", key="inv_open", width="stretch"):
            go("Attack Investigations", choice)
            st.rerun()


def states_panel(d: dict) -> None:
    """The five distinct states, why each is on or off, and how the score was built."""
    ui.section("Detection states")
    ui.table([{"state": s["label"], "now": "Yes" if s["active"] else "No", "basis": s["basis"]} for s in d.get("states", [])],
             {"state": "State", "now": "Active", "basis": "Basis"})
    st.caption("Model outputs (anomalous activity, correlated sequence, potential exposure) are inferences and are never shown as "
               "confirmed. 'Confirmed' is reserved for labelled test data. Containment acts only inside this application.")
    audit = d.get("audit")
    if audit:
        score_explanation(audit)


def _refs(ids: list[int], limit: int = 6) -> str:
    return ", ".join(f"#{i}" for i in ids[:limit]) + (f" +{len(ids) - limit}" if len(ids) > limit else "")


def score_explanation(audit: dict) -> None:
    """Everything behind the score: components and their origin, evidence groups with event references and times, the model
    output, feature deviations, the corroboration gate and the thresholds. Rendered from the backend's breakdown only."""
    bd = audit["breakdown"]
    with st.expander("How the heuristic risk score was built (not a probability)", expanded=False):
        st.markdown(f"`{bd['formula']}`")
        win = bd["window"]
        st.caption(f"Window: {win['minutes']} minutes, {short(win['start'])} to {short(win['end'])} (UTC). "
                   f"Heuristic risk score {audit['risk_score']:.1f}/100.")
        ui.table([{"component": COMPONENT_LABELS.get(c["component"], c["component"]), "origin": c["kind"], "value": f"{c['value']:.2f}",
                   "weight": f"{c['weight']:.2f}", "points": f"{c['contribution']:.1f}"} for c in audit["components"]],
                 {"component": "Component", "origin": "Where the number comes from", "value": "Value (0-1)", "weight": "Weight",
                  "points": "Points"})
        st.caption(bd["counting_rule"])
        st.caption("Not added to the score, because they restate the same rule evidence: " + ", ".join(bd["not_added_to_the_score"][:3]) + ".")

        st.markdown("**Rule evidence (reason codes)**")
        ui.table([{"rule": r["rule"].replace("_", " "), "target": r.get("target") or "-", "weight": f"{r['rule_weight']:.2f}",
                   "counted": f"{r['counted_weight']:.2f}", "events": r["count"], "refs": _refs(r["event_ids"]),
                   "when": f"{short(r['first_seen'])} - {short(r['last_seen'])}", "why": r["description"]}
                  for r in bd["rule_evidence"]],
                 {"rule": "Rule", "target": "Target", "weight": "Rule weight", "counted": "Counted weight", "events": "Events",
                  "refs": "Event references", "when": "First - last (UTC)", "why": "Meaning"})

        m = bd["model"]
        st.markdown("**Anomaly model output**")
        ui.kv_table([("Mode", m["mode"].replace("_", " ")), ("Anomaly score (0-1)", f"{m['score']:.3f}"),
                     ("Raw model score", "-" if m["raw"] is None else f"{m['raw']:.3f}"),
                     ("Volume guard (0-1)", f"{m['volume_guard']:.3f}"), ("Role", m["role"])])

        st.markdown("**Feature deviations behind the anomaly score**")
        ui.table([{"feature": f["label"], "value": "yes" if f["value"] is True else "no" if f["value"] is False else f["value"],
                   "ref": f["reference"], "dev": "Deviates" if f["deviates"] else "Within normal"} for f in bd["feature_deviations"]],
                 {"feature": "Feature", "value": "This window", "ref": "Normal for this employee", "dev": "Comparison"})

        g, t = bd["gate"], bd["thresholds"]
        st.markdown("**Risk band, gate and thresholds**")
        ui.kv_table([("Independent attack stages", f"{g['independent_stages']} ({', '.join(x.replace('_', ' ') for x in g['stages']) or 'none'})"),
                     ("Stages needed", f"Elevated {g['needed_for_elevated']}, Alert {g['needed_for_alert']}"),
                     ("Band from the score alone", sc.SEVERITY_LABELS.get(g["band_from_score_alone"], g["band_from_score_alone"])),
                     ("Risk band", sc.SEVERITY_LABELS.get(g["band"], g["band"]) + (" (lowered by the stage gate)" if g["lowered_by_gate"] else "")),
                     ("Thresholds (risk score)", f"Watch {t['watch']}, Elevated {t['elevated']}, Alert {t['alert']} - {t['source']}")])

        imp, stg = audit["impact"], audit["strength"]
        st.markdown(f"**Impact severity: {imp['label']}** (from the evidence only; independent of the score)")
        st.markdown("\n".join(f"- {r}" for r in imp["reasons"]) or "- none")
        st.markdown(f"**Evidence strength: {stg['label']}** (a qualitative reading, not a probability)")
        st.markdown("\n".join(f"- {r}" for r in stg["reasons"]))

        if audit.get("evidence"):
            st.markdown("**Events considered**")
            ui.table([{"event": f"#{e['event_id']}", "time": short(e["timestamp"]), "rule": e["rule"].replace("_", " "),
                       "weight": f"{e['rule_weight']:.2f}", "counted": "yes" if e["counted"] else "no (not scored)",
                       "stages": ", ".join(x.replace("_", " ") for x in e["stages"]) or "-"} for e in audit["evidence"][:60]],
                     {"event": "Event", "time": "Time (UTC)", "rule": "Strongest rule", "weight": "Rule weight",
                      "counted": "Counted in score", "stages": "Stages supported"})
        if audit.get("at_alert"):
            st.caption(f"When the alert was raised the score was {audit['at_alert']['risk_score']:.1f} over "
                       f"{audit['at_alert']['gate']['independent_stages']} independent stage(s); the alert keeps that basis.")
        st.caption(audit["note"])


def score_guide() -> None:
    """What each number means, taken from the backend so the dashboard cannot drift from the definitions."""
    info = static("detection_status", "/api/detection/status")
    if not info:
        return
    with st.expander("How to read the scores (none of them is a probability)"):
        for key in SCORE_TERMS:
            d = info["score_definitions"][key]
            st.markdown(f"**{d['label']}** ({d['range']}; {d['kind']}). {d['text']}")
        op = info["operating_point"]
        test = (op.get("test") or {}).get("bands", {}).get("Alert")
        st.markdown(f"**Thresholds** - Watch {op['thresholds']['suspicious']}, Elevated {op['thresholds']['high_risk']}, "
                    f"Alert {op['thresholds']['critical']} ({op['source']}).")
        if test:
            st.caption(f"Chosen on synthetic validation runs. On held-out synthetic test runs the Alert band detected {test['tp']} of "
                       f"{test['tp'] + test['fn']} malicious runs (missed {test['fn']}) and flagged {test['fp']} of {test['fp'] + test['tn']} "
                       "benign runs. Synthetic only: this does not describe real employees or incidents.")
        else:
            st.caption(op.get("note", "No operating point recorded."))


def render_investigation(inv_id: int) -> None:
    d = cached(f"inv:{inv_id}", f"/api/soc/investigations/{inv_id}")
    tl = cached(f"tl-inv:{inv_id}", "/api/soc/timeline", investigation_id=inv_id)
    if d is None:
        return
    sc.live_note("Live - updates as new correlated events arrive")
    tiles = [("Heuristic risk score", f"{d['risk_score']:.1f}", f"risk band {d['level_label']}; not a probability", "alert" if d["level"] == "critical" else ""),
             ("Impact severity", d["impact_label"], "from the evidence, not the score", "warn" if d["impact_severity"] in ("high", "critical") else ""),
             ("Evidence strength", d["strength_label"], "qualitative, not a probability", ""),
             ("Current stage", d["stage_label"], "", ""), ("Likely attack type", d["attack_type_label"], "", ""),
             ("Affected employee", d["employee_id"], "", ""),
             ("Status", d["status"].title(), f"alert #{d['alert_id']}" if d["alert_id"] else "no alert", ""),
             ("Data exposure", d["exposure_label"], f"{d['records_exposed']:,} records potentially exposed", "")]
    sc.kpi_grid(tiles)
    ui.notice("info", d["summary"])
    states_panel(d)
    if tl:
        ui.section("Attack stages")
        st.markdown(sc.stage_strip(tl["stages"]), unsafe_allow_html=True)
    findings_panel(d)
    case_file_panel(d)

    a, b = st.columns(2)
    with a:
        ui.section("Data exposure assessment")
        exp = d["exposure"] or {}
        ui.kv_table([("Status", exp.get("status_label", "-"))] + [(label, f"{exp.get(key, 0):,}") for key, label in EXPOSURE_ROWS]
                    + [("External transfer confirmed", "Yes" if exp.get("external_transfer_confirmed") else "No"),
                       ("Exfiltration established", "Yes" if exp.get("exfiltration_established") else "No")])
        st.caption(exp.get("statement", ""))
    with b:
        ui.section("Current live assessment")
        live_data = d["live"]
        if live_data:
            ui.kv_table([("Heuristic risk score", f"{live_data['risk_score']:.1f} / 100 (not a probability)"),
                         ("Risk band", sc.SEVERITY_LABELS[live_data["level"]] + (" (limited by stage count)" if live_data["band_gated"] else "")),
                         ("Impact severity", live_data["impact_label"]), ("Evidence strength", live_data["strength_label"]),
                         ("Independent stages", live_data["independent_stages"]),
                         ("Anomaly model", live_data["ml"]["mode"].replace("_", " ") if live_data["ml"] else "n/a")])
            st.caption("The full calculation is under 'How the heuristic risk score was built' above.")

    ui.section("Correlated evidence")
    alert = d["alert"]
    if alert:
        st.caption(f"Alert #{alert['id']} - first suspicious event #{alert['first_event_id']}, triggering event #{alert['trigger_event_id']}, "
                   f"detected {short(alert['detected_at']['local'])}")
        ui.table([{"time": short(ev["timestamp"]["local"]), "event": f"#{ev['event_id']}", "account": ev["account"],
                   "type": ev["event_type"].replace("_", " "), "resource": ev["resource"] or "-", "rule": ev["rule"].replace("_", " "),
                   "stages": ", ".join(s.replace("_", " ") for s in ev["stages"]) or "-", "links": ", ".join(ev["relations"]) or "-"}
                  for ev in alert["evidence"]],
                 {"time": "Time", "event": "Event", "account": "Account", "type": "Event type", "resource": "Resource",
                  "rule": "Strongest rule", "stages": "Stages supported", "links": "Linked by"})
    else:
        st.caption("No alert has been raised for this investigation; showing the investigation timeline instead.")
        ui.table([{"time": short(t["timestamp"]["local"]), "event": f"#{t['event_id']}", "type": t["event_type"].replace("_", " "),
                   "resource": t["resource"] or "-", "outcome": t["outcome"], "ip": t["source_ip"]} for t in d["timeline"]],
                 {"time": "Time", "event": "Event", "type": "Event type", "resource": "Resource", "outcome": "Outcome", "ip": "Source IP"})

    ui.section("Indicators")
    st.markdown("\n".join(f"- {i}" for i in d["indicators"]) or "None")
    containment_panel(d)
    ui.section("Containment history")
    ui.table([{"time": short(c["at"]["local"]), "action": ACTION_LABELS.get(c["action"], c["action"].replace("_", " ")),
               "target": c["target"], "by": c["by"], "reason": c["reason"], "result": c.get("result") or "-",
               "alert": f"#{c['alert_id']}" if c.get("alert_id") else "-"} for c in d["containment_actions"]],
             {"time": "Time", "action": "Requested action", "target": "Target", "by": "Initiated by", "reason": "Reason",
              "alert": "Alert", "result": "Result"})
    export_panel(d)
    resolution_panel(d)
    flash_notice()


def refs(items: list[dict], limit: int = 4) -> str:
    text = ", ".join(f"#{r['event_id']} ({r['local']})" for r in items[:limit])
    return text + (f" and {len(items) - limit} more" if len(items) > limit else "") if items else "-"


def findings_panel(d: dict) -> None:
    """The deterministic, evidence-based explanation: everything below cites stored event IDs and times."""
    ex = d.get("explanation")
    ui.section("Investigation findings")
    if not ex:
        st.caption("No explanation has been generated for this investigation yet.")
        return
    st.caption(f"Generated from {ex['evidence_event_count']} preserved events by a deterministic rule engine "
               "(no external AI service). Every statement cites stored event IDs and times.")
    ui.notice("info", f"Likely attack type: {ex['attack_type']['text']}")
    ui.notice("warn", ex["attribution"])
    if ex.get("simulation_notice"):
        st.caption(ex["simulation_notice"])

    a, b = st.columns(2)
    with a:
        ui.section("Attack classification")
        ui.table([{"type": c["label"], "assessment": "Supported" if c["supported"] else "Not supported",
                   "basis": refs(c["events"]) if c["supported"] else "-", "reason": c["reason"]} for c in ex["classifications"]],
                 {"type": "Category", "assessment": "Assessment", "basis": "Supporting events", "reason": "Reasoning"})
    with b:
        ui.section("Current stage")
        st.markdown(f"**{ex['current_stage']['label']}**")
        ui.table([{"stage": s["label"], "first": short(s["first_seen"]), "events": ", ".join(f"#{i}" for i in s["event_ids"][:6])}
                  for s in ex["current_stage"]["observed"]],
                 {"stage": "Observed stage", "first": "First seen (UTC)", "events": "Events"})
        st.caption((ex.get("risk_assessment") or ex.get("confidence") or {}).get("statement", ""))   # legacy: older explanations

    ui.section("Suspicious activities")
    ui.table([{"activity": s["description"], "count": s["count"], "events": refs(s["events"], 3),
               "where": ", ".join([*s["resources"], *s["source_ips"]]) or "-"} for s in ex["suspicious_activities"]],
             {"activity": "Activity", "count": "Count", "events": "Events", "where": "Resources / addresses"})
    ui.section("Supporting evidence")
    ui.table([{"time": e["local"], "event": f"#{e['event_id']}", "statement": e["statement"],
               "rules": ", ".join(r.replace("_", " ") for r in e["rules"])} for e in ex["supporting_evidence"]],
             {"time": "Time", "event": "Event", "statement": "What the event shows", "rules": "Rules triggered"})

    c, e = st.columns(2)
    with c:
        ui.section("Potential impact")
        st.markdown("\n".join(f"- {i}" for i in ex["potential_impact"]))
        ui.section("Missing evidence")
        st.markdown("\n".join(f"- {i}" for i in ex["missing_evidence"]))
    with e:
        ui.section("Possible alternative explanations")
        st.markdown("\n".join(f"- {i}" for i in ex["alternative_explanations"]))


def case_file_panel(d: dict) -> None:
    case, integrity = d.get("case_file"), d.get("integrity")
    ui.section("Case file and preserved evidence")
    if not case:
        st.caption("No evidence has been collected for this investigation yet.")
        return
    data = case["data"]
    sc.kpi_grid([("Related events", len(case["event_ids"]), f"first #{d['first_event_id']}, latest #{d['latest_event_id']}", ""),
                 ("Sessions", len(case["sessions"]), "", ""), ("Suspicious IPs", len(case["suspicious_ips"]), "", ""),
                 ("Records exported", f"{data['records_exported']:,}", "", ""),
                 ("Potentially exposed", f"{data['records_potentially_exposed']:,}", "", ""),
                 ("Confirmed external transfers", data["confirmed_external_transfers"], f"{data['records_confirmed_external']:,} records", "")])
    if integrity:
        ui.notice("ok" if integrity["intact"] else "error",
                  f"Evidence integrity: {integrity['verified']} of {integrity['checked']} preserved events match their SHA-256 "
                  "snapshot." + ("" if integrity["intact"] else f" Modified: {integrity['modified']}, missing: {integrity['missing']}."))
    a, b = st.columns(2)
    with a:
        ui.table([{"session": f"#{s['session_id']}", "account": s["account"], "ip": s["source_ip"], "events": s["event_count"],
                   "state": "Revoked" if s["revoked_at"] else "Active / ended"} for s in case["sessions"]],
                 {"session": "Session", "account": "Account", "ip": "Source IP", "events": "Events", "state": "State"})
        ui.table([{"ip": i["ip"], "events": i["event_count"], "first": short(i["first_seen"]),         "state": "Blocked" if i["blocked"] else "Not blocked"}
                          for i in case["suspicious_ips"]], {"ip": "Suspicious IP", "events": "Events", "first": "First seen (UTC)", "state": "Control in this application"})
    with b:
        ui.table([{"resource": r["name"], "level": {2: "Confidential", 3: "Restricted"}[r["sensitivity"]], "read": f"{r['records_accessed']:,}",
                   "exported": f"{r['records_downloaded']:,}", "denied": r["denied_attempts"]} for r in case["sensitive_resources"]],
                 {"resource": "Sensitive resource", "level": "Classification", "read": "Records accessed", "exported": "Records exported",
                  "denied": "Denied attempts"})
        ui.table([{"account": a_["employee_id"], "username": a_["username"], "role": a_["job_role"], "status": a_["status"].title()}
                  for a_ in case["related_accounts"]],
                 {"account": "Related privileged account", "username": "Username", "role": "Role", "status": "Status"})


def _locked(case: dict, target: str | None) -> bool:
    if target:
        return any(a["username"] == target and a["status"] == "locked" for a in case.get("related_accounts", []))
    return case.get("employee", {}).get("status") == "locked"


def containment_panel(d: dict) -> None:
    ui.section("Containment")
    st.caption("Every action needs administrator confirmation and a reason, and is audited. It changes this "
               "application's own records (account status, sessions, permissions, block list, isolation flags), which it then enforces, and does not "
               "contact or change any firewall, directory service, endpoint, email service or real network.")
    case, resolved = d.get("case_file") or {}, d["status"] == "resolved"
    blocked = {i["ip"] for i in case.get("suspicious_ips", []) if i["blocked"]}
    rows = [a for a in d["recommended_actions"] if a.get("executable", True)]
    head = st.columns([1.2, 2.6, 2.0, 3.6, 1.4, 1.8])
    for col, title in zip(head, ["Priority", "Action", "Target", "Reason", "Status", ""]):
        col.markdown(f"<span style='color:#5F6B7A;font-size:.78rem'>{title}</span>", unsafe_allow_html=True)
    for i, a in enumerate(rows):
        done = (a["action"] == "block_ip" and a.get("target") in blocked) or (a["action"] == "lock_account" and _locked(case, a.get("target")))
        row = st.columns([1.2, 2.6, 2.0, 3.6, 1.4, 1.8], vertical_alignment="center")
        row[0].write(a["priority"])
        row[1].write(ACTION_LABELS.get(a["action"], a["action"].replace("_", " ").capitalize()))
        row[2].write(a.get("target") or "employee account")
        row[3].caption(a["reason"])
        row[4].markdown(f"<span style='color:{'#1E6B34' if done else '#7A5200'};font-weight:600'>{'Applied' if done else 'Not applied'}</span>",
                        unsafe_allow_html=True)
        if not done and not resolved and row[5].button("Run containment", key=f"ic_{d['id']}_{i}_{a['action']}", width="stretch"):
            request_action(action=a["action"], employee_pk=a.get("target_employee_id") or d["employee_pk"],
                           subject=a.get("target") or d["employee_id"], reason=a["reason"], investigation_id=d["id"],
                           target=a.get("target") if a["action"] in ("block_ip", "isolate_system") else None)
    resources = case.get("sensitive_resources", [])
    if resources and not resolved:
        names = {r["resource"]: r["name"] for r in resources}
        c1, c2 = st.columns([3, 1], vertical_alignment="bottom")
        pick = c1.selectbox("Restrict this employee's access to a sensitive resource", list(names), format_func=lambda r: names[r],
                            key=f"restrict_pick_{d['id']}")
        if c2.button("Restrict access", key=f"restrict_go_{d['id']}", width="stretch"):
            request_action(action="restrict_access", employee_pk=d["employee_pk"], subject=f"{d['employee_id']} / {names[pick]}",
                           reason=f"Restrict access to {names[pick]} during the investigation", investigation_id=d["id"], target=pick)


def export_panel(d: dict) -> None:
    ui.section("Evidence export")
    st.caption("The report contains only this investigation's evidence: summary, attack timeline, correlated events with hashes, "
               "risk score history, data exposure, containment actions and findings. Each export is audited.")
    cols = st.columns([1.3, 1.3, 4])
    for col, fmt in zip(cols, ("json", "csv")):
        if col.button(f"Prepare {fmt.upper()} report", key=f"exp_{fmt}_{d['id']}", width="stretch"):
            try:
                data, name, mime = api().download(f"/api/investigations/{d['id']}/export", format=fmt)
            except ApiError as exc:
                handle(exc)
            else:
                st.session_state["export"] = {"id": d["id"], "data": data, "name": name, "mime": mime}
    ready = st.session_state.get("export")
    if ready and ready["id"] == d["id"]:
        st.download_button(f"Download {ready['name']}", ready["data"], file_name=ready["name"], mime=ready["mime"], key=f"dl_{d['id']}")


def resolution_panel(d: dict) -> None:
    ui.section("Investigation status")
    inv_id = d["id"]
    if d["status"] == "resolved":
        st.caption(f"Resolved {short(d['resolved_at']['local']) if d.get('resolved_at') else ''}. Preserved evidence is retained.")
        confirm = st.checkbox("I confirm this investigation should be reopened", key=f"inv_confirm_{inv_id}")
        if st.button("Reopen investigation", key=f"inv_status_{inv_id}", disabled=not confirm):
            try:
                api().patch(f"/api/investigations/{inv_id}", {"status": "open"})
                st.session_state["_cache"] = {}
                st.session_state["flash_ok"] = f"Investigation {inv_id} reopened."
            except ApiError as exc:
                handle(exc)
            else:
                st.rerun(scope="fragment")
        return
    note = st.text_input("Resolution note (recorded in the audit log)", key=f"resolve_note_{inv_id}")
    if st.button("Review resolution", key=f"resolve_go_{inv_id}", disabled=len(note.strip()) < 3):
        request_action(action="resolve_investigation", employee_pk=d["employee_pk"], subject=f"Investigation {inv_id} ({d['employee_id']})",
                       reason=note.strip(), investigation_id=inv_id)


# ------------------------------------------------------------------ 4. employee risk monitor
def page_risk() -> None:
    ui.page_header("Employee Risk Monitor", "Employees ranked by current risk, from behavioural and rule evidence only")

    def render():
        rows = cached("employees", "/api/soc/employees")
        if rows is None:
            return
        sc.live_note(f"Live - {len(rows)} accounts ranked by heuristic risk score")
        ui.table([{"rank": i + 1, "employee": r["employee_id"], "dept": r["department"], "role": r["job_role"],
                   "score": r["risk_score"], "severity": r["level_label"], "impact": r["impact_label"], "strength": r["strength_label"],
                   "anomaly": f"{r['anomaly_score']:.2f}",
                   "events": r["suspicious_events_24h"], "last": short(r["last_suspicious"]["local"]), "stage": r["stage_label"],
                   "inv": (f"#{r['investigation_id']} {r['investigation_status']}" if r["investigation_id"] else "none"),
                   "type": r["account_type"]} for i, r in enumerate(rows)],
                 {"rank": "Rank", "employee": "Employee ID", "dept": "Department", "role": "Job role", "score": "Heuristic risk score (0-100)",
                  "severity": "Risk band", "impact": "Impact severity", "strength": "Evidence strength",
                  "anomaly": "Anomaly score (0-1)", "events": "Suspicious events (24 h)",
                  "last": "Last suspicious activity", "stage": "Current stage", "inv": "Investigation", "type": "Account type"},
                 result_column="severity")
        st.caption("The risk score is a hand-weighted heuristic from rule evidence and an anomaly model, not a probability; impact severity "
                   "and evidence strength are judged separately. See 'How to read the scores' on the Overview. "
                   "No names or personal characteristics are used. All data here, and every benchmark used to evaluate the "
                   "model (project-generated sessions, the CERT Insider Threat Test Dataset), is synthetic; none of it is real banking data.")

    live(render)


# ------------------------------------------------------------------ 5 + 6. timeline and graph
def scope_picker():
    refresh_token()
    scopes = cached("scopes", "/api/soc/scopes") or []
    if not scopes:
        ui.notice("info", "No investigations or active threats yet. They appear when detection raises an Alert-band alert.")
        return None
    keys = [f"{s['kind']}:{s['id']}" for s in scopes]
    labels = dict(zip(keys, (s["label"] for s in scopes)))
    chosen = pselect("Attack", keys, "scope", fmt=lambda k: labels[k])
    scope = scopes[keys.index(chosen)]
    return {"investigation_id": scope["id"]} if scope["kind"] == "investigation" else {"employee_id": scope["id"]}


def page_timeline() -> None:
    ui.page_header("Attack Timeline", "Chronological view of the correlated events behind an attack")
    scope = scope_picker()
    if not scope:
        return

    def render():
        tl = cached("timeline", "/api/soc/timeline", **scope)
        if tl is None:
            return
        sc.live_note(f"Live - {tl['source']} for {tl['employee_id']}; current stage: {tl['current_stage_label']}; "
                     f"heuristic risk score {tl['risk_score']:.1f} (not a probability)")
        st.markdown(sc.stage_strip(tl["stages"]), unsafe_allow_html=True)
        if tl["events"]:
            st.plotly_chart(sc.stage_lane_chart(tl["stages"], tl["events"]), width="stretch", config={"displayModeBar": False})
        ui.section("Chronology")
        ui.table([{"time": short(e["timestamp"]["local"]), "event": f"#{e['event_id']}", "account": e.get("account", "-"),
                   "type": e["event_type"].replace("_", " "), "resource": e["resource"] or "-", "ip": e["source_ip"],
                   "outcome": e["outcome"],
                   "stages": ", ".join(ui_stage(s) for s in e.get("stages", [])) or "-",
                   "rules": ", ".join(r.replace("_", " ") for r in e.get("rules", [])) or "-"} for e in tl["events"]],
                 {"time": "Time", "event": "Event", "account": "Account", "type": "Event type", "resource": "Resource",
                  "ip": "Source IP", "outcome": "Status", "stages": "Attack stage(s)", "rules": "Rules triggered"},
                 result_column="outcome")

    live(render)


def ui_stage(stage: str) -> str:
    return stage.replace("_", " ").title()


def page_graph() -> None:
    ui.page_header("Attack Graph", "Relationships between accounts, IP addresses, sessions, systems and external destinations")
    scope = scope_picker()
    if not scope:
        return
    params = dict(scope)
    if "employee_id" in scope:
        minutes = pselect("Window", [30, 60, 120, 240, 720], "g_window", fmt=lambda m: f"Last {m} minutes")
        params["minutes"] = minutes

    def render():
        graph = cached("graph", "/api/soc/graph", **params)
        if graph is None:
            return
        sc.live_note(f"Live - built from {graph['event_count']} stored events for {graph['subject']}; "
                     f"{len(graph['nodes'])} nodes, {len(graph['edges'])} relationships")
        if graph["nodes"]:
            st.plotly_chart(sc.attack_graph(graph), width="stretch", config={"displayModeBar": False})
        names = {n["id"]: n["label"] for n in graph["nodes"]}
        ui.section("Relationships")
        ui.table([{"from": names[e["source"]], "to": names[e["target"]], "type": e["kind"].replace("_", " "),
                   "detail": e["label"] or "-", "flag": "flagged" if e["suspicious"] else ""} for e in graph["edges"]],
                 {"from": "From", "to": "To", "type": "Relationship", "detail": "Detail", "flag": "Detection"})

    live(render)


# ------------------------------------------------------------------ 7. response centre
def request_action(**spec) -> None:
    # One idempotency key per confirmation, so a double click or rerun of "Run action" cannot repeat the action.
    st.session_state["pending"] = {**spec, "key": uuid.uuid4().hex}
    st.rerun()


def confirmation_panel(options: dict) -> None:
    p = st.session_state["pending"]
    info = options[p["action"]]
    ui.section("Confirm containment")
    ui.notice("warn", "Live updates are paused while this action awaits confirmation." if info["needs_confirmation"]
              else "Review the action before running it.")
    ui.kv_table([("Requested action", info["label"]), ("Applies to", p["subject"]),
                 ("Investigation", f"#{p['investigation_id']}" if p.get("investigation_id") else "-"),
                 ("What changes", info["description"]),
                 ("Scope", "This application's own records and enforcement. No external system is contacted."),
                 ("Disruptive", "Yes - confirmation required" if info["needs_confirmation"] else "No")])
    reason = st.text_input("Reason (recorded in the audit log)", value=p["reason"], key="pending_reason")
    confirmed = st.checkbox("I confirm that I want to run this action", key="pending_confirm") if info["needs_confirmation"] else True
    a, b, _ = st.columns([1, 1, 4])
    if a.button("Run action", type="primary", disabled=not confirmed or len(reason.strip()) < 3, key="pending_go"):
        body = {"employee_id": p["employee_pk"], "action_type": p["action"], "reason": reason.strip(), "confirm": bool(confirmed),
                "investigation_id": p.get("investigation_id"), "target": p.get("target"), "idempotency_key": p["key"]}
        try:
            done = api().post("/api/containment", {k: v for k, v in body.items() if v is not None})
        except ApiError as exc:
            if exc.status_code == 401:
                handle(exc)
            ui.notice("error", f"Action not run: {exc.detail} (the attempt has been recorded in the audit log)")
        else:
            st.session_state["flash_ok"] = (done.get("result") or f"Containment completed: {info['label']} for {p['subject']}.") \
                + (" (already recorded; not repeated)" if done.get("replayed") else "")
            st.session_state.pop("pending")
            st.session_state["_cache"] = {}
            st.rerun()
    if b.button("Cancel", key="pending_cancel"):
        st.session_state.pop("pending")
        st.rerun()


def page_response() -> None:
    ui.page_header("Response Centre", "Recommended containment actions, active controls and history")
    refresh_token()
    centre = cached("response", "/api/soc/response")
    if centre is None:
        return
    options = {o["action"]: o for o in centre["options"]}
    ui.notice("info", centre.get("scope_notice", "Containment acts inside this application."))
    flash_notice()
    if st.session_state.get("pending"):
        confirmation_panel(options)

    def render():
        data = cached("response", "/api/soc/response")
        if data is None:
            return
        sc.live_note("Live - recommendations update as the attack progresses")
        ui.section(f"Recommended actions ({len(data['threats'])} active threat{'s' if len(data['threats']) != 1 else ''})")
        if not data["threats"]:
            ui.notice("ok", "No active threats require a response.")
        for t in data["threats"]:
            st.markdown(f"**{t['employee_id']}** &nbsp; {sc.severity_badge(t['level'])} {sc.impact_badge(t['impact_severity'])} "
                        f"&nbsp; heuristic risk score {t['risk_score']:.1f} "
                        f"&nbsp; stage: {t['stage_label']} &nbsp; exposure: {t['exposure_label']}", unsafe_allow_html=True)
            head = st.columns([1.3, 2.6, 2.0, 3.6, 1.4, 1.8])
            for col, title in zip(head, ["Priority", "Action", "Target", "Reason", "Status", ""]):
                col.markdown(f"<span style='color:#5F6B7A;font-size:.78rem'>{title}</span>", unsafe_allow_html=True)
            for i, a in enumerate(t["actions"]):
                row = st.columns([1.3, 2.6, 2.0, 3.6, 1.4, 1.8], vertical_alignment="center")
                label = options.get(a["action"], {}).get("label", a["action"].replace("_", " ").title())
                row[0].write(a["priority"])
                row[1].write(label)
                row[2].write(a.get("target") or "employee account")
                row[3].caption(a["reason"])
                row[4].markdown(f"<span style='color:{'#1E6B34' if a['done'] else '#7A5200'};font-weight:600'>"
                                f"{'Applied' if a['done'] else ('Advisory' if not a['executable'] else 'Not applied')}</span>",
                                unsafe_allow_html=True)
                if a["executable"] and not a["done"]:
                    if row[5].button("Run containment", key=f"act_{t['employee_pk']}_{i}_{a['action']}", width="stretch"):
                        request_action(action=a["action"], employee_pk=a.get("target_employee_id") or t["employee_pk"],
                                       subject=f"{a.get('target') or t['employee_id']}", reason=a["reason"],
                                       investigation_id=t["investigation_id"],
                                       target=a.get("target") if a["action"] in ("block_ip", "isolate_system") else None)
            st.divider()

        ui.section(f"Active controls ({len(data['controls'])})")
        if data["controls"]:
            ui.table([{"kind": "Blocked IP" if c["kind"] == "blocked_ip" else "Isolated system", "target": c["label"],
                       "by": c["by"], "since": short(c["created_at"]["local"]), "reason": c["reason"]} for c in data["controls"]],
                     {"kind": "Control", "target": "Target", "by": "Applied by", "since": "Since", "reason": "Reason"})
            for c in data["controls"]:
                release = "unblock_ip" if c["kind"] == "blocked_ip" else "release_system"
                if st.button(f"Release {c['label']}", key=f"rel_{c['id']}"):
                    request_action(action=release, employee_pk=c["employee_pk"], subject=c["label"], reason="Control released",
                                   target=c["value"])
        else:
            st.caption("No IP blocks or system isolations are active.")

        ui.section("Response history")
        ui.table([{"time": short(h["at"]["local"]), "action": h["label"], "employee": h["employee_id"], "by": h["by"],
                   "reason": h["reason"], "inv": f"#{h['investigation_id']}" if h["investigation_id"] else "-",
                   "alert": f"#{h['alert_id']}" if h.get("alert_id") else "-", "result": h.get("result") or "-"}
                  for h in data["history"]],
                 {"time": "Time", "action": "Requested action", "employee": "Employee ID", "by": "Initiated by", "reason": "Reason",
                  "inv": "Investigation", "alert": "Alert", "result": "Result"})

    live(render)

    ui.section("Manual response")
    c1, c2 = st.columns(2)
    manual = [a for a in options if options[a]["needs"] != "investigation"]       # resolving happens on the investigation page
    action = pselect("Action", manual, "m_action", container=c1, fmt=lambda a: options[a]["label"])
    emp_map = {e["employee_id"]: e["id"] for e in centre["employees"]}
    emp = pselect("Employee / account concerned", list(emp_map), "m_emp", container=c2)
    needs = options[action]["needs"]
    target = None
    if needs == "ip":
        target = ptext("IP address", "m_ip", placeholder="e.g. 185.220.101.45")
    elif needs == "system":
        systems = {s["id"]: s["label"] for s in centre["systems"]}
        target = pselect("System", list(systems), "m_system", fmt=lambda s: systems[s])
    elif action == "restrict_access":
        resources = {"": "All confidential and restricted resources", **{s["id"]: s["label"] for s in centre["systems"]}}
        target = pselect("Resource", list(resources), "m_resource", fmt=lambda s: resources[s]) or None
    st.caption(options[action]["description"])
    reason = ptext("Reason", "m_reason", placeholder="Why this action is needed")
    if st.button("Run containment", key="m_review", disabled=len(reason.strip()) < 3 or (needs == "ip" and not (target or "").strip())):
        request_action(action=action, employee_pk=emp_map[emp], subject=target or emp, reason=reason.strip(), target=target)


# ------------------------------------------------------------------ 8. audit logs
def page_audit() -> None:
    ui.page_header("Audit Logs", "Alerts, investigation updates, containment actions, administrator actions and failed responses")
    refresh_token()
    categories = (cached("audit_cat", "/api/soc/audit", limit=1) or {}).get("categories", {})
    names = {"": "All categories", **categories}
    chosen = pselect("Category", list(names), "a_cat", fmt=lambda c: names[c])

    def render():
        data = cached("audit", "/api/soc/audit", category=chosen or None, limit=200)
        if data is None:
            return
        sc.live_note(f"Live - {len(data['rows'])} most recent entries")
        ui.table([{"time": short(r["timestamp"]["local"]), "cat": r["category_label"], "action": r["action"].replace("_", " "),
                   "actor": r["actor"], "target": r["target"], "summary": r["summary"], "ip": r["ip"]} for r in data["rows"]],
                 {"time": "Timestamp", "cat": "Category", "action": "Action", "actor": "Administrator ID", "target": "Target",
                  "summary": "Details", "ip": "Source IP"})

    live(render)


# ------------------------------------------------------------------ authentication defence
def page_auth_defense() -> None:
    auth_page.page(api=api, api_with_key=lambda key: ApiClient(st.session_state.get("token"), "SOC Dashboard (Streamlit)", key),
                   cached=cached, live=live, refresh_token=refresh_token, handle=handle, short=short, pselect=pselect)


# ------------------------------------------------------------------ shell
PAGE_FUNCTIONS = {
    "Security Overview": page_overview, "Live Event Feed": page_feed, "Attack Investigations": page_investigations,
    "Employee Risk Monitor": page_risk, "Attack Timeline": page_timeline, "Attack Graph": page_graph,
    "Authentication Defence": page_auth_defense, "Response Centre": page_response, "Audit Logs": page_audit,
}


NAV_GROUPS = [("Overview", ["Security Overview", "Live Event Feed"]),
              ("Investigate", ["Attack Investigations", "Employee Risk Monitor", "Attack Timeline", "Attack Graph"]),
              ("Respond", ["Authentication Defence", "Response Centre", "Audit Logs"])]
NAV_ICONS = {"Security Overview": "dashboard", "Live Event Feed": "monitoring", "Attack Investigations": "manage_search",
             "Employee Risk Monitor": "group", "Attack Timeline": "timeline", "Attack Graph": "hub",
             "Authentication Defence": "lock_person", "Response Centre": "shield", "Audit Logs": "receipt_long"}


def dashboard() -> None:
    page = st.session_state.get("page", PAGES[0])
    with st.sidebar:
        ui.brand("Security Operations")
        for group, names in NAV_GROUPS:
            ui.nav_caption(group)
            for name in names:
                st.button(name, key=f"nav_{name}", width="stretch", on_click=nav, args=(name,), icon=f":material/{NAV_ICONS[name]}:",
                          type="primary" if name == page else "secondary")
        ui.nav_caption("Account")
        st.button("Logout", key="nav_logout", width="stretch", on_click=sign_out, icon=":material/logout:")
        ui.user_card(st.session_state.get("admin_id", ""), "Security administrator")
        st.markdown(f'<div class="org-sub" style="margin:.8rem 0 0 .2rem">Live refresh: {LIVE_SECONDS} s</div>', unsafe_allow_html=True)
    PAGE_FUNCTIONS[page]()


if st.session_state.get("token"):
    dashboard()
else:
    login_page()
