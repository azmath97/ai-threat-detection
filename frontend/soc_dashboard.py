"""Security Operations Centre dashboard (Streamlit).  Run:  streamlit run frontend/soc_dashboard.py --server.port 8503

Every figure, row, chart and graph is fetched from the backend (/api/soc/*). Live panels poll a cheap change token and
reload data only when something changed. They are Streamlit fragments, so a refresh never resets the page, filters or
the navigation.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st  # noqa: E402

from frontend import components as ui  # noqa: E402
from frontend import soc_components as sc  # noqa: E402
from frontend.api_client import ApiClient, ApiError  # noqa: E402

st.set_page_config(page_title="Meridian Trust Bank - Security Operations Centre", layout="wide", initial_sidebar_state="expanded")
sc.inject()

PAGES = ["Security Overview", "Live Event Feed", "Attack Investigations", "Employee Risk Monitor", "Attack Timeline",
         "Attack Graph", "Response Centre", "Audit Logs"]
LIVE_SECONDS = 3
CACHE_SECONDS = 25
TIME_RANGES = {"Last 15 minutes": 15, "Last hour": 60, "Last 6 hours": 360, "Last 24 hours": 1440, "Last 7 days": 10080,
               "All time": None}
SEVERITIES = {"All severities": None, "Normal": "normal", "Suspicious": "suspicious", "High Risk": "high_risk", "Critical": "critical"}
EVENT_TYPES = ["All event types", "login", "login_failed", "logout", "resource_access", "file_download", "data_export",
               "directory_search", "administrative_action", "external_transfer", "permission_change_attempt"]
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


def store_get(key, default=None):
    return st.session_state.get("store", {}).get(key, default)


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
        st.markdown(f'<div class="login-title">{ui.ORG_NAME}</div><div class="login-sub">Security Operations Centre - sign in</div>',
                    unsafe_allow_html=True)
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
    tiles = [
        ("Total security events", f"{k['total_events']:,}", f"{k['events_24h']:,} in the last 24 h", ""),
        ("Active investigations", k["active_investigations"], "open or contained", "warn" if k["active_investigations"] else ""),
        ("Critical alerts", k["critical_alerts"], "active", "alert" if k["critical_alerts"] else ""),
        ("High-risk employees", k["high_risk_employees"], "High Risk or Critical", "warn" if k["high_risk_employees"] else ""),
        ("Sensitive records accessed", f"{k['sensitive_records_accessed']:,}", f"{k['sensitive_records_24h']:,} in the last 24 h", ""),
        ("Confirmed external transfers", k["confirmed_external_transfers"], "transfer confirmed", "alert" if k["confirmed_external_transfers"] else ""),
    ]
    sc.kpi_grid(tiles)

    ui.section("Live attack confidence")
    threats = ov["threats"]
    if threats:
        ids = [t["employee_id"] for t in threats]
        chosen = pselect("Monitored employee", ids, "meter_emp",
                         fmt=lambda eid: next(f"{eid} - {t['level_label']} ({t['confidence']:.1f})" for t in threats if t["employee_id"] == eid))
        t = next(x for x in threats if x["employee_id"] == chosen)
        left, right = st.columns([3, 2])
        left.markdown(sc.meter(t["confidence"], t["level"], ov["thresholds"]), unsafe_allow_html=True)
        with right:
            ui.kv_table([
                ("Employee ID", t["employee_id"]), ("Severity", t["level_label"]), ("Current attack stage", t["stage_label"]),
                ("Last event", short(t["last_event_at"]["local"])), ("Data exposure", t["exposure_label"]),
                ("Investigation", f"#{t['investigation_id']} ({t['investigation_status']})" if t["investigation_id"] else "none"),
            ])
        history = cached(f"history:{t['employee_pk']}", "/api/soc/confidence-history", employee_id=t["employee_pk"], minutes=240)
        if history and len(history) >= 2:
            st.plotly_chart(sc.confidence_chart(history, ov["thresholds"]), width="stretch", config={"displayModeBar": False})
    else:
        left, right = st.columns([3, 2])
        left.markdown(sc.meter(0, "normal", ov["thresholds"]), unsafe_allow_html=True)
        with right:
            ui.kv_table([("Employee ID", "-"), ("Severity", "Normal"), ("Current attack stage", "None"), ("Last event", "-")])
        ui.notice("ok", "No employee is above the Normal threshold.")

    ui.section(f"Active threats ({len(threats)})")
    if threats:
        ui.table([{"employee": t["employee_id"], "severity": t["level_label"], "confidence": f"{t['confidence']:.1f}",
                   "stage": t["stage_label"], "exposure": t["exposure_label"], "last": short(t["last_event_at"]["local"]),
                   "investigation": f"#{t['investigation_id']} {t['investigation_status']}" if t["investigation_id"] else "-"}
                  for t in threats],
                 {"employee": "Employee ID", "severity": "Severity", "confidence": "Attack confidence", "stage": "Current stage",
                  "exposure": "Data exposure", "last": "Last event", "investigation": "Investigation"}, result_column="severity")
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
    b.plotly_chart(sc.severity_chart(ov["employees_by_severity"]), width="stretch", config={"displayModeBar": False})


def page_overview() -> None:
    ui.page_header("Security Overview", "Current threat posture across the organisation")
    live(render_overview)


# ------------------------------------------------------------------ 2. live event feed
def page_feed() -> None:
    ui.page_header("Live Event Feed", "Every security event with its anomaly score, rule severity and attack stage")
    refresh_token()
    employees = cached("employees", "/api/soc/employees") or []
    cols = st.columns([1.2, 1.2, 1.4, 1.2, 1.4])
    emp = pselect("Employee", ["All employees"] + [e["employee_id"] for e in employees], "f_emp", container=cols[0])
    ip = ptext("IP address (prefix)", "f_ip", container=cols[1], placeholder="e.g. 185.220")
    etype = pselect("Event type", EVENT_TYPES, "f_type", container=cols[2], fmt=lambda v: v.replace("_", " "))
    sev = pselect("Severity", list(SEVERITIES), "f_sev", container=cols[3])
    rng = pselect("Time range", list(TIME_RANGES), "f_range", container=cols[4])

    def render():
        feed = cached("feed", "/api/soc/events", employee=None if emp.startswith("All") else emp, ip=ip.strip() or None,
                      event_type=None if etype.startswith("All") else etype, severity=SEVERITIES[sev],
                      minutes=TIME_RANGES[rng], limit=150)
        if feed is None:
            return
        rows = feed["rows"]
        sc.live_note(f"Live - latest event #{feed['latest_id']}; showing {len(rows)} most recent matching events")
        ui.table([{
            "time": short(r["timestamp"]["local"]), "employee": r["employee_id"], "type": r["event_type"].replace("_", " "),
            "ip": r["source_ip"], "resource": r["resource"] or "-", "status": r["outcome"],
            "anomaly": "-" if r["anomaly_score"] is None else f"{r['anomaly_score']:.2f}",
            "risk": r["risk_contribution"], "stage": r["stage_label"], "severity": sc.SEVERITY_LABELS[r["severity"]],
            "origin": "simulated" if r["synthetic"] else "live"} for r in rows],
            {"time": "Timestamp", "employee": "Employee ID", "type": "Event type", "ip": "Source IP", "resource": "Resource",
             "status": "Status", "anomaly": "Anomaly score", "risk": "Risk contribution", "stage": "Attack stage",
             "severity": "Severity", "origin": "Origin"}, result_column=["status", "severity"])

    live(render)


# ------------------------------------------------------------------ 3. attack investigations
def page_investigations() -> None:
    selected = st.session_state.get("selected_investigation")
    if selected:
        ui.page_header(f"Investigation {selected}", "Correlated evidence, data exposure and response status")
        st.button("Back to all investigations", key="inv_back", on_click=nav, args=("Attack Investigations",))
        live(lambda: render_investigation(selected))
        return
    ui.page_header("Attack Investigations", "Active and historical investigations")
    refresh_token()
    view = pselect("Show", ["Active", "All", "Closed"], "inv_view")
    live(lambda: render_investigation_list(view))


def render_investigation_list(view: str) -> None:
    rows = cached("inv_list", "/api/soc/investigations", status={"Active": "active", "Closed": "closed"}.get(view))
    if rows is None:
        return
    sc.live_note(f"Live - {len(rows)} investigation(s)")
    ui.table([{"id": r["id"], "employee": r["employee_id"], "confidence": f"{r['confidence']}", "severity": r["level_label"],
               "stage": r["stage_label"], "first": fmt_event(r["first_event"]), "latest": fmt_event(r["latest_event"]),
               "exposure": f"{r['exposure_label']} ({r['records_exposed']:,} records)" if r["records_exposed"] else r["exposure_label"],
               "status": r["status"].title()} for r in rows],
             {"id": "ID", "employee": "Affected employee", "confidence": "Attack confidence", "severity": "Severity",
              "stage": "Current stage", "first": "First suspicious event", "latest": "Latest event", "exposure": "Data exposure",
              "status": "Status"}, result_column="severity")
    if rows:
        a, b = st.columns([3, 1], vertical_alignment="bottom")
        choice = a.selectbox("Select an investigation", [r["id"] for r in rows], key="inv_pick",
                             format_func=lambda i: next(f"Investigation {i} - {r['employee_id']} - {r['level_label']} ({r['status']})"
                                                        for r in rows if r["id"] == i))
        if b.button("Open investigation", key="inv_open", width="stretch"):
            go("Attack Investigations", choice)
            st.rerun()


def render_investigation(inv_id: int) -> None:
    d = cached(f"inv:{inv_id}", f"/api/soc/investigations/{inv_id}")
    tl = cached(f"tl-inv:{inv_id}", "/api/soc/timeline", investigation_id=inv_id)
    if d is None:
        return
    sc.live_note("Live - updates as new correlated events arrive")
    tiles = [("Attack confidence", d["confidence"], d["level_label"], "alert" if d["level"] == "critical" else ""),
             ("Current stage", d["stage_label"], "", ""), ("Affected employee", d["employee_id"], "", ""),
             ("Status", d["status"].title(), f"alert #{d['alert_id']}" if d["alert_id"] else "no alert", ""),
             ("Data exposure", d["exposure_label"], f"{d['records_exposed']:,} records potentially exposed", "")]
    sc.kpi_grid(tiles)
    ui.notice("info", d["summary"])
    if tl:
        ui.section("Attack stages")
        st.markdown(sc.stage_strip(tl["stages"]), unsafe_allow_html=True)

    a, b = st.columns(2)
    with a:
        ui.section("Data exposure assessment")
        exp = d["exposure"] or {}
        ui.kv_table([("Status", exp.get("status_label", "-"))] + [(label, f"{exp.get(key, 0):,}") for key, label in EXPOSURE_ROWS]
                    + [("External transfer confirmed", "Yes" if exp.get("external_transfer_confirmed") else "No"),
                       ("Exfiltration established", "Yes" if exp.get("exfiltration_established") else "No")])
        st.caption(exp.get("statement", ""))
    with b:
        ui.section("How the confidence was reached")
        live_data = d["live"]
        if live_data:
            comps = live_data["components"]
            ui.table([{"component": name.title(), "value": f"{comps[name]['value']:.2f}", "weight": f"{comps[name]['weight']:.2f}",
                       "contribution": f"{comps[name]['contribution']:.1f}"} for name in ("ml", "rules", "correlation", "baseline", "stage")],
                     {"component": "Component", "value": "Value (0-1)", "weight": "Weight", "contribution": "Points"})
            st.caption(f"Current live confidence {live_data['confidence']:.1f} ({live_data['independent_stages']} independent stages; "
                       f"anomaly model: {live_data['ml']['mode'].replace('_', ' ') if live_data['ml'] else 'n/a'}).")

    ui.section("Correlated evidence")
    alert = d["alert"]
    if alert:
        st.caption(f"Alert #{alert['id']} - first suspicious event #{alert['first_event_id']}, triggering event #{alert['trigger_event_id']}, "
                   f"detected {short(alert['detected_at']['local'])}")
        ui.table([{"time": short(ev["timestamp"]), "event": f"#{ev['event_id']}", "account": ev["account"],
                   "type": ev["event_type"].replace("_", " "), "resource": ev["resource"] or "-", "rule": ev["rule"].replace("_", " "),
                   "stages": ", ".join(s.replace("_", " ") for s in ev["stages"]) or "-", "links": ", ".join(ev["relations"]) or "-"}
                  for ev in alert["evidence"]],
                 {"time": "Time (UTC)", "event": "Event", "account": "Account", "type": "Event type", "resource": "Resource",
                  "rule": "Strongest rule", "stages": "Stages supported", "links": "Linked by"})
    else:
        st.caption("No alert has been raised for this investigation; showing the investigation timeline instead.")
        ui.table([{"time": short(t["timestamp"]["local"]), "event": f"#{t['event_id']}", "type": t["event_type"].replace("_", " "),
                   "resource": t["resource"] or "-", "outcome": t["outcome"], "ip": t["source_ip"]} for t in d["timeline"]],
                 {"time": "Time", "event": "Event", "type": "Event type", "resource": "Resource", "outcome": "Outcome", "ip": "Source IP"})

    ui.section("Indicators")
    st.markdown("\n".join(f"- {i}" for i in d["indicators"]) or "None")
    ui.section("Recommended containment")
    ui.table([{"priority": a["priority"], "action": a["action"].replace("_", " "), "target": a.get("target") or "employee account",
               "reason": a["reason"]} for a in d["recommended_actions"]],
             {"priority": "Priority", "action": "Action", "target": "Target", "reason": "Reason"})
    st.button("Go to Response Centre", key="inv_to_response", on_click=nav, args=("Response Centre",))
    ui.section("Containment history")
    ui.table([{"time": short(c["at"]["local"]), "action": c["action"].replace("_", " "), "target": c["target"], "by": c["by"],
               "reason": c["reason"]} for c in d["containment_actions"]],
             {"time": "Time", "action": "Action", "target": "Target", "by": "Administrator", "reason": "Reason"})

    ui.section("Investigation status")
    closing = d["status"] != "closed"
    confirm = st.checkbox("I confirm this investigation should be " + ("closed" if closing else "reopened"), key=f"inv_confirm_{inv_id}")
    if st.button("Close investigation" if closing else "Reopen investigation", key=f"inv_status_{inv_id}", disabled=not confirm):
        try:
            api().patch(f"/api/investigations/{inv_id}", {"status": "closed" if closing else "open"})
            st.session_state["_cache"] = {}
            st.session_state["flash_ok"] = f"Investigation {inv_id} {'closed' if closing else 'reopened'}."
        except ApiError as exc:
            handle(exc)
        else:
            st.rerun(scope="fragment")
    flash_notice()


# ------------------------------------------------------------------ 4. employee risk monitor
def page_risk() -> None:
    ui.page_header("Employee Risk Monitor", "Employees ranked by current risk, from behavioural and rule evidence only")

    def render():
        rows = cached("employees", "/api/soc/employees")
        if rows is None:
            return
        sc.live_note(f"Live - {len(rows)} accounts ranked by attack confidence")
        ui.table([{"rank": i + 1, "employee": r["employee_id"], "dept": r["department"], "role": r["job_role"],
                   "score": r["risk_score"], "severity": r["level_label"], "anomaly": f"{r['anomaly_score']:.2f}",
                   "events": r["suspicious_events_24h"], "last": short(r["last_suspicious"]["local"]), "stage": r["stage_label"],
                   "inv": (f"#{r['investigation_id']} {r['investigation_status']}" if r["investigation_id"] else "none"),
                   "type": r["account_type"]} for i, r in enumerate(rows)],
                 {"rank": "Rank", "employee": "Employee ID", "dept": "Department", "role": "Job role", "score": "Risk score",
                  "severity": "Severity", "anomaly": "Anomaly score", "events": "Suspicious events (24 h)",
                  "last": "Last suspicious activity", "stage": "Current stage", "inv": "Investigation", "type": "Account type"},
                 result_column="severity")
        st.caption("Scores come from the detection engine (anomaly model, rules, correlation and baseline). "
                   "No names or personal characteristics are used.")

    live(render)


# ------------------------------------------------------------------ 5 + 6. timeline and graph
def scope_picker():
    refresh_token()
    scopes = cached("scopes", "/api/soc/scopes") or []
    if not scopes:
        ui.notice("info", "No investigations or active threats yet. Run an attack simulation to populate this page.")
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
                     f"attack confidence {tl['confidence']}")
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
    st.session_state["pending"] = spec
    st.rerun()


def confirmation_panel(options: dict) -> None:
    p = st.session_state["pending"]
    info = options[p["action"]]
    ui.section("Confirm response action")
    ui.notice("warn", "Live updates are paused while this action awaits confirmation." if info["needs_confirmation"]
              else "Review the action before executing.")
    ui.kv_table([("Action", info["label"]), ("Applies to", p["subject"]), ("Effect", info["description"]),
                 ("Disruptive", "Yes - confirmation required" if info["needs_confirmation"] else "No")])
    reason = st.text_input("Reason (recorded in the audit log)", value=p["reason"], key="pending_reason")
    confirmed = st.checkbox("I confirm that I want to execute this action", key="pending_confirm") if info["needs_confirmation"] else True
    a, b, _ = st.columns([1, 1, 4])
    if a.button("Execute action", type="primary", disabled=not confirmed or len(reason.strip()) < 3, key="pending_go"):
        body = {"employee_id": p["employee_pk"], "action_type": p["action"], "reason": reason.strip(), "confirm": bool(confirmed),
                "investigation_id": p.get("investigation_id"), "target": p.get("target")}
        try:
            api().post("/api/containment", {k: v for k, v in body.items() if v is not None})
        except ApiError as exc:
            if exc.status_code == 401:
                handle(exc)
            ui.notice("error", f"Action failed: {exc.detail} (the attempt has been recorded in the audit log)")
        else:
            st.session_state["flash_ok"] = f"{info['label']} executed for {p['subject']}."
            st.session_state.pop("pending")
            st.session_state["_cache"] = {}
            st.rerun()
    if b.button("Cancel", key="pending_cancel"):
        st.session_state.pop("pending")
        st.rerun()


def page_response() -> None:
    ui.page_header("Response Centre", "Recommended containment actions, active controls and response history")
    refresh_token()
    centre = cached("response", "/api/soc/response")
    if centre is None:
        return
    options = {o["action"]: o for o in centre["options"]}
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
            st.markdown(f"**{t['employee_id']}** &nbsp; {sc.severity_badge(t['level'])} &nbsp; confidence {t['confidence']:.1f} "
                        f"&nbsp; stage: {t['stage_label']} &nbsp; exposure: {t['exposure_label']}", unsafe_allow_html=True)
            head = st.columns([1, 2.2, 1.6, 4.6, 1, 1.2])
            for col, title in zip(head, ["Priority", "Action", "Target", "Reason", "Status", ""]):
                col.markdown(f"<span style='color:#5F6B7A;font-size:.78rem'>{title}</span>", unsafe_allow_html=True)
            for i, a in enumerate(t["actions"]):
                row = st.columns([1, 2.2, 1.6, 4.6, 1, 1.2], vertical_alignment="center")
                label = options.get(a["action"], {}).get("label", a["action"].replace("_", " ").title())
                row[0].write(a["priority"])
                row[1].write(label)
                row[2].write(a.get("target") or "employee account")
                row[3].caption(a["reason"])
                row[4].markdown(f"<span style='color:{'#1E6B34' if a['done'] else '#7A5200'};font-weight:600'>"
                                f"{'Done' if a['done'] else ('Advisory' if not a['executable'] else 'Pending')}</span>", unsafe_allow_html=True)
                if a["executable"] and not a["done"]:
                    if row[5].button("Review", key=f"act_{t['employee_pk']}_{i}_{a['action']}", width="stretch"):
                        request_action(action=a["action"], employee_pk=a.get("target_employee_id") or t["employee_pk"],
                                       subject=f"{a.get('target') or t['employee_id']}", reason=a["reason"],
                                       investigation_id=t["investigation_id"],
                                       target=a.get("target") if a["action"] in ("block_ip", "isolate_system") else None)
            st.divider()

        ui.section(f"Active response controls ({len(data['controls'])})")
        if data["controls"]:
            ui.table([{"kind": "Blocked IP" if c["kind"] == "blocked_ip" else "Isolated system", "target": c["label"], "by": c["by"],
                       "since": short(c["created_at"]["local"]), "reason": c["reason"]} for c in data["controls"]],
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
                   "reason": h["reason"], "inv": f"#{h['investigation_id']}" if h["investigation_id"] else "-"} for h in data["history"]],
                 {"time": "Time", "action": "Action", "employee": "Employee ID", "by": "Administrator", "reason": "Reason",
                  "inv": "Investigation"})

    live(render)

    ui.section("Manual response")
    c1, c2 = st.columns(2)
    action = pselect("Action", list(options), "m_action", container=c1, fmt=lambda a: options[a]["label"])
    emp_map = {e["employee_id"]: e["id"] for e in centre["employees"]}
    emp = pselect("Employee / account concerned", list(emp_map), "m_emp", container=c2)
    needs = options[action]["needs"]
    target = None
    if needs == "ip":
        target = ptext("IP address", "m_ip", placeholder="e.g. 185.220.101.45")
    elif needs == "system":
        systems = {s["id"]: s["label"] for s in centre["systems"]}
        target = pselect("System", list(systems), "m_system", fmt=lambda s: systems[s])
    st.caption(options[action]["description"])
    reason = ptext("Reason", "m_reason", placeholder="Why this action is needed")
    if st.button("Review action", key="m_review", disabled=len(reason.strip()) < 3 or (needs == "ip" and not (target or "").strip())):
        request_action(action=action, employee_pk=emp_map[emp], subject=target or emp, reason=reason.strip(),         target=target)


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


# ------------------------------------------------------------------ shell
PAGE_FUNCTIONS = {
    "Security Overview": page_overview, "Live Event Feed": page_feed, "Attack Investigations": page_investigations,
    "Employee Risk Monitor": page_risk, "Attack Timeline": page_timeline, "Attack Graph": page_graph,
    "Response Centre": page_response, "Audit Logs": page_audit,
}


def dashboard() -> None:
    page = st.session_state.get("page", PAGES[0])
    with st.sidebar:
        st.markdown(f'<div class="org-name">{ui.ORG_NAME}</div><div class="org-sub">Security Operations Centre</div>', unsafe_allow_html=True)
        for name in PAGES:
            st.button(name, key=f"nav_{name}", width="stretch", on_click=nav, args=(name,),
                      type="primary" if name == page else "secondary")
        st.button("Logout", key="nav_logout", width="stretch", on_click=sign_out)
        st.markdown(f'<div class="whoami">Signed in as<br><b>{st.session_state.get("admin_id", "")}</b><br>'
                    f'Live refresh: {LIVE_SECONDS} s</div>', unsafe_allow_html=True)
    PAGE_FUNCTIONS[page]()


if st.session_state.get("token"):
    dashboard()
else:
    login_page()
