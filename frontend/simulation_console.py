"""Security administrator simulation console (Streamlit). Run:  streamlit run frontend/simulation_console.py --server.port 8502

A control panel only: a seeded scenario is generated and executed by the backend, which submits every simulated action
through its normal authentication, permission, event-collection and detection code. Everything is flagged synthetic and
can be reset. The console never creates alerts or scores itself; it only shows what the backend produced.
"""
import ipaddress
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st  # noqa: E402

from frontend import components as ui  # noqa: E402
from frontend.api_client import ApiClient, ApiError  # noqa: E402

st.set_page_config(page_title=f"{ui.ORG_NAME} - Simulation Console", layout="wide")
ui.inject_css()

STATUS_TEXT = {"completed": "Completed", "denied": "Denied by backend", "blocked": "Blocked"}


def api() -> ApiClient:
    return ApiClient(st.session_state.get("token"), "Simulation Console (Streamlit)")


def sign_out(message: str | None = None) -> None:
    if st.session_state.get("token"):
        try:
            api().logout()
        except ApiError:
            pass
    st.session_state.clear()
    if message:
        st.session_state["flash"] = message


def login_page() -> None:
    _, centre, _ = st.columns([1, 1.15, 1])
    with centre:
        st.markdown("<div style='height:3rem'></div>", unsafe_allow_html=True)
        ui.login_header("Simulation Console - administrators only")
        flash = st.session_state.pop("flash", None)
        if flash:
            ui.notice("info", flash)
        with st.form("sim_login"):
            employee_id = st.text_input("Employee ID")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign in", type="primary")
        if submitted:
            try:
                result = ApiClient(None, "Simulation Console (Streamlit)").login(employee_id.strip(), password)
            except ApiError as exc:
                ui.notice("error", exc.detail)
            else:
                session_client = ApiClient(result["access_token"], "Simulation Console (Streamlit)")
                try:
                    session_client.sim_scenarios()  # 403 for anyone who is not an authorised administrator
                except ApiError as exc:
                    try:
                        session_client.logout()
                    except ApiError:
                        pass
                    ui.notice("error", "This console is restricted to security administrators."
                              if exc.status_code == 403 else exc.detail)
                else:
                    st.session_state.token = result["access_token"]
                    st.session_state.admin_name = result["employee"]["full_name"]
                    st.rerun()


def refresh_config() -> dict:
    return api().sim_scenarios()


def run_and_log(action) -> None:
    """Run one manual step and add its outcome to this session's log."""
    try:
        outcome = action()
    except ApiError as exc:
        if exc.status_code == 401:
            sign_out("Your session has expired. Please sign in again.")
            st.rerun()
        ui.notice("error", exc.detail)
        return
    st.session_state.setdefault("log", []).insert(
        0, {"step": outcome["step"], "status": STATUS_TEXT.get(outcome["status"], outcome["status"]),
            "detail": outcome["detail"], "events": len(outcome["event_ids"])})


RUN_STATUS_TEXT = {"queued": "Queued", "running": "Running", "completed": "Completed", "failed": "Failed", "cancelled": "Cancelled"}
LEVEL_TEXT = {"normal": "Normal", "suspicious": "Suspicious", "high_risk": "High risk", "critical": "Critical"}


def render_run(run: dict) -> None:
    """Status, progress, plan identity and the outcome the detection pipeline actually produced."""
    active = run["status"] in ("queued", "running")
    st.markdown(f"**Run {run['id']}: {run['scenario'].replace('_', ' ')}** - {RUN_STATUS_TEXT[run['status']]}"
                + (" (stop requested)" if run["cancel_requested"] and active else ""))
    st.progress(run["steps_done"] / max(1, run["steps_total"]), text=f"{run['steps_done']} of {run['steps_total']} actions submitted")
    observed = run["observed"]
    ui.kv_table([
        ("Seed", f"{run['seed']} ({'fixed, reproducible' if run['seed_mode'] == 'fixed' else 'random'})"),
        ("Employee", f"{run['target']['employee_id']} - {run['target']['full_name']}" if run["target"] else "-"),
        ("Simulated source address", run["source_ip"] or "employee's familiar address"),
        ("Plan fingerprint (SHA-256)", (run["plan_sha256"] or "")[:16] + "..."),
        ("Events stored", f"{observed['events']} ({observed['noise_events']} benign background)"),
        ("Highest assessed level", LEVEL_TEXT.get(observed["peak_level"], "-") + (f" ({observed['peak_score']}/100)" if observed["peak_score"] is not None else "")),
        ("Alert raised by the detector", "Yes" if observed["alert_raised"] else "No"),
        ("Rules that fired", ", ".join(observed["rules_fired"]) or "None"),
    ])
    if run["error"]:
        ui.notice("error", run["error"])


def run_panel(run_id: int, active: bool) -> None:
    @st.fragment(run_every=1.0 if active else None)
    def panel() -> None:
        try:
            run = api().sim_get_run(run_id)
        except ApiError as exc:
            ui.notice("error", exc.detail)
            return
        render_run(run)
        if active and run["status"] not in ("queued", "running"):
            st.rerun()                                       # the run ended: refresh the controls

    panel()


def console() -> None:
    try:
        config = refresh_config()
        status = api().sim_status()
    except ApiError as exc:
        if exc.status_code == 401:
            sign_out("Your session has expired. Please sign in again.")
            st.rerun()
        ui.notice("error", exc.detail)
        return

    with st.sidebar:
        ui.brand("Simulation Console")
        ui.user_card(st.session_state.admin_name, "Security administrator")
        st.button("Logout", on_click=sign_out, width="stretch", icon=":material/logout:")

    st.markdown('<div class="sim-banner">SIMULATION ENVIRONMENT - SYNTHETIC DATA ONLY. Actions run through the live backend '
                "and are stored in the shared database flagged as synthetic.</div>", unsafe_allow_html=True)
    ui.page_header("Attack simulation", "Simulate a compromised employee account")

    ui.section("Scenario run")
    active_id = status.get("active_run_id")
    scenarios = {s["name"]: s for s in config["scenarios"]}
    left, right = st.columns(2)
    scenario = scenarios[left.selectbox("Scenario", list(scenarios), disabled=bool(active_id))]
    st.caption(f"{scenario['description']}  Intent: {scenario['intent']}")
    eligible = [t for t in config["targets"] if t["eligible"].get(scenario["id"])]
    labels = {f"{t['employee_id']} - {t['full_name']} ({t['job_role']})": t for t in eligible}
    choice = right.selectbox("Employee account", ["Chosen by the seed", *labels], key=f"target_{scenario['id']}", disabled=bool(active_id))
    target = labels.get(choice)

    a, b, c = st.columns(3)
    seed_mode = a.radio("Seed", ["Random (demo)", "Fixed (reproducible)"], horizontal=False, disabled=bool(active_id))
    seed = int(b.number_input("Seed value", min_value=0, max_value=2**31 - 1, value=1234, step=1,
                              disabled=seed_mode.startswith("Random") or bool(active_id)))
    pace = c.selectbox("Pace", config["paces"], format_func={"demo": "Demo (watch it unfold)", "instant": "Instant"}.get,
                       disabled=bool(active_id))
    d, e, f = st.columns(3)
    noise = int(d.slider("Background employees", 0, 3, 2, help="Other employees whose benign activity is mixed in", disabled=bool(active_id)))
    custom_records = e.checkbox("Set the record volume", disabled=bool(active_id))
    records = int(f.number_input("Records", min_value=1, max_value=1_000_000, value=config["default_records"], step=1000,
                                 disabled=not custom_records or bool(active_id)))
    source_ip = ""
    if scenario["uses_external_ip"]:
        source_ip = st.text_input("Simulated external address (optional)", value="",
                                  placeholder="Leave empty for a generated documentation address (RFC 5737)",
                                  disabled=bool(active_id)).strip()
    ip_valid = True
    if source_ip:
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            ip_valid = False
            ui.notice("warn", "Enter a valid IPv4 or IPv6 address, or leave the field empty.")

    start_col, stop_col = st.columns(2)
    if "run_key" not in st.session_state:
        st.session_state["run_key"] = uuid.uuid4().hex      # one key per start intent: reruns and double clicks reuse it
    if start_col.button("Start run", type="primary", disabled=bool(active_id) or not ip_valid, key="start_run"):
        body = {"scenario": scenario["id"], "pace": pace, "noise": noise, "idempotency_key": st.session_state["run_key"]}
        if target:
            body["target_employee_id"] = target["id"]
        if seed_mode.startswith("Fixed"):
            body["seed"] = seed
        if custom_records:
            body["records"] = records
        if source_ip:
            body["source_ip"] = source_ip
        try:
            started = api().sim_start_run(body)
        except ApiError as exc:
            ui.notice("error", exc.detail)
        else:
            st.session_state["run_id"] = started["id"]
            st.session_state.pop("run_key", None)
            st.rerun()
    if stop_col.button("Stop run", disabled=not active_id, key="stop_run"):
        try:
            api().sim_cancel_run(active_id)
        except ApiError as exc:
            ui.notice("error", exc.detail)
        st.rerun()

    shown = active_id or st.session_state.get("run_id")
    if shown:
        run_panel(shown, bool(active_id))
    history = api().sim_runs(8)
    if history:
        st.markdown("**Recent runs**")
        ui.table([{"id": r["id"], "scenario": r["scenario"].replace("_", " "), "status": RUN_STATUS_TEXT[r["status"]],
                   "seed": r["seed"], "employee": r["target"]["employee_id"] if r["target"] else "-",
                   "events": r["observed"]["events"], "level": LEVEL_TEXT.get(r["observed"]["peak_level"], "-")} for r in history],
                 {"id": "Run", "scenario": "Scenario", "status": "Status", "seed": "Seed", "employee": "Employee",
                  "events": "Events", "level": "Highest level"})

    ui.section("Reset")
    confirm = st.checkbox("Confirm reset: removes all synthetic data and undoes containment on affected accounts")
    if st.button("Reset simulation", disabled=not confirm or bool(active_id)):
        try:
            outcome = api().sim_reset()
            st.session_state["log"] = []
            st.session_state.pop("run_id", None)
            st.session_state["reset_message"] = (
                f"Simulation reset. Removed {outcome['events']} events, {outcome['sessions']} sessions, "
                f"{outcome['accounts']} accounts, {outcome['alerts']} alerts, {outcome['investigations']} investigations "
                f"and {outcome['runs']} run records."
            )
        except ApiError as exc:
            ui.notice("error", exc.detail)
        st.rerun()
    if "reset_message" in st.session_state:
        ui.notice("ok", st.session_state.pop("reset_message"))
    if active_id:
        st.caption("Reset and manual steps are disabled while a run is active. Stop it first.")

    ui.section("Individual steps")
    st.caption("Manual single-stage controls. Each step goes through the same backend path as a scenario run.")
    manual_labels = {f"{t['employee_id']} - {t['full_name']}": t for t in config["targets"]}
    m1, m2, m3 = st.columns(3)
    manual_target = manual_labels[m1.selectbox("Employee for manual steps", list(manual_labels), key="manual_target")]
    manual_ip = m2.text_input("Source IP address", value=config["default_source_ip"], key="manual_ip").strip()
    manual_records = int(m3.number_input("Records", min_value=1, max_value=1_000_000, value=config["default_records"], step=1000,
                                         key="manual_records"))
    manual_ip_valid = True
    try:
        ipaddress.ip_address(manual_ip)
    except ValueError:
        manual_ip_valid = False
        ui.notice("warn", "Enter a valid IPv4 or IPv6 address.")
    steps = {s["id"]: s for s in config["steps"]}
    for step_id, step in steps.items():
        a, b, c = st.columns([3, 6, 2], vertical_alignment="center")
        a.markdown(f"**{step['label']}**" + ("  \n:grey[executed]" if step_id in status["steps_executed"] else ""))
        b.caption(step["description"])
        if c.button("Run step", key=f"step_{step_id}", disabled=not manual_ip_valid or bool(active_id), width="stretch"):
            run_and_log(lambda s=step_id: api().sim_step(manual_target["id"], s, manual_ip, "manual_steps", manual_records))
            st.rerun()

    ui.section("Execution log")
    log = st.session_state.get("log", [])
    if log:
        ui.table(log, {"step": "Step", "status": "Result", "detail": "Detail", "events": "Events"}, result_column="status")
    else:
        st.caption("No simulation steps have been run in this session.")

    ui.section("Simulation state")
    ui.kv_table([
        ("Synthetic events stored", status["synthetic_events"]),
        ("Active synthetic sessions", status["active_synthetic_sessions"]),
        ("Synthetic accounts", ", ".join(a["username"] for a in status["synthetic_accounts"]) or "None"),
        ("Steps executed", ", ".join(status["steps_executed"]) or "None"),
    ])
    events = api().synthetic_events(15)
    if events:
        st.markdown("**Latest synthetic events (shared database)**")
        ui.table(
            [{"id": e["id"], "time": ui.fmt_ts(e["timestamp_local"]), "account": e["employee_username"],
              "type": e["event_type"], "resource": e["resource"] or "-", "result": e["outcome"],
              "ip": e["source_ip"], "accessed": e["records_accessed"], "downloaded": e["records_downloaded"],
              "synthetic": "Yes" if e["is_synthetic"] else "No"} for e in events],
            {"id": "ID", "time": "Time", "account": "Account", "type": "Type", "resource": "Resource", "result": "Result",
             "ip": "Source IP", "accessed": "Records accessed", "downloaded": "Records downloaded", "synthetic": "Synthetic"},
        )


if st.session_state.get("token"):
    console()
else:
    login_page()
