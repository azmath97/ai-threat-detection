"""Security administrator simulation console (Streamlit). Run:  streamlit run frontend/simulation_console.py --server.port 8502

A control panel only: every simulated action goes through the backend's real authentication, permission,
event-collection and detection code, and everything it creates is flagged synthetic and can be reset.
"""
import ipaddress
import sys
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
    try:
        outcome = action()
    except ApiError as exc:
        if exc.status_code == 401:
            sign_out("Your session has expired. Please sign in again.")
            st.rerun()
        ui.notice("error", exc.detail)
        return
    results = outcome["results"] if "results" in outcome else [outcome]
    log = st.session_state.setdefault("log", [])
    for r in results:
        log.insert(0, {"step": r["step"], "status": STATUS_TEXT.get(r["status"], r["status"]), "detail": r["detail"],
                       "events": len(r["event_ids"])})


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
        st.markdown(f'<div class="whoami">Signed in as<br><b>{st.session_state.admin_name}</b></div>', unsafe_allow_html=True)
        st.button("Logout", on_click=sign_out, width="stretch", icon=":material/logout:")

    st.markdown('<div class="sim-banner">SIMULATION ENVIRONMENT - SYNTHETIC DATA ONLY. Actions run through the live backend '
                "and are stored in the shared database flagged as synthetic.</div>", unsafe_allow_html=True)
    ui.page_header("Attack simulation", "Simulate a compromised employee account")

    ui.section("Scenario")
    scenarios = {s["name"]: s for s in config["scenarios"]}
    targets = {f"{t['employee_id']} - {t['full_name']} ({t['job_role']})": t for t in config["targets"]}
    left, right = st.columns(2)
    scenario = scenarios[left.selectbox("Scenario", list(scenarios))]
    default_label = next((k for k, t in targets.items() if t["username"] == scenario["default_target"]), list(targets)[0])
    target = targets[right.selectbox("Compromised employee account", list(targets), index=list(targets).index(default_label),
                                     key=f"target_{scenario['id']}")]
    st.caption(scenario["description"])
    source_ip = st.text_input("Source IP address of the simulated attacker", value=config["default_source_ip"])
    records = int(st.number_input("Records in the simulated export and external transfer", min_value=1, max_value=1_000_000,
                                  value=config["default_records"], step=1000))
    ip_valid = True
    try:
        ipaddress.ip_address(source_ip.strip())
    except ValueError:
        ip_valid = False
        ui.notice("warn", "Enter a valid IPv4 or IPv6 address.")
    if ip_valid and source_ip.strip() in target["known_ips"]:
        ui.notice("info", "This address is one of the employee's known addresses; it will not look unfamiliar.")

    ui.section("Run")
    run_col, reset_col = st.columns([1, 1])
    if run_col.button(f"Run complete scenario ({len(scenario['steps'])} steps)", type="primary", disabled=not ip_valid):
        run_and_log(lambda: api().sim_run(target["id"], source_ip.strip(), scenario["id"], records))
        st.rerun()
    confirm = reset_col.checkbox("Confirm reset: removes all synthetic data and undoes containment on affected accounts")
    if reset_col.button("Reset simulation", disabled=not confirm):
        try:
            outcome = api().sim_reset()
            st.session_state["log"] = []
            st.session_state["reset_message"] = (
                f"Simulation reset. Removed {outcome['events']} events, {outcome['sessions']} sessions, "
                f"{outcome['accounts']} accounts, {outcome['alerts']} alerts and {outcome['investigations']} investigations."
            )
        except ApiError as exc:
            ui.notice("error", exc.detail)
        st.rerun()
    if "reset_message" in st.session_state:
        ui.notice("ok", st.session_state.pop("reset_message"))

    ui.section("Individual steps")
    steps = {s["id"]: s for s in config["steps"]}
    for step_id, step in steps.items():
        a, b, c = st.columns([3, 6, 2], vertical_alignment="center")
        a.markdown(f"**{step['label']}**" + ("  \n:grey[executed]" if step_id in status["steps_executed"] else ""))
        b.caption(step["description"])
        if c.button("Run step", key=f"step_{step_id}", disabled=not ip_valid, width="stretch"):
            run_and_log(lambda s=step_id: api().sim_step(target["id"], s, source_ip.strip(), scenario["id"], records))
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
