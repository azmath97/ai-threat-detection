"""Employee Workspace Portal (Streamlit). Run:  streamlit run frontend/employee_portal.py

The portal holds only the session token. Identity, permissions, source IP and device are decided by the
backend; this UI never shows security scores, alerts or investigation data.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st  # noqa: E402

from frontend import components as ui  # noqa: E402
from frontend.api_client import ApiClient, ApiError  # noqa: E402

st.set_page_config(page_title=f"{ui.ORG_NAME} - Employee Portal", layout="wide", initial_sidebar_state="auto")
ui.inject_css()

PAGES = ["Dashboard", "HR Records", "Payroll", "Documents", "Employee Directory", "My Profile"]
PAGE_STATE = ("data", "hr_record", "payslip_view", "export_file", "doc_file", "dir_results", "hr_query")


# ------------------------------------------------------------------ session helpers
def device_description() -> str:
    try:
        return st.context.headers.get("User-Agent") or "unknown"
    except Exception:
        return "unknown"


def api() -> ApiClient:
    return ApiClient(st.session_state.get("token"), device_description())


def reset_session(message: str | None = None) -> None:
    st.session_state.clear()
    if message:
        st.session_state["flash"] = message


def call(fn, *args):
    """Run a backend call. Returns (result, error). An expired session returns the user to sign-in."""
    try:
        return fn(*args), None
    except ApiError as exc:
        if exc.status_code == 401 and st.session_state.get("token"):
            reset_session("Your session has expired. Please sign in again.")
            st.rerun()
        return None, exc


def load(key: str, fn, *args):
    """Fetch once per page visit so that re-renders do not generate repeated activity records."""
    cache = st.session_state.setdefault("data", {})
    if key not in cache:
        cache[key] = call(fn, *args)
    return cache[key]


def go(page: str) -> None:
    for key in PAGE_STATE:
        st.session_state.pop(key, None)
    st.session_state.page = page


def sign_out() -> None:
    call(api().logout)
    reset_session("You have been signed out.")


def show_error(error: ApiError) -> None:
    ui.notice("error" if error.status_code in (403, 0) or error.status_code >= 500 else "warn", error.detail)


def access_levels() -> dict[str, str | None]:
    resources, error = load("resources", api().resources)
    return {r["id"]: r["access_level"] for r in resources} if not error else {}


def resource_names() -> dict[str, str]:
    resources, error = load("resources", api().resources)
    return {r["id"]: r["name"] for r in resources} if not error else {}


# ------------------------------------------------------------------ sign-in
def login_page() -> None:
    _, centre, _ = st.columns([1, 1.15, 1])
    with centre:
        st.markdown("<div style='height:3rem'></div>", unsafe_allow_html=True)
        ui.login_header("Employee Portal - sign in")
        flash = st.session_state.pop("flash", None)
        if flash:
            ui.notice("info", flash)
        with st.form("login", clear_on_submit=False):
            employee_id = st.text_input("Employee ID", placeholder="For example EMP-1001")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign in", type="primary")
        if submitted:
            if not employee_id.strip() or not password:
                ui.notice("warn", "Enter your employee ID and password.")
            else:
                try:
                    result = ApiClient(None, device_description()).login(employee_id.strip(), password)
                except ApiError as exc:
                    show_error(exc)
                else:
                    st.session_state.token = result["access_token"]
                    st.session_state.page = "Dashboard"
                    st.session_state.data = {}
                    st.rerun()
        st.markdown(
            '<div class="fine-print">Authorised users only. Activity on this system is recorded and monitored. '
            "This is a demonstration environment containing synthetic data.</div>",
            unsafe_allow_html=True,
        )


# ------------------------------------------------------------------ pages
def page_dashboard() -> None:
    profile, error = load("me", api().me)
    if error:
        show_error(error)
        return
    ui.page_header("Dashboard", "Your workspace at a glance")
    last = ui.fmt_ts(profile.get("previous_login_at_local")) if profile.get("previous_login_at") else "First sign-in"
    ui.hero("Employee workspace", f"Welcome back, {profile['full_name'].split()[0]}",
            f"{profile['job_role']} in {profile['department']}. Use the menu to open your payslips, documents, the directory and your profile.",
            [profile["employee_code"], f"Last sign-in {last}"])

    ui.section("Your details")
    ui.kv_table([
        ("Name", profile["full_name"]),
        ("Employee ID", profile["employee_code"]),
        ("Department", profile["department"]),
        ("Job role", profile["job_role"]),
        ("Last login", last),
    ])

    ui.section("Available resources")
    resources, error = load("resources", api().resources)
    if error:
        show_error(error)
    else:
        rows = [
            {"name": r["name"], "classification": r["sensitivity"].title(), "department": r["department"],
             "access": ui.ACCESS_LABELS.get(r["access_level"], "-")}
            for r in resources if r["access_level"]
        ]
        ui.table(rows, {"name": "Resource", "classification": "Classification", "department": "Owner", "access": "Your access"})

    ui.section("Recent activity")
    events, error = load("activity", api().my_activity, 10)
    if error:
        show_error(error)
    elif not events:
        st.caption("No recent activity.")
    else:
        names = resource_names()
        ui.feed([{"title": ui.ACTIVITY_LABELS.get(e["event_type"], e["event_type"]) + (f" - {names.get(e['resource'], e['resource'])}" if e["resource"] else ""),
                  "sub": ui.RESULT_LABELS.get(e["outcome"], e["outcome"]) + (f" - {e['records_accessed']} records" if e["records_accessed"] else ""),
                  "time": ui.fmt_ts(e["timestamp_local"]), "tone": "bad" if e["outcome"] in ("denied", "failure") else ""} for e in events])


def page_hr_records() -> None:
    ui.page_header("HR Records", "Employee records and employment details")
    if not access_levels().get("hr-records"):
        ui.notice("warn", "HR Records are available to HR staff only. Your role does not include access to this resource.")
        return

    query = st.session_state.get("hr_query", "")
    with st.form("hr_search"):
        text = st.text_input("Search records", value=query, placeholder="Name, employee ID, department or role")
        if st.form_submit_button("Search"):
            st.session_state.hr_query = text.strip()
            st.rerun()

    rows, error = load(f"hr_list:{query}", api().hr_records, query)
    if error:
        show_error(error)
        return
    ui.section(f"Employee records ({len(rows)})")
    ui.table(rows, {"employee_id": "Employee ID", "name": "Name", "department": "Department",
                    "job_role": "Job role", "status": "Status"})
    if not rows:
        return

    options = {f"{r['employee_id']} - {r['name']}": r["employee_id"] for r in rows}
    left, right = st.columns([3, 1], vertical_alignment="bottom")
    choice = left.selectbox("Select a record", list(options))
    if right.button("Open record", width="stretch"):
        st.session_state.hr_record = call(api().hr_record, options[choice])

    if "hr_record" in st.session_state:
        record, error = st.session_state.hr_record
        if error:
            show_error(error)
        else:
            ui.section(f"Record: {record['name']}")
            ui.kv_table([
                ("Employee ID", record["employee_id"]), ("Name", record["name"]), ("Email", record["email"]),
                ("Department", record["department"]), ("Job role", record["job_role"]), ("Status", record["status"]),
                ("Manager", record["manager"]), ("Location", record["location"]),
                ("Employment type", record["employment_type"]), ("Hire date", ui.fmt_ts(record["hire_date"], False)),
                ("Work phone", record["work_phone"]), ("Leave balance", f"{record['leave_balance_days']} days"),
                ("Latest performance rating", record["performance_rating"]),
                ("Emergency contact", record["emergency_contact"]),
            ])


def _money_rows(rows: list[dict], keys: list[str]) -> list[dict]:
    return [{**r, **{k: f"{r[k]:,.2f}" for k in keys}} for r in rows]


def page_payroll() -> None:
    ui.page_header("Payroll", "Payslips and payroll administration")
    level = access_levels().get("payroll-records")
    views = ["My payslips"] + (["Payroll register"] if level else [])
    view = st.radio("View", views, horizontal=True, label_visibility="collapsed")

    if view == "My payslips":
        slips, error = load("payslips", api().payslips)
        if error:
            show_error(error)
            return
        ui.section("Payslips")
        ui.table(
            [{"period": s["period"], "gross": ui.fmt_money(s["gross"], s["currency"]),
              "deductions": ui.fmt_money(s["total_deductions"], s["currency"]), "net": ui.fmt_money(s["net"], s["currency"])}
             for s in slips],
            {"period": "Pay period", "gross": "Gross pay", "deductions": "Deductions", "net": "Net pay"},
        )
        left, right = st.columns([3, 1], vertical_alignment="bottom")
        period = left.selectbox("Pay period", [s["period"] for s in slips])
        if right.button("View payslip", width="stretch"):
            st.session_state.payslip_view = call(api().payslip, period)
        if "payslip_view" in st.session_state:
            slip, error = st.session_state.payslip_view
            if error:
                show_error(error)
            else:
                cur = slip["currency"]
                ui.section(f"Payslip - {slip['period']}")
                ui.kv_table([("Employee", f"{slip['name']} ({slip['employee_id']})"), ("Pay period", slip["period"])])
                a, b = st.columns(2)
                with a:
                    st.markdown("**Earnings**")
                    ui.table([{"item": k, "amount": f"{v:,.2f}"} for k, v in slip["earnings"].items()],
                             {"item": "Item", "amount": f"Amount ({cur})"})
                with b:
                    st.markdown("**Deductions**")
                    ui.table([{"item": k, "amount": f"{v:,.2f}"} for k, v in slip["deductions"].items()],
                             {"item": "Item", "amount": f"Amount ({cur})"})
                ui.kv_table([("Gross pay", ui.fmt_money(slip["gross"], cur)),
                             ("Total deductions", ui.fmt_money(slip["total_deductions"], cur)),
                             ("Net pay", ui.fmt_money(slip["net"], cur))])
        return

    rows, error = load("register", api().payroll_register)
    if error:
        show_error(error)
        return
    ui.section(f"Payroll register ({len(rows)} employees)")
    ui.table(_money_rows(rows, ["gross", "deductions", "net"]),
             {"employee_id": "Employee ID", "name": "Name", "department": "Department", "period": "Pay period",
              "gross": "Gross", "deductions": "Deductions", "net": "Net"})
    if level != "write":
        ui.notice("info", "Exporting the register requires payroll write access.")
    elif st.button("Export payroll register (CSV)"):
        st.session_state.export_file = call(api().payroll_export)
    if "export_file" in st.session_state:
        export, error = st.session_state.export_file
        if error:
            show_error(error)
        else:
            ui.notice("ok", f"Export completed: {export['record_count']} records.")
            st.download_button("Save file", export["content"], file_name=export["filename"], mime=export["media_type"])


def page_documents() -> None:
    ui.page_header("Documents", "Documents available to your role")
    docs, error = load("documents", api().documents)
    if error:
        show_error(error)
        return
    ui.table(
        [{"id": d["id"], "title": d["title"], "category": d["category"], "source": d["source"],
          "format": d["format"].upper(), "size": f"{d['size_bytes'] / 1024:.1f} KB"} for d in docs],
        {"id": "Reference", "title": "Title", "category": "Category", "source": "Source", "format": "Format", "size": "Size"},
    )
    options = {f"{d['id']} - {d['title']}": d["id"] for d in docs}
    left, right = st.columns([3, 1], vertical_alignment="bottom")
    choice = left.selectbox("Select a document", list(options))
    if right.button("Request download", width="stretch"):
        data, error = call(api().download_document, options[choice])
        st.session_state.doc_file = (data, error)
    if "doc_file" in st.session_state:
        data, error = st.session_state.doc_file
        if error:
            show_error(error)
        else:
            content, filename, mime = data
            ui.notice("ok", f"Document ready: {filename}")
            st.download_button("Save file", content, file_name=filename, mime=mime.split(";")[0])


def page_directory() -> None:
    ui.page_header("Employee Directory", "Find colleagues by name, role or department")
    departments, _ = load("departments", api().departments)
    with st.form("directory_search"):
        a, b = st.columns([3, 2])
        text = a.text_input("Search", placeholder="Name, employee ID, role or email")
        department = b.selectbox("Department", ["All departments"] + (departments or []))
        submitted = st.form_submit_button("Search")
    if submitted:
        st.session_state.dir_results = call(api().directory, text.strip(), "" if department.startswith("All") else department)
    if "dir_results" not in st.session_state:
        st.caption("Enter a search term or choose a department to list employees.")
        return
    rows, error = st.session_state.dir_results
    if error:
        show_error(error)
    elif not rows:
        ui.notice("info", "No matching employees found.")
    else:
        ui.section(f"Results ({len(rows)})")
        ui.table(rows, {"name": "Name", "employee_id": "Employee ID", "department": "Department", "job_role": "Job role",
                        "email": "Email", "phone": "Phone", "location": "Location"})


def page_profile() -> None:
    ui.page_header("My Profile", "Your employment and contact information")
    detail, error = load("profile_detail", api().profile_detail)
    if error:
        show_error(error)
        return
    me, _ = load("me", api().me)
    ui.section("Personal and employment details")
    ui.kv_table([
        ("Name", detail["name"]), ("Employee ID", detail["employee_id"]), ("Email", detail["email"]),
        ("Department", detail["department"]), ("Job role", detail["job_role"]), ("Manager", detail["manager"]),
        ("Location", detail["location"]), ("Employment type", detail["employment_type"]),
        ("Hire date", ui.fmt_ts(detail["hire_date"], False)), ("Work phone", detail["work_phone"]),
        ("Leave balance", f"{detail['leave_balance_days']} days"), ("Emergency contact", detail["emergency_contact"]),
    ])
    if me:
        ui.section("Your system access")
        ui.table(
            [{"name": p["name"], "classification": p["sensitivity"].title(), "access": ui.ACCESS_LABELS.get(p["access_level"], "-")}
             for p in me["permissions"]],
            {"name": "Resource", "classification": "Classification", "access": "Access"},
        )


PAGE_FUNCTIONS = {
    "Dashboard": page_dashboard,
    "HR Records": page_hr_records,
    "Payroll": page_payroll,
    "Documents": page_documents,
    "Employee Directory": page_directory,
    "My Profile": page_profile,
}


NAV_ICONS = {"Dashboard": "dashboard", "HR Records": "badge", "Payroll": "payments", "Documents": "description",
             "Employee Directory": "contacts", "My Profile": "account_circle"}


def portal() -> None:
    page = st.session_state.get("page", "Dashboard")
    profile, _ = load("me", api().me)
    with st.sidebar:
        ui.brand("Employee Portal")
        ui.nav_caption("Workspace")
        for name in PAGES:
            if name == "My Profile":
                ui.nav_caption("Account")
            st.button(name, key=f"nav_{name}", width="stretch", on_click=go, args=(name,), icon=f":material/{NAV_ICONS[name]}:",
                      type="primary" if name == page else "secondary")
        st.button("Logout", key="nav_logout", width="stretch", on_click=sign_out, icon=":material/logout:")
        if profile:
            ui.user_card(profile["full_name"], f'{profile["employee_code"]} - {profile["job_role"]}')
    PAGE_FUNCTIONS[page]()


if st.session_state.get("token"):
    portal()
else:
    login_page()
