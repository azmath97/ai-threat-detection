"""SOC dashboard page: authentication attacks, the automatic response and manual responses.

Everything shown comes from the backend (`/api/soc/auth/...`); the page computes no scores of its own. The backend enforces the
administrator role on every call, and each state-changing action goes through a confirmation with a reason and an
Idempotency-Key, so a rerun or a double click cannot repeat it.
"""
import uuid

import streamlit as st

from frontend import components as ui
from frontend import soc_components as sc
from frontend.api_client import ApiError

BANDS = {"suspicious": "Watch", "high_risk": "Elevated", "critical": "Alert"}
ACTIONS = {
    "lock_account": ("Lock account", "Locks the account and revokes its sessions. It cannot sign in or use any token until unlocked.", True),
    "unlock_account": ("Unlock account", "Lets the account sign in again. Sessions revoked by the lock stay revoked.", False),
    "revoke_sessions": ("Revoke sessions", "Ends every live session of the account. It can sign in again with its password.", True),
    "block_ip": ("Block address (application level)", "This backend refuses sign-ins and API calls from the address. Not a firewall rule.", True),
    "unblock_ip": ("Remove address block", "Lets the address reach this backend again.", False),
}


def _status_label(status: str) -> str:
    return {"open": "Open", "investigating": "Investigating", "contained": "Contained (automatic or manual response applied)",
            "resolved": "Resolved", "false_positive": "False positive"}.get(status, status)


def request_action(**spec) -> None:
    st.session_state["auth_pending"] = {**spec, "key": uuid.uuid4().hex[:32]}
    st.rerun()


def confirmation_panel(h: dict) -> None:
    p = st.session_state["auth_pending"]
    label, description, needs_confirm = ACTIONS[p["action"]]
    ui.section(f"Confirm: {label}")
    ui.notice("warn" if needs_confirm else "info", "Enforced inside this application only; nothing is sent to a firewall or any other system.")
    ui.kv_table([("Action", label), ("Applies to", p["target"]), ("Incident", f"#{p['incident_id']}" if p.get("incident_id") else "-"),
                 ("What changes", description)])
    reason = st.text_input("Reason (recorded in the audit log)", value=p.get("reason", ""), key="auth_reason")
    minutes = None
    if p["action"] in ("lock_account", "block_ip"):
        limited = st.checkbox("Limit the duration", value=True, key="auth_limited")
        if limited:
            minutes = st.number_input("Minutes", min_value=1, max_value=60 * 24 * 90, value=60, key="auth_minutes")
    confirmed = st.checkbox("I confirm that I want to apply this action", key="auth_confirm") if needs_confirm else True
    a, b, _ = st.columns([1, 1, 4])
    if a.button("Apply", type="primary", key="auth_go", disabled=not confirmed or len(reason.strip()) < 5):
        body = {"action": p["action"], "target": p["target"], "reason": reason.strip(), "confirm": bool(confirmed)}
        if minutes:
            body["minutes"] = int(minutes)
        path = f"/api/soc/auth/incidents/{p['incident_id']}/actions" if p.get("incident_id") else "/api/soc/auth/actions"
        try:
            done = h["api_with_key"](p["key"]).post(path, body)
        except ApiError as exc:
            if exc.status_code == 401:
                h["handle"](exc)
            ui.notice("error", f"Not applied: {exc.detail}")
        else:
            st.session_state["flash_ok"] = f"{done['status_label']}: {done['action_label']} for {done['target']}. {done['result']}" \
                + (" (already recorded; not repeated)" if done.get("replayed") else "")
            st.session_state.pop("auth_pending")
            st.session_state["_cache"] = {}
            st.rerun()
    if b.button("Cancel", key="auth_cancel"):
        st.session_state.pop("auth_pending")
        st.rerun()


def incident_detail(h: dict, incident_id: int) -> None:
    d = h["cached"](f"auth_inc:{incident_id}", f"/api/soc/auth/incidents/{incident_id}")
    if d is None:
        return
    ui.section(f"Incident #{d['id']}: {d['title']}")
    st.markdown(f"{sc.severity_badge(d['severity'])} &nbsp; {d['kind_label']} &nbsp; status: **{_status_label(d['status'])}**",
                unsafe_allow_html=True)
    st.write(d["explanation"])
    st.caption(d["severity_note"])
    e = d["evidence"]
    rows = [("Rule", e.get("rule", "-")), ("Window", f"{e['window_minutes']} minutes" if e.get("window_minutes") else "-"),
            ("Threshold", e.get("threshold", "-")),
            ("Failures / refusals counted", e.get("failures", e.get("failures_before", e.get("refusals", e.get("distinct_objects", "-"))))),
            ("Route", e.get("route", ", ".join(e.get("routes", [])) or "-")),
            ("Objects asked for", ", ".join(e.get("objects", [])) or "-"),
            ("Source addresses", ", ".join(e.get("source_ips", e.get("failure_ips", []))) or d["source_ip"] or "-"),
            ("Accounts involved", ", ".join(e.get("accounts", [])) or d["employee_id"] or "-"),
            ("First seen", h["short"](d["first_seen"]["local"])), ("Last seen", h["short"](d["last_seen"]["local"]))]
    ui.kv_table([(k, str(v)) for k, v in rows])

    ui.section("Response history")
    if d["response_history"]:
        ui.table([{"time": h["short"](a["created_at"]["local"]), "action": a["action_label"], "target": a["target"],
                   "by": a["performed_by"], "status": a["status_label"], "result": a["result"], "policy": a["policy"] or "-"}
                  for a in d["response_history"]],
                 {"time": "Time", "action": "Action", "target": "Target", "by": "Applied by", "status": "Status", "result": "Result",
                  "policy": "Policy"})
    else:
        st.caption("No response has been applied yet.")

    if d.get("export_requests"):
        ui.section("Evidence: the export requests behind this incident")
        ui.table([{"time": h["short"](x["created_at"]["local"]), "resource": x["resource_name"], "action": x["action"],
                   "records": f"{x['records']:,}", "status": x["status_label"], "why": x["detail"]} for x in d["export_requests"]],
                 {"time": "Time", "resource": "Resource", "action": "Action", "records": "Records", "status": "State", "why": "Why it was held"})
    elif d.get("denials"):
        ui.section("Evidence: the refused requests behind this incident")
        ui.table([{"time": h["short"](x["timestamp"]["local"]), "ip": x["source_ip"], "account": x["account"],
                   "request": f"{x['method']} {x['route']}", "object": x["object"] or "-", "status": f"{x['status_code']} {x['meaning']}"}
                  for x in d["denials"]],
                 {"time": "Time", "ip": "Source IP", "account": "Account", "request": "Request", "object": "Object asked for",
                  "status": "Result"})
    else:
        ui.section("Evidence: the sign-in attempts behind this incident")
        ui.table([{"time": h["short"](a["timestamp"]["local"]), "ip": a["source_ip"], "account": a["account"], "outcome": a["outcome"],
                   "reason": a["reason"].replace("_", " ")} for a in d["attempts"]],
                 {"time": "Time", "ip": "Source IP", "account": "Account", "outcome": "Outcome", "reason": "Reason"})

    ui.section("Respond")
    cols = st.columns(4)
    if d["employee_id"]:
        if cols[0].button("Lock account", key=f"ai_lock_{d['id']}", width="stretch"):
            request_action(action="lock_account", target=d["employee_id"], incident_id=d["id"], reason=f"Analyst review of incident #{d['id']}")
        if cols[1].button("Revoke sessions", key=f"ai_rev_{d['id']}", width="stretch"):
            request_action(action="revoke_sessions", target=d["employee_id"], incident_id=d["id"], reason=f"Analyst review of incident #{d['id']}")
    if d["source_ip"]:
        if cols[2].button("Block address", key=f"ai_blk_{d['id']}", width="stretch"):
            request_action(action="block_ip", target=d["source_ip"], incident_id=d["id"], reason=f"Analyst review of incident #{d['id']}")
    with st.form(f"ai_status_{d['id']}"):
        new = st.selectbox("Incident status", ["investigating", "resolved", "false_positive"], format_func=_status_label)
        note = st.text_input("Note (required to resolve or mark a false positive)")
        if st.form_submit_button("Update status"):
            try:
                h["api"]().post(f"/api/soc/auth/incidents/{d['id']}/status", {"status": new, "note": note})
            except ApiError as exc:
                ui.notice("error", exc.detail)
            else:
                st.session_state["_cache"] = {}
                st.rerun()


def export_approvals(h: dict) -> None:
    """Bulk downloads and exports waiting for a security administrator. Approving releases nothing by itself."""
    data = h["cached"]("auth_exports", "/api/soc/auth/export-requests", status="pending") or {}
    rows = data.get("rows", [])
    rules = data.get("rules", {})
    ui.section(f"Export approvals ({len(rows)} waiting)")
    st.caption(f"A request for more than {rules.get('approval_threshold', 0):,} records waits here. An approval is single-use, tied to that account, "
               f"resource and size, and lasts {rules.get('approval_minutes', 0)} minutes. Nothing is released until the employee repeats the request.")
    if not rows:
        st.caption("No export is waiting for approval.")
    for r in rows:
        with st.form(f"export_{r['id']}"):
            st.markdown(f"**#{r['id']} {r['employee_id']}** wants to {r['action']} **{r['records']:,}** records of {r['resource_name']} "
                        f"({h['short'](r['created_at']['local'])}). {r['detail']}")
            note = st.text_input("Decision note (recorded in the audit log)", key=f"export_note_{r['id']}")
            approve, deny, _ = st.columns([1, 1, 4])
            choice = "approve" if approve.form_submit_button("Approve", type="primary") else "deny" if deny.form_submit_button("Deny") else None
            if choice:
                try:
                    h["api"]().post(f"/api/soc/auth/export-requests/{r['id']}/decision", {"decision": choice, "note": note})
                except ApiError as exc:
                    ui.notice("error", exc.detail)
                else:
                    st.session_state["flash_ok"] = f"Export request #{r['id']} {'approved' if choice == 'approve' else 'denied'}."
                    st.session_state["_cache"] = {}
                    st.rerun()


def render(h: dict) -> None:
    ov = h["cached"]("auth_ov", "/api/soc/auth/overview")
    if ov is None:
        return
    a, inc = ov["attempts"], ov["active_incidents"]
    sc.live_note(f"Live - real sign-in attempts of the last {ov['window_hours']} h")
    sc.kpi_grid([
        ("Failed sign-ins", f"{a['failure']:,}", f"from {a['distinct_failing_addresses']} address(es)", "warn" if a["failure"] else "", "alert"),
        ("Successful sign-ins", f"{a['success']:,}", f"last {ov['window_hours']} h", "", "users"),
        ("Refused", f"{a['denied']:,}", "address blocked or account locked", "", "activity"),
        ("Refused requests", f"{ov['refused_requests']['forbidden_403'] + ov['refused_requests']['unauthenticated_401']:,}",
         f"{ov['refused_requests']['forbidden_403']} not permitted (403), {ov['refused_requests']['unauthenticated_401']} without a session (401)",
         "warn" if ov["refused_requests"]["forbidden_403"] + ov["refused_requests"]["unauthenticated_401"] else "", "alert"),
        ("Active incidents", inc["total"], f"{inc['critical']} Alert, {inc['high_risk']} Elevated, {inc['suspicious']} Watch",
         "alert" if inc["critical"] else "warn" if inc["total"] else "", "briefcase"),
        ("Locked accounts", len(ov["locked_accounts"]), "refused by this backend", "warn" if ov["locked_accounts"] else "", "users"),
        ("Blocked addresses", len(ov["blocked_addresses"]), "application level, not a firewall", "warn" if ov["blocked_addresses"] else "", "send"),
    ])
    if ov["pending_approval"]:
        ui.notice("warn", f"{ov['pending_approval']} automatic action(s) are waiting for an analyst because an hourly safety limit was reached.")
    if not ov["policy"]["auto_response"]:
        ui.notice("info", "Automatic response is off: incidents are raised but nothing is locked or blocked without an analyst.")

    export_approvals(h)

    ui.section("Incidents")
    status = h["pselect"]("Show", ["active", "all", "resolved", "false_positive"], "ai_status",
                          fmt={"active": "Active", "all": "All", "resolved": "Resolved", "false_positive": "False positives"}.get)
    rows = (h["cached"](f"auth_list:{status}", "/api/soc/auth/incidents", status=status, limit=100) or {}).get("rows", [])
    if rows:
        ui.table([{"id": f"#{r['id']}", "band": BANDS.get(r["severity"], r["severity"]), "kind": r["kind_label"],
                   "subject": r["employee_id"] or r["source_ip"] or "-", "ip": r["source_ip"] or "-", "n": r["attempts"],
                   "last": h["short"](r["last_seen"]["local"]), "status": _status_label(r["status"]).split(" (")[0],
                   "actions": r["actions"]} for r in rows],
                 {"id": "ID", "band": "Severity band", "kind": "Pattern", "subject": "Account / address", "ip": "Source address",
                  "n": "Attempts", "last": "Last seen", "status": "Status", "actions": "Responses"}, result_column="band")
        chosen = h["pselect"]("Open incident", [r["id"] for r in rows], "ai_open",
                              fmt=lambda i: next(f"#{r['id']} - {r['title']}" for r in rows if r["id"] == i))
        incident_detail(h, chosen)
    else:
        ui.notice("ok", "No incidents in this view. Detection runs on every real sign-in attempt.")

    ui.section(f"Locked accounts ({len(ov['locked_accounts'])})")
    for acc in ov["locked_accounts"]:
        c = st.columns([2, 4, 3, 2], vertical_alignment="center")
        c[0].write(f"**{acc['employee_id']}** {acc['name']}")
        c[1].caption(acc["reason"] or "-")
        c[2].caption(("Automatic lock, ends " + h["short"](acc["expires_at"]["local"])) if acc["automatic"] and acc["expires_at"]["local"]
                     else f"Locked by {acc['locked_by'] or '-'} until unlocked")
        if c[3].button("Unlock", key=f"unlock_{acc['employee_id']}", width="stretch"):
            request_action(action="unlock_account", target=acc["employee_id"], reason="Identity verified, incident reviewed")
    if not ov["locked_accounts"]:
        st.caption("No account is locked.")

    ui.section(f"Blocked addresses ({len(ov['blocked_addresses'])})")
    for blk in ov["blocked_addresses"]:
        c = st.columns([2, 4, 3, 2], vertical_alignment="center")
        c[0].write(f"**{blk['ip']}**")
        c[1].caption(blk["reason"] or "-")
        c[2].caption(blk["status"] + (", ends " + h["short"](blk["expires_at"]["local"]) if blk["expires_at"]["local"] else ""))
        if c[3].button("Remove block", key=f"unblock_{blk['ip']}", width="stretch"):
            request_action(action="unblock_ip", target=blk["ip"], reason="Block reviewed and released")
    if not ov["blocked_addresses"]:
        st.caption("No address is blocked.")

    ui.section("Recent sign-in attempts")
    attempts = (h["cached"]("auth_attempts", "/api/soc/auth/attempts", minutes=240, limit=60) or {}).get("rows", [])
    ui.table([{"time": h["short"](r["timestamp"]["local"]), "ip": r["source_ip"], "account": r["account"], "outcome": r["outcome"],
               "reason": r["reason"].replace("_", " ")} for r in attempts],
             {"time": "Time", "ip": "Source IP", "account": "Account (unknown names are hashed)", "outcome": "Outcome", "reason": "Reason"})

    ui.section("Recent refused requests")
    denied = (h["cached"]("auth_denials", "/api/soc/auth/denials", minutes=240, limit=60) or {}).get("rows", [])
    ui.table([{"time": h["short"](r["timestamp"]["local"]), "ip": r["source_ip"], "account": r["account"],
               "request": f"{r['method']} {r['route']}", "object": r["object"] or "-", "status": f"{r['status_code']} {r['meaning']}"}
              for r in denied],
             {"time": "Time", "ip": "Source IP", "account": "Account", "request": "Request", "object": "Object asked for",
              "status": "Result"})

    ui.section("Response history")
    history = (h["cached"]("auth_actions", "/api/soc/auth/actions", limit=60) or {}).get("rows", [])
    ui.table([{"time": h["short"](r["created_at"]["local"]), "action": r["action_label"], "target": r["target"], "by": r["performed_by"],
               "status": r["status_label"], "result": r["result"]} for r in history],
             {"time": "Time", "action": "Action", "target": "Target", "by": "Applied by", "status": "Status", "result": "Result"})

    with st.expander("Detection and response policy in force"):
        p = ov["policy"]
        ui.kv_table([
            ("Account lock", f"{p['account_lockout_threshold']} failures in {p['account_window_minutes']} min "
                             f"({p['known_ip_lockout_threshold']} if all from the account's own addresses); locks for {p['account_lock_minutes']} min"),
            ("Address burst", f"{p['ip_alert_failures']} failures in {p['ip_alert_window_minutes']} min: Elevated; "
                              f"{p['ip_block_threshold']} in {p['ip_block_window_minutes']} min: Alert and block for {p['ip_block_minutes']} min"),
            ("Credential stuffing", f"{p['stuffing_accounts_alert']} accounts from one address in {p['stuffing_window_minutes']} min: Elevated; "
                                    f"{p['stuffing_accounts_critical']}: Alert and block"),
            ("Refused requests", f"{p['forbidden_alert']} refusals (403) by one account in {p['access_window_minutes']} min: Elevated, "
                                 f"{p['forbidden_critical']}: Alert and the session ends and the account locks; {p['idor_alert']} different records "
                                 f"on one route: probing (Elevated), {p['idor_critical']}: Alert; {p['unauth_alert']} requests without a "
                                 f"session from one address: Elevated, {p['unauth_critical']}: Alert and block"),
            ("Exports and downloads", f"more than {p['export_approval_threshold']:,} records in one request needs a security approval; never more than "
                                      f"{p['export_hard_limit']:,}; {p['export_hourly_limit']:,} records per account per hour "
                                      f"({p['export_owner_multiplier']}x for staff who own the data); {p['export_attempt_alert']} held or refused "
                                      f"requests in {p['export_attempt_window_minutes']} min: Elevated, {p['export_attempt_critical']}: Alert and the "
                                      "session ends and the account locks"),
            ("Safety limits", f"at most {p['max_auto_locks_per_hour']} automatic locks and {p['max_auto_blocks_per_hour']} automatic blocks per hour; "
                              "administrators are never locked automatically; private and protected addresses are never blocked"),
            ("Note", p["note"]),
        ])


def page(**h) -> None:
    ui.page_header("Authentication Defence", "Real sign-in attempts, detected attacks and the response applied")
    h["refresh_token"]()
    ui.notice("info", "Responses are enforced inside this application: a locked account or blocked address is refused by this backend. "
                      "They are not firewall rules and do not stop traffic reaching the host.")
    message = st.session_state.pop("flash_ok", None)
    if message:
        ui.notice("ok", message)
    if st.session_state.get("auth_pending"):
        confirmation_panel(h)
    h["live"](lambda: render(h))
