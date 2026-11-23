
import sqlite3
from pathlib import Path
from datetime import datetime

import pandas as pd
import streamlit as st

from incident_manager import (
    initialize_incident_tables,
    create_incident,
    link_alert_to_incident,
    add_investigation_note,
    add_evidence,
    update_incident_status,
    assign_incident,
    get_incidents,
    get_incident_details
)


# =========================================================
# CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "minisoc.db"

st.set_page_config(
    page_title="Mini SOC | Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =========================================================
# DATABASE
# =========================================================

def load_alerts():

    if not DATABASE.exists():
        raise FileNotFoundError(
            f"Database not found: {DATABASE}"
        )

    with sqlite3.connect(DATABASE) as connection:

        alerts = pd.read_sql_query(
            """
            SELECT
                id,
                severity,
                rule,
                process,
                command,
                detected_at
            FROM alerts
            ORDER BY id DESC
            """,
            connection
        )

    return alerts


def prepare_timestamps(data):

    data = data.copy()

    data["parsed_time"] = pd.to_datetime(
        data["detected_at"],
        errors="coerce",
        utc=True
    )

    return data


# =========================================================
# ALERT FILTERING
# =========================================================

def filter_alerts(data, severity, time_range, search):

    filtered = data.copy()

    if severity != "ALL":

        filtered = filtered[
            filtered["severity"].str.upper() == severity
        ]

    now = pd.Timestamp.now(tz="UTC")

    if time_range == "LAST 24 HOURS":

        cutoff = now - pd.Timedelta(hours=24)

        filtered = filtered[
            filtered["parsed_time"] >= cutoff
        ]

    elif time_range == "LAST 7 DAYS":

        cutoff = now - pd.Timedelta(days=7)

        filtered = filtered[
            filtered["parsed_time"] >= cutoff
        ]

    elif time_range == "LAST 30 DAYS":

        cutoff = now - pd.Timedelta(days=30)

        filtered = filtered[
            filtered["parsed_time"] >= cutoff
        ]

    if search:

        search = search.strip()

        mask = (
            filtered["process"].fillna("").str.contains(
                search, case=False, regex=False
            )
            |
            filtered["rule"].fillna("").str.contains(
                search, case=False, regex=False
            )
            |
            filtered["command"].fillna("").str.contains(
                search, case=False, regex=False
            )
        )

        filtered = filtered[mask]

    return filtered


def severity_label(severity):

    labels = {
        "HIGH": "🔴 HIGH",
        "MEDIUM": "🟠 MEDIUM",
        "LOW": "🟢 LOW"
    }

    return labels.get(str(severity).upper(), severity)


# =========================================================
# INITIALIZE DATABASE TABLES
# =========================================================

try:
    initialize_incident_tables()

    alerts = load_alerts()
    alerts = prepare_timestamps(alerts)

except Exception as error:

    st.error("Unable to initialize Mini SOC.")

    st.exception(error)

    st.stop()


# =========================================================
# HEADER
# =========================================================

st.title("🛡️ MINI SOC")

st.caption(
    "SECURITY OPERATIONS CENTER | "
    "WINDOWS ENDPOINT MONITORING, "
    "THREAT DETECTION AND INCIDENT RESPONSE"
)

st.divider()


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.title("🛡️ SOC CONTROL PANEL")

st.sidebar.success("Dashboard Online")

st.sidebar.markdown("### Monitoring Environment")

st.sidebar.write("**Endpoint:** Windows")
st.sidebar.write("**Telemetry:** Sysmon")
st.sidebar.write("**Security Logs:** Windows Event Logs")
st.sidebar.write("**Detection Engine:** Python")
st.sidebar.write("**Incident Management:** Enabled")
st.sidebar.write("**Database:** SQLite")

st.sidebar.divider()

if st.sidebar.button(
    "🔄 Refresh Dashboard",
    use_container_width=True
):
    st.rerun()

st.sidebar.divider()

st.sidebar.caption(
    "Mini SOC | Security Monitoring Project"
)


# =========================================================
# MAIN NAVIGATION
# =========================================================

monitoring_tab, incident_tab = st.tabs(
    [
        "🛡️ Security Monitoring",
        "🚨 Incident Response"
    ]
)


# =========================================================
# TAB 1 — SECURITY MONITORING
# =========================================================

with monitoring_tab:

    st.subheader("📊 Security Overview")

    total = len(alerts)

    if total:

        high = int(
            (alerts["severity"].str.upper() == "HIGH").sum()
        )

        medium = int(
            (alerts["severity"].str.upper() == "MEDIUM").sum()
        )

        low = int(
            (alerts["severity"].str.upper() == "LOW").sum()
        )

    else:

        high = medium = low = 0

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Alerts", total)
    c2.metric("🔴 High Severity", high)
    c3.metric("🟠 Medium Severity", medium)
    c4.metric("🟢 Low Severity", low)

    st.divider()

    # -----------------------------------------------------
    # ALERT FILTERS
    # -----------------------------------------------------

    st.subheader("🔎 Alert Investigation")

    f1, f2, f3 = st.columns([1, 1, 2])

    with f1:

        severity_filter = st.selectbox(
            "Severity",
            ["ALL", "HIGH", "MEDIUM", "LOW"],
            key="alert_severity_filter"
        )

    with f2:

        time_filter = st.selectbox(
            "Time Range",
            [
                "ALL TIME",
                "LAST 24 HOURS",
                "LAST 7 DAYS",
                "LAST 30 DAYS"
            ],
            key="alert_time_filter"
        )

    with f3:

        search = st.text_input(
            "Search Alerts",
            placeholder=(
                "Search process, detection rule or command line..."
            ),
            key="alert_search"
        )

    filtered = filter_alerts(
        alerts,
        severity_filter,
        time_filter,
        search
    )

    # -----------------------------------------------------
    # ALERT HISTORY
    # -----------------------------------------------------

    st.subheader("🚨 Security Alert History")

    st.write(
        f"Displaying **{len(filtered)}** of "
        f"**{total}** saved alerts."
    )

    if not filtered.empty:

        display_alerts = filtered[
            [
                "id",
                "severity",
                "rule",
                "process",
                "command",
                "detected_at"
            ]
        ].copy()

        display_alerts["severity"] = (
            display_alerts["severity"].apply(severity_label)
        )

        st.dataframe(
            display_alerts,
            use_container_width=True,
            hide_index=True,
            column_config={
                "id": st.column_config.NumberColumn("Alert ID"),
                "severity": st.column_config.TextColumn("Severity"),
                "rule": st.column_config.TextColumn("Detection Rule"),
                "process": st.column_config.TextColumn("Process"),
                "command": st.column_config.TextColumn("Command Line"),
                "detected_at": st.column_config.TextColumn(
                    "Detection Time"
                )
            }
        )

        csv_data = filtered[
            [
                "id",
                "severity",
                "rule",
                "process",
                "command",
                "detected_at"
            ]
        ].to_csv(index=False).encode("utf-8")

        st.download_button(
            "📥 Export Filtered Alerts (CSV)",
            data=csv_data,
            file_name="minisoc_security_alerts.csv",
            mime="text/csv"
        )

    else:

        st.info("No alerts match your selected filters.")

    # -----------------------------------------------------
    # INDIVIDUAL ALERT INVESTIGATION
    # -----------------------------------------------------

    st.divider()

    st.subheader("🔬 Investigate Individual Alert")

    if not filtered.empty:

        alert_ids = filtered["id"].tolist()

        selected_id = st.selectbox(
            "Select an Alert ID",
            alert_ids,
            key="selected_alert"
        )

        selected = filtered[
            filtered["id"] == selected_id
        ].iloc[0]

        with st.container(border=True):

            st.markdown(
                f"### Alert #{selected['id']}"
            )

            severity = str(selected["severity"]).upper()

            if severity == "HIGH":
                st.error(f"Severity: {severity}")

            elif severity == "MEDIUM":
                st.warning(f"Severity: {severity}")

            elif severity == "LOW":
                st.success(f"Severity: {severity}")

            left, right = st.columns(2)

            with left:

                st.write("**Detection Rule**")
                st.write(selected["rule"])

                st.write("**Process**")
                st.write(selected["process"])

            with right:

                st.write("**Alert ID**")
                st.write(int(selected["id"]))

                st.write("**Detection Time**")
                st.write(selected["detected_at"])

            st.write("**Command Line / Detection Details**")

            st.code(
                str(selected["command"]),
                language="powershell"
            )

    else:

        st.info("No alert is available for investigation.")

    # -----------------------------------------------------
    # ANALYTICS
    # -----------------------------------------------------

    st.divider()

    st.subheader("📈 Security Analytics")

    if not alerts.empty:

        st.markdown("### Severity Distribution")

        severity_counts = (
            alerts["severity"]
            .str.upper()
            .value_counts()
            .reindex(
                ["HIGH", "MEDIUM", "LOW"],
                fill_value=0
            )
        )

        st.bar_chart(severity_counts)

        st.markdown("### Detection Rules")

        rule_counts = (
            alerts["rule"]
            .fillna("Unknown")
            .value_counts()
            .head(10)
            .sort_values()
        )

        st.bar_chart(
            rule_counts,
            horizontal=True
        )

        # Full detection rule count table

        rule_table = (
            alerts["rule"]
            .fillna("Unknown")
            .value_counts()
            .rename_axis("Detection Rule")
            .reset_index(name="Alert Count")
        )

        st.dataframe(
            rule_table,
            use_container_width=True,
            hide_index=True
        )

        # DAILY ACTIVITY

        st.markdown("### 📅 Daily Alert Activity")

        timeline = alerts.dropna(
            subset=["parsed_time"]
        ).copy()

        if not timeline.empty:

            timeline["Date"] = (
                timeline["parsed_time"]
                .dt.strftime("%Y-%m-%d")
            )

            daily_activity = (
                timeline.groupby("Date")
                .size()
                .rename("Alerts")
                .to_frame()
                .sort_index()
            )

            st.bar_chart(daily_activity)

            st.caption(
                "Daily alert counts calculated from saved SQLite records."
            )

        else:

            st.info("No valid timestamps available.")

        # RECENT ALERTS

        st.markdown("### 🛡️ Recent Security Alerts")

        recent = alerts.sort_values(
            "parsed_time",
            ascending=False
        ).head(5)

        recent_display = recent[
            [
                "id",
                "severity",
                "rule",
                "detected_at"
            ]
        ].copy()

        recent_display["severity"] = (
            recent_display["severity"].apply(severity_label)
        )

        st.dataframe(
            recent_display,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info("Analytics will appear when alerts are recorded.")


# =========================================================
# TAB 2 — INCIDENT RESPONSE
# =========================================================

with incident_tab:

    st.subheader("🚨 Incident Response Center")

    st.caption(
        "Manage security incidents, investigate alerts, "
        "record evidence and track response activities."
    )

    try:
        incidents = get_incidents()

    except Exception as error:

        st.error("Unable to retrieve incidents.")
        st.exception(error)
        st.stop()

    # -----------------------------------------------------
    # INCIDENT METRICS
    # -----------------------------------------------------

    incident_total = len(incidents)

    open_count = sum(
        i["status"] == "OPEN" for i in incidents
    )

    investigating_count = sum(
        i["status"] == "INVESTIGATING" for i in incidents
    )

    contained_count = sum(
        i["status"] == "CONTAINED" for i in incidents
    )

    closed_count = sum(
        i["status"] == "CLOSED" for i in incidents
    )

    m1, m2, m3, m4, m5 = st.columns(5)

    m1.metric("Total Cases", incident_total)
    m2.metric("Open", open_count)
    m3.metric("Investigating", investigating_count)
    m4.metric("Contained", contained_count)
    m5.metric("Closed", closed_count)

    st.divider()

    # -----------------------------------------------------
    # CREATE INCIDENT
    # -----------------------------------------------------

    st.subheader("➕ Create New Incident")

    with st.form("create_incident_form"):

        incident_title = st.text_input(
            "Incident Title",
            placeholder="Example: Suspicious PowerShell Activity"
        )

        incident_description = st.text_area(
            "Incident Description",
            placeholder="Describe the suspicious activity and initial findings."
        )

        col1, col2 = st.columns(2)

        with col1:

            incident_severity = st.selectbox(
                "Incident Severity",
                ["HIGH", "MEDIUM", "LOW"]
            )

        with col2:

            assigned_analyst = st.text_input(
                "Assigned Analyst",
                placeholder="SOC Analyst"
            )

        create_submitted = st.form_submit_button(
            "Create Incident",
            use_container_width=True
        )

    if create_submitted:

        try:

            if not incident_title.strip():
                raise ValueError("Incident title is required.")

            result = create_incident(
                incident_title,
                incident_description,
                incident_severity,
                assigned_analyst.strip() or None
            )

            st.success(
                f"Incident created successfully: {result['case_id']}"
            )

            st.rerun()

        except Exception as error:

            st.error(f"Unable to create incident: {error}")

    st.divider()

    # -----------------------------------------------------
    # INCIDENT HISTORY
    # -----------------------------------------------------

    st.subheader("📁 Incident Case History")

    if incidents:

        incident_frame = pd.DataFrame(incidents)

        history_columns = [
            "id",
            "case_id",
            "title",
            "severity",
            "status",
            "assigned_to",
            "created_at"
        ]

        st.dataframe(
            incident_frame[history_columns],
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info("No incidents have been created yet.")

    st.divider()

    # -----------------------------------------------------
    # SELECT INCIDENT
    # -----------------------------------------------------

    st.subheader("🔍 Incident Investigation Workspace")

    if not incidents:

        st.info(
            "Create an incident before using the investigation workspace."
        )

    else:

        incident_options = {
            f"{i['case_id']} | {i['title']}": i["id"]
            for i in incidents
        }

        selected_case = st.selectbox(
            "Select Incident",
            list(incident_options.keys()),
            key="selected_incident"
        )

        incident_id = incident_options[selected_case]

        try:

            details = get_incident_details(incident_id)

            case = details["incident"]

        except Exception as error:

            st.error(f"Unable to load incident: {error}")
            st.stop()

        # -------------------------------------------------
        # INCIDENT DETAILS
        # -------------------------------------------------

        with st.container(border=True):

            st.markdown(
                f"### Case: {case['case_id']}"
            )

            st.write("**Title:**", case["title"])
            st.write("**Description:**", case["description"])
            st.write("**Severity:**", case["severity"])
            st.write("**Status:**", case["status"])
            st.write("**Assigned Analyst:**", case["assigned_to"] or "Unassigned")
            st.write("**Created:**", case["created_at"])
            st.write("**Last Updated:**", case["updated_at"])

            if case["closed_at"]:
                st.write("**Closed:**", case["closed_at"])

            if case["resolution"]:
                st.write("**Resolution:**", case["resolution"])

        # -------------------------------------------------
        # ASSIGN ANALYST
        # -------------------------------------------------

        st.markdown("### 👤 Analyst Assignment")

        with st.form("assign_analyst_form"):

            new_analyst = st.text_input(
                "Assign or Reassign Analyst",
                value=case["assigned_to"] or ""
            )

            assign_submitted = st.form_submit_button(
                "Update Assignment"
            )

        if assign_submitted:

            try:

                assign_incident(
                    incident_id,
                    new_analyst
                )

                st.success("Analyst assignment updated.")
                st.rerun()

            except Exception as error:

                st.error(str(error))

        # -------------------------------------------------
        # LINK ALERTS
        # -------------------------------------------------

        st.markdown("### 🔗 Link Security Alerts")

        if alerts.empty:

            st.info("No security alerts are available.")

        else:

            existing_alert_ids = {
                item["id"] for item in details["alerts"]
            }

            available_alerts = alerts[
                ~alerts["id"].isin(existing_alert_ids)
            ]

            if available_alerts.empty:

                st.info(
                    "All available alerts are already linked to this incident."
                )

            else:

                alert_options = {
                    (
                        f"Alert #{row.id} | "
                        f"{row.rule} | {row.severity}"
                    ): int(row.id)
                    for row in available_alerts.itertuples()
                }

                with st.form("link_alert_form"):

                    selected_alert_label = st.selectbox(
                        "Choose Alert",
                        list(alert_options.keys())
                    )

                    link_submitted = st.form_submit_button(
                        "Link Alert to Incident"
                    )

                if link_submitted:

                    try:

                        link_alert_to_incident(
                            incident_id,
                            alert_options[selected_alert_label]
                        )

                        st.success("Alert linked successfully.")
                        st.rerun()

                    except Exception as error:

                        st.error(str(error))

        # -------------------------------------------------
        # INVESTIGATION NOTES
        # -------------------------------------------------

        st.markdown("### 📝 Investigation Notes")

        with st.form("investigation_note_form"):

            note_analyst = st.text_input(
                "Analyst Name",
                value=case["assigned_to"] or ""
            )

            note_text = st.text_area(
                "Investigation Note",
                placeholder="Record investigation findings, observations and actions."
            )

            note_submitted = st.form_submit_button(
                "Save Investigation Note"
            )

        if note_submitted:

            try:

                add_investigation_note(
                    incident_id,
                    note_analyst,
                    note_text
                )

                st.success("Investigation note saved.")
                st.rerun()

            except Exception as error:

                st.error(str(error))

        # -------------------------------------------------
        # EVIDENCE MANAGEMENT
        # -------------------------------------------------

        st.markdown("### 📂 Evidence Management")

        with st.form("evidence_form"):

            evidence_type = st.selectbox(
                "Evidence Type",
                [
                    "Process Telemetry",
                    "Windows Event Log",
                    "Sysmon Event",
                    "Network Traffic",
                    "Screenshot",
                    "File Hash",
                    "Other"
                ]
            )

            evidence_description = st.text_area(
                "Evidence Description",
                placeholder="Describe the collected evidence and its relevance."
            )

            evidence_path = st.text_input(
                "Evidence File Path (Optional)",
                placeholder="C:\\MiniSOC\\Evidence\\sample.evtx"
            )

            evidence_collector = st.text_input(
                "Collected By",
                value=case["assigned_to"] or ""
            )

            evidence_submitted = st.form_submit_button(
                "Register Evidence"
            )

        if evidence_submitted:

            try:

                add_evidence(
                    incident_id,
                    evidence_type,
                    evidence_description,
                    evidence_collector,
                    evidence_path.strip() or None
                )

                st.success("Evidence record registered.")
                st.rerun()

            except Exception as error:

                st.error(str(error))

        # -------------------------------------------------
        # INCIDENT STATUS MANAGEMENT
        # -------------------------------------------------

        st.markdown("### ⚙️ Incident Status Management")

        valid_statuses = [
            "OPEN",
            "INVESTIGATING",
            "CONTAINED",
            "RESOLVED",
            "CLOSED"
        ]

        with st.form("incident_status_form"):

            new_status = st.selectbox(
                "Update Incident Status",
                valid_statuses,
                index=valid_statuses.index(case["status"])
            )

            resolution_text = st.text_area(
                "Resolution / Closure Notes",
                value=case["resolution"] or "",
                placeholder="Document the resolution and actions taken."
            )

            status_submitted = st.form_submit_button(
                "Update Incident Status"
            )

        if status_submitted:

            try:

                if new_status == "CLOSED" and not resolution_text.strip():
                    raise ValueError(
                        "Provide resolution notes before closing the incident."
                    )

                update_incident_status(
                    incident_id,
                    new_status,
                    resolution_text.strip() or None
                )

                st.success(
                    f"Incident status updated to {new_status}."
                )

                st.rerun()

            except Exception as error:

                st.error(str(error))

        # -------------------------------------------------
        # LINKED ALERTS
        # -------------------------------------------------

        st.divider()

        st.markdown("### 🚨 Linked Security Alerts")

        if details["alerts"]:

            linked_frame = pd.DataFrame(details["alerts"])

            st.dataframe(
                linked_frame[
                    [
                        "id",
                        "severity",
                        "rule",
                        "process",
                        "detected_at"
                    ]
                ],
                use_container_width=True,
                hide_index=True
            )

        else:

            st.info("No alerts linked to this incident.")

        # -------------------------------------------------
        # INVESTIGATION TIMELINE
        # -------------------------------------------------

        st.markdown("### 📋 Investigation Timeline")

        if details["notes"]:

            for note in details["notes"]:

                with st.container(border=True):

                    st.write(
                        f"**Analyst:** {note['analyst']}"
                    )

                    st.caption(note["created_at"])

                    st.write(note["note"])

        else:

            st.info("No investigation notes recorded.")

        # -------------------------------------------------
        # EVIDENCE REGISTER
        # -------------------------------------------------

        st.markdown("### 🗂️ Evidence Register")

        if details["evidence"]:

            evidence_frame = pd.DataFrame(
                details["evidence"]
            )

            st.dataframe(
                evidence_frame[
                    [
                        "id",
                        "evidence_type",
                        "description",
                        "file_path",
                        "collected_by",
                        "collected_at"
                    ]
                ],
                use_container_width=True,
                hide_index=True
            )

        else:

            st.info("No evidence has been registered.")


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.caption(
    "MINI SOC | Windows Security Monitoring and Incident Response | "
    f"Dashboard Load: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
)
