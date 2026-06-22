"""
Automated check logic for the IP Reputation Checker - triggered by an
external HTTP call instead of an always-on background scheduler.

Why this design: free hosting tiers (Render, Railway, PythonAnywhere
free tier, etc.) either spin a process down when idle or don't
guarantee a background thread (like APScheduler's BackgroundScheduler)
keeps running indefinitely. Relying on an in-process timer means the
hourly check silently stops the moment the app sleeps or restarts.

Instead, this module exposes one function - run_scheduled_check() -
that app.py wires up to a protected route (/run-scheduled-check). An
external free cron service (e.g. cron-job.org) calls that URL once an
hour. The HTTP request itself is what wakes a sleeping free-tier app
and triggers the check - no background thread needs to survive.

Two things happen on every call to run_scheduled_check():

  1. Hourly check - reads uploads/IP.txt, runs every IP through all
     vendors (reusing app.py's process_single_ip /
     build_blocked_report_rows_for_ips logic), emails a CSV report of
     everything blocked, and records a "last successful run" timestamp
     to uploads/scheduler_state.json.

  2. Watchdog check - compares "now" against that last-successful-run
     timestamp. If too much time has passed since the last successful
     run (more than CHECK_INTERVAL_MINUTES + MISSED_CHECK_GRACE_MINUTES),
     a "missed check" alert email is sent - but only once per missed
     window, so it doesn't spam the same alert on every subsequent call.

State is kept in a small JSON file (not just in memory) so that "was
the check missed" can still be detected correctly across an app
restart or a free-tier sleep/wake cycle.
"""

import os
import json
import threading
from datetime import datetime, timedelta

from dotenv import load_dotenv

from services.mailer import send_blocked_report_email, send_missed_check_alert

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(APP_DIR, ".env")
STATE_FILE_PATH = os.path.join(APP_DIR, "uploads", "scheduler_state.json")

load_dotenv(ENV_PATH)

CHECK_INTERVAL_MINUTES = int(os.environ.get("CHECK_INTERVAL_MINUTES", "60"))
MISSED_CHECK_GRACE_MINUTES = int(os.environ.get("MISSED_CHECK_GRACE_MINUTES", "10"))
SCHEDULED_CHECK_TOKEN = os.environ.get("SCHEDULED_CHECK_TOKEN", "")

_state_lock = threading.Lock()


def _read_state():
    """Read the persisted scheduler state from disk. Returns a dict with
    safe defaults if the file doesn't exist yet or can't be parsed."""
    default_state = {
        "last_success_at": None,
        "last_success_iso": None,
        "last_alert_sent_for": None,
    }
    if not os.path.exists(STATE_FILE_PATH):
        return default_state
    try:
        with open(STATE_FILE_PATH, "r") as f:
            data = json.load(f)
        for key in default_state:
            data.setdefault(key, default_state[key])
        return data
    except (json.JSONDecodeError, OSError):
        return default_state


def _write_state(state):
    os.makedirs(os.path.dirname(STATE_FILE_PATH), exist_ok=True)
    with open(STATE_FILE_PATH, "w") as f:
        json.dump(state, f, indent=2)


def get_scheduler_status():
    """Used by app.py to show a small status panel on the homepage."""
    state = _read_state()
    last_success_iso = state.get("last_success_iso")

    next_check_eta = "N/A"
    if last_success_iso:
        try:
            last_dt = datetime.fromisoformat(last_success_iso)
            next_dt = last_dt + timedelta(minutes=CHECK_INTERVAL_MINUTES)
            next_check_eta = next_dt.strftime("%Y-%m-%d %H:%M")
        except ValueError:
            next_check_eta = "N/A"

    return {
        "last_success_at": state.get("last_success_at") or "Never run yet",
        "next_check_eta": next_check_eta,
        "interval_minutes": CHECK_INTERVAL_MINUTES,
    }


def is_token_valid(provided_token):
    """Compares the token in the request against SCHEDULED_CHECK_TOKEN
    from .env. If no token is configured at all, the endpoint refuses
    every request (fail closed) rather than running unauthenticated."""
    if not SCHEDULED_CHECK_TOKEN:
        return False
    return provided_token == SCHEDULED_CHECK_TOKEN


def _send_blocked_report(ip_file_path, extract_ips_from_file, build_blocked_report_rows_for_ips):
    """The hourly-check body. Takes the needed helpers as arguments
    instead of importing app.py directly, to avoid a circular import
    (app.py imports this module to wire up the route)."""
    import pandas as pd
    from io import StringIO

    run_time = datetime.now().strftime("%Y-%m-%d %H:%M")

    if not os.path.exists(ip_file_path):
        return False, f"IP file not found at {ip_file_path}, skipping this run."

    with open(ip_file_path, "r") as f:
        file_content = f.read()

    ips = extract_ips_from_file(file_content)

    if not ips:
        return False, "No valid IPs found in IP.txt, skipping this run."

    report_rows, blocked_ip_count = build_blocked_report_rows_for_ips(ips)

    columns = [
        "Date of Analyzing the IP", "IP", "Blocked Vendor Name",
        "Status", "Reason", "Last Reported Date", "Total Reports"
    ]
    df = pd.DataFrame(report_rows, columns=columns)
    csv_buffer = StringIO()
    df.to_csv(csv_buffer, index=False)

    filename = f"Hourly_Blocked_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"

    summary = {
        "run_time": run_time,
        "total_ips": len(ips),
        "blocked_ips": blocked_ip_count,
    }

    success, message = send_blocked_report_email(csv_buffer.getvalue(), filename, summary)

    # Mark this run as successful regardless of whether the email send
    # itself succeeded - the *check* ran; email delivery issues are
    # reported separately. This keeps the watchdog focused on
    # "did the check run", not "did SMTP work".
    with _state_lock:
        state = _read_state()
        state["last_success_at"] = run_time
        state["last_success_iso"] = datetime.now().isoformat()
        state["last_alert_sent_for"] = None  # reset missed-check alert tracking
        _write_state(state)

    return True, f"Checked {len(ips)} IP(s), {blocked_ip_count} blocked. Email: {message}"


def _check_watchdog():
    """Checks whether the hourly check is overdue and sends an alert
    email at most once per missed window. Called on every hit to
    /run-scheduled-check, right after the hourly check itself, so a
    missed run is detected the very next time the cron service calls in."""
    state = _read_state()
    last_success_iso = state.get("last_success_iso")

    threshold_minutes = CHECK_INTERVAL_MINUTES + MISSED_CHECK_GRACE_MINUTES

    if last_success_iso is None:
        return "No prior successful run recorded yet - nothing to compare against."

    try:
        last_dt = datetime.fromisoformat(last_success_iso)
    except ValueError:
        return "Could not parse last success timestamp."

    minutes_since = (datetime.now() - last_dt).total_seconds() / 60

    if minutes_since <= threshold_minutes:
        return f"OK - last successful run was {round(minutes_since)} min ago (threshold {threshold_minutes} min)."

    if state.get("last_alert_sent_for") == last_success_iso:
        return f"Overdue ({round(minutes_since)} min) but alert already sent for this gap."

    success, message = send_missed_check_alert(
        state.get("last_success_at") or "never",
        round(minutes_since)
    )

    with _state_lock:
        state["last_alert_sent_for"] = last_success_iso
        _write_state(state)

    return f"Overdue ({round(minutes_since)} min) - alert email: {message}"


def run_scheduled_check(ip_file_path, extract_ips_from_file, build_blocked_report_rows_for_ips):
    """Entry point called by the /run-scheduled-check route. Runs the
    hourly check, then the watchdog check, and returns a small dict
    summarizing what happened (useful for the route's JSON response and
    for the cron service's logs)."""
    try:
        check_ok, check_message = _send_blocked_report(
            ip_file_path, extract_ips_from_file, build_blocked_report_rows_for_ips
        )
    except Exception as e:
        check_ok, check_message = False, f"Hourly check failed: {e}"

    watchdog_message = _check_watchdog()

    return {
        "check_ran": check_ok,
        "check_message": check_message,
        "watchdog_message": watchdog_message,
        "timestamp": datetime.now().isoformat(),
    }

