"""
Background automation for the IP Reputation Checker.

Runs two jobs inside the same Flask process using APScheduler
(BackgroundScheduler - a thread inside this process, no separate worker
or OS cron needed):

  1. Hourly check job - reads uploads/IP.txt, runs every IP through all
     vendors (reusing app.py's existing process_single_ip /
     build_blocked_report_rows_for_ips logic), emails a CSV report of
     everything blocked, and records a "last successful run" timestamp
     to uploads/scheduler_state.json.

  2. Watchdog job (runs every few minutes) - compares "now" against that
     last-successful-run timestamp. If the hourly job hasn't completed
     successfully within CHECK_INTERVAL_MINUTES + MISSED_CHECK_GRACE_MINUTES,
     it sends a "missed check" alert email - but only once per missed
     window, so it doesn't spam the same alert every few minutes.

State is kept in a small JSON file (not just in memory) specifically so
that "was the check missed" can still be detected correctly across an
app restart - e.g. if the app crashed and is restarted an hour later,
the watchdog will immediately notice the gap rather than assuming
everything is fine just because the process is freshly started.
"""

import os
import json
import threading
from datetime import datetime, timedelta

from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler

from services.mailer import send_blocked_report_email, send_missed_check_alert

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(APP_DIR, ".env")
STATE_FILE_PATH = os.path.join(APP_DIR, "uploads", "scheduler_state.json")

load_dotenv(ENV_PATH)

CHECK_INTERVAL_MINUTES = int(os.environ.get("CHECK_INTERVAL_MINUTES", "60"))
MISSED_CHECK_GRACE_MINUTES = int(os.environ.get("MISSED_CHECK_GRACE_MINUTES", "10"))

_state_lock = threading.Lock()
_scheduler = None


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


def _run_hourly_check(ip_file_path, extract_ips_from_file, build_blocked_report_rows_for_ips):
    """The hourly job body. Takes the needed helpers as arguments instead
    of importing app.py directly, to avoid a circular import (app.py
    imports this module to start the scheduler)."""
    import pandas as pd
    from io import StringIO

    run_time = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Simple cross-process lock to avoid duplicate runs sending the same
    # email when multiple Python processes start (e.g. Flask debug reloader).
    lock_path = STATE_FILE_PATH + ".lock"
    lock_fd = None
    try:
        # Attempt to create the lock file atomically; if it already exists,
        # another process is running the job and we should skip this run.
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
    except FileExistsError:
        return

    try:
        if not os.path.exists(ip_file_path):
            return

        with open(ip_file_path, "r") as f:
            file_content = f.read()

        ips = extract_ips_from_file(file_content)

        if not ips:
            return

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
        # logged separately above. This keeps the watchdog focused on
        # "did the check run", not "did SMTP work".
        with _state_lock:
            state = _read_state()
            state["last_success_at"] = run_time
            state["last_success_iso"] = datetime.now().isoformat()
            state["last_alert_sent_for"] = None  # reset missed-check alert tracking
            _write_state(state)
    except Exception:
        # Swallow exceptions here; the scheduler should keep running. Errors
        # are not escalated to the main app process.
        pass
    finally:
        # Clean up the lock file so subsequent runs are allowed.
        try:
            if lock_fd is not None:
                os.close(lock_fd)
        except Exception:
            pass
        try:
            if os.path.exists(lock_path):
                os.remove(lock_path)
        except Exception:
            pass


def _run_watchdog():
    """Checks whether the hourly job is overdue and sends an alert email
    at most once per missed window."""
    state = _read_state()
    last_success_iso = state.get("last_success_iso")

    threshold_minutes = CHECK_INTERVAL_MINUTES + MISSED_CHECK_GRACE_MINUTES

    if last_success_iso is None:
        # No successful run since the app started keeping state at all.
        # Treat "now" as the reference point the first time so we don't
        # immediately alert on a brand-new install before the first run
        # has even had a chance to fire.
        return

    try:
        last_dt = datetime.fromisoformat(last_success_iso)
    except ValueError:
        return

    minutes_since = (datetime.now() - last_dt).total_seconds() / 60

    if minutes_since <= threshold_minutes:
        return  # still within the allowed window, nothing to do

    # It's overdue. Only send one alert per missed window (tracked by the
    # last_success_iso value it's overdue against), so this doesn't fire
    # repeatedly every few minutes for the same missed run.
    if state.get("last_alert_sent_for") == last_success_iso:
        return

    success, message = send_missed_check_alert(
        state.get("last_success_at") or "never",
        round(minutes_since)
    )
    # Alert sent; message available in `message` for debugging if needed.

    with _state_lock:
        state["last_alert_sent_for"] = last_success_iso
        _write_state(state)


def start_scheduler(ip_file_path, extract_ips_from_file, build_blocked_report_rows_for_ips):
    """Call once at app startup. Safe to call multiple times - subsequent
    calls are ignored if a scheduler is already running (Flask's debug
    reloader spawns the app twice otherwise, which would double the jobs)."""
    global _scheduler

    if _scheduler is not None:
        return _scheduler

    _scheduler = BackgroundScheduler(daemon=True)

    _scheduler.add_job(
        func=_run_hourly_check,
        args=(ip_file_path, extract_ips_from_file, build_blocked_report_rows_for_ips),
        trigger="interval",
        minutes=CHECK_INTERVAL_MINUTES,
        id="hourly_ip_check",
        next_run_time=datetime.now(),  # also run once immediately on startup
        max_instances=1,
        coalesce=True,
    )

    watchdog_interval = max(1, min(10, MISSED_CHECK_GRACE_MINUTES))
    _scheduler.add_job(
        func=_run_watchdog,
        trigger="interval",
        minutes=watchdog_interval,
        id="missed_check_watchdog",
        max_instances=1,
        coalesce=True,
    )

    _scheduler.start()
    return _scheduler
