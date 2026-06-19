"""
Email sending for the IP Reputation Checker's automated hourly check.

Uses Gmail's free SMTP server via Python's built-in smtplib - no paid
email API, no extra account beyond a Gmail address + an "App Password"
(see .env.example for setup steps).

Two emails this module can send:
  - send_blocked_report_email(...) - the hourly "here's what's blocked"
    report, with the CSV attached.
  - send_missed_check_alert(...)   - sent by the watchdog job if the
    hourly check hasn't successfully run recently.

Credentials are read from environment variables (loaded from .env by
services/scheduler.py at startup via python-dotenv), never hard-coded.
"""

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

from dotenv import load_dotenv

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(_APP_DIR, ".env"))


def _smtp_settings():
    """Read SMTP/email settings from environment variables."""
    return {
        "sender": os.environ.get("MAIL_SENDER", ""),
        "app_password": os.environ.get("MAIL_APP_PASSWORD", ""),
        "recipient": os.environ.get("MAIL_RECIPIENT", ""),
        "server": os.environ.get("SMTP_SERVER", "smtp.gmail.com"),
        "port": int(os.environ.get("SMTP_PORT", "587")),
    }


def _settings_are_valid(settings):
    """Basic sanity check so we fail with a clear message instead of a
    confusing SMTP error when .env hasn't been filled in yet."""
    missing = [
        key for key in ("sender", "app_password", "recipient")
        if not settings.get(key) or "your" in settings.get(key, "").lower()
    ]
    return len(missing) == 0, missing


def _send_email(subject, body_text, attachment_bytes=None, attachment_filename=None):
    """Shared low-level send routine used by both email types below.

    Returns (success: bool, message: str) instead of raising, so the
    scheduler can log failures without crashing the background job.
    """
    settings = _smtp_settings()
    valid, missing = _settings_are_valid(settings)

    if not valid:
        return False, (
            f"Email not sent - missing/placeholder .env values for: {', '.join(missing)}. "
            f"Fill in MAIL_SENDER, MAIL_APP_PASSWORD, and MAIL_RECIPIENT in your .env file."
        )

    msg = MIMEMultipart()
    msg["From"] = settings["sender"]
    msg["To"] = settings["recipient"]
    msg["Subject"] = subject
    msg.attach(MIMEText(body_text, "plain"))

    if attachment_bytes is not None and attachment_filename:
        part = MIMEApplication(attachment_bytes, Name=attachment_filename)
        part["Content-Disposition"] = f'attachment; filename="{attachment_filename}"'
        msg.attach(part)

    try:
        with smtplib.SMTP(settings["server"], settings["port"], timeout=30) as server:
            server.starttls()
            server.login(settings["sender"], settings["app_password"])
            server.sendmail(settings["sender"], settings["recipient"], msg.as_string())
        return True, "Email sent successfully."
    except smtplib.SMTPAuthenticationError:
        return False, (
            "SMTP authentication failed. Double check MAIL_SENDER/MAIL_APP_PASSWORD "
            "in .env - remember this must be a Gmail 'App Password', not your normal "
            "Gmail login password."
        )
    except Exception as e:
        return False, f"Failed to send email: {e}"


def send_blocked_report_email(csv_text, filename, summary):
    """Send the hourly blocked-report email with the CSV attached.

    summary: dict with keys like total_ips, blocked_ips, run_time - used
    to write a short human-readable body above the attachment.
    """
    subject = f"IP Reputation Checker - Hourly Report ({summary.get('run_time', '')})"

    if summary.get("blocked_ips", 0) > 0:
        headline = (
            f"{summary.get('blocked_ips')} of {summary.get('total_ips')} IP(s) "
            f"were flagged as Blocked by at least one vendor this run."
        )
    else:
        headline = (
            f"All clear - none of the {summary.get('total_ips')} IP(s) checked "
            f"were flagged as Blocked by any vendor this run."
        )

    body = (
        f"Automated IP Reputation Check\n"
        f"Run time: {summary.get('run_time', 'N/A')}\n"
        f"IPs checked: {summary.get('total_ips', 'N/A')}\n"
        f"IPs with at least one Blocked vendor: {summary.get('blocked_ips', 'N/A')}\n\n"
        f"{headline}\n\n"
        f"Full per-vendor blocked details are attached as a CSV.\n"
    )

    csv_bytes = csv_text.encode("utf-8")
    return _send_email(subject, body, attachment_bytes=csv_bytes, attachment_filename=filename)


def send_missed_check_alert(last_success_time, minutes_since):
    """Send the watchdog alert when the hourly check hasn't run on time."""
    subject = "ALERT: IP Reputation Checker - Hourly Check Missed"

    body = (
        f"The automated hourly IP check has NOT run successfully on schedule.\n\n"
        f"Last successful run: {last_success_time or 'never'}\n"
        f"Time since last successful run: {minutes_since} minute(s)\n\n"
        f"Please check that the application is still running and that the "
        f"network/API keys are working correctly.\n"
    )

    return _send_email(subject, body)
