from io import StringIO, BytesIO
from flask import Flask, render_template, request, send_file, Response, flash, redirect, session, jsonify
from services.main_file import abuseipdb, virustotal
from services.extra_vendors import greynoise, ipqualityscore, shodan_internetdb
from services.scheduler import start_scheduler, get_scheduler_status
from ipwhois import IPWhois
import pandas as pd
import ipaddress
from werkzeug.utils import secure_filename
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = "aathi24"

latest_results = []
latest_ip = None
latest_analyzed_at = None
batch_ips = []
batch_results = {}
current_batch_index = 0

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'csv'}

APP_DIR = os.path.dirname(os.path.abspath(__file__))
IP_FILE_PATH = os.path.join(APP_DIR, '..', 'uploads', 'IP.txt')

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

@app.after_request
def add_no_cache_headers(response):
    """Force every page to be re-fetched from the server instead of being
    served from the browser's cache. Without this, navigating between batch
    IPs (or using browser back/forward) can show a stale, previously-loaded
    IP's page instead of the one actually requested."""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_ips_from_file(file_content):
    """Extract valid IPs from file content"""
    ips = []
    lines = file_content.strip().split('\n')
    
    for line in lines:
        ip = line.strip()
        if ip:
            try:
                ipaddress.ip_address(ip)
                ips.append(ip)
            except ValueError:
                continue
    
    return ips

def process_single_ip(ip):
    """Process a single IP and return results"""
    analyzed_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    try:
        abuse_data = abuseipdb(ip)
        vt_results = virustotal(ip) or []

        extra_rows = []

        if abuse_data:
            extra_rows.append({
                "Vendor": abuse_data.get("Vendor", "AbuseIPDB"),
                "Blocked": abuse_data.get("Blocked", "Safe"),
                "Reason": abuse_data.get("Reason", "Nil"),
                "Total_Reports": abuse_data.get("Total_Reports", "N/A"),
                "Last_Reported": abuse_data.get("Last_Reported", "Nil"),
                "Link": abuse_data.get("Link", f"https://www.abuseipdb.com/check/{ip}")
            })

        for fetch_vendor in (greynoise, ipqualityscore, shodan_internetdb):
            row = fetch_vendor(ip)
            if row:
                extra_rows.append(row)

        results = extra_rows + vt_results

        total = len(results)
        blocked = len([x for x in results if x["Blocked"] == "Blocked"])
        safe = total - blocked

        if blocked > 0:
            verdict = "Suspicious"
        else:
            verdict = "Safe"

        if vt_results:
            total_reports = vt_results[0].get("Total_Reports")
            last_reported = vt_results[0].get("Last_Reported")
        elif abuse_data:
            total_reports = abuse_data.get("Total_Reports")
            last_reported = abuse_data.get("Last_Reported")
        else:
            total_reports = "N/A"
            last_reported = "N/A"

        return {
            'results': results,
            'total': total,
            'safe': safe,
            'blocked': blocked,
            'verdict': verdict,
            'total_reports': total_reports,
            'last_reported': last_reported,
            'analyzed_at': analyzed_at,
            'error': None
        }
    except Exception as e:
        return {
            'results': [],
            'total': 0,
            'safe': 0,
            'blocked': 0,
            'verdict': 'Error',
            'total_reports': 'N/A',
            'last_reported': 'N/A',
            'analyzed_at': analyzed_at,
            'error': str(e)
        }

@app.route("/", methods=["GET", "POST"])

def home():

    global latest_results, latest_ip, latest_analyzed_at, batch_ips, batch_results, current_batch_index

    if request.method == "POST":

        # Single IP processing
        ip = request.form.get("ip", "").strip()

        if not ip:
            flash("Please enter an IP address.", "danger")
            return redirect("/")

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            flash("Please enter a valid IPv4 or IPv6 address.", "danger")
            return redirect("/")

        data = process_single_ip(ip)
        latest_results = data['results']
        latest_ip = ip
        latest_analyzed_at = data['analyzed_at']

        batch_ips = []
        batch_results = {}
        current_batch_index = 0

        return render_template(
            "result.html", 
            results = data['results'], 
            total = data['total'], 
            safe = data['safe'], 
            blocked = data['blocked'], 
            ip = ip,
            verdict = data['verdict'],
            total_reports = data['total_reports'],
            last_reported = data['last_reported'],
            error = data['error'],
            is_batch = False,
            batch_info = None
            )
    
    return render_template("index.html", scheduler_status=get_scheduler_status())

@app.route("/run-batch")
def run_batch():
    """Read the IP list directly from the internal IP.txt file on the
    server (uploads/IP.txt) and start a fresh batch analysis - no file
    upload from the user needed."""
    global batch_ips, batch_results, current_batch_index

    if not os.path.exists(IP_FILE_PATH):
        flash(f"IP file not found at '{IP_FILE_PATH}'.", "danger")
        return redirect("/")

    try:
        with open(IP_FILE_PATH, "r") as f:
            file_content = f.read()
    except Exception as e:
        flash(f"Error reading IP file: {str(e)}", "danger")
        return redirect("/")

    ips = extract_ips_from_file(file_content)

    if not ips:
        flash("No valid IPs found in the IP file.", "danger")
        return redirect("/")

    batch_ips = ips
    batch_results = {}
    current_batch_index = 0

    flash(f"Loaded {len(ips)} IP(s) from the file.", "success")

    return redirect("/batch/0")

@app.route("/batch/<int:index>")
def view_batch_ip(index):
    """View results for a specific IP in batch"""
    global batch_ips, batch_results, current_batch_index, latest_results, latest_ip, latest_analyzed_at
    
    if not batch_ips or index < 0 or index >= len(batch_ips):
        flash("Invalid batch index.", "danger")
        return redirect("/")
    
    current_batch_index = index
    ip = batch_ips[index]
    
    # Process IP if not already cached
    if ip not in batch_results:
        batch_results[ip] = process_single_ip(ip)
    
    data = batch_results[ip]
    latest_results = data['results']
    latest_ip = ip
    latest_analyzed_at = data['analyzed_at']
    
    batch_info = {
        'current': index + 1,
        'total': len(batch_ips),
        'has_next': index < len(batch_ips) - 1,
        'has_prev': index > 0
    }
    
    return render_template(
        "result.html", 
        results = data['results'], 
        total = data['total'], 
        safe = data['safe'], 
        blocked = data['blocked'], 
        ip = ip,
        verdict = data['verdict'],
        total_reports = data['total_reports'],
        last_reported = data['last_reported'],
        error = data['error'],
        is_batch = True,
        batch_info = batch_info
        )

def get_vendor_rows(vendor_name):
    """Collect a single vendor's result for every IP checked so far.

    - In batch mode, this looks across every IP in the batch that has
      already been viewed/cached (results are still fetched lazily, one
      IP at a time, just like the rest of the batch flow).
    - In single-IP mode, it returns just that one IP's row.
    """
    rows = []

    if batch_ips:
        for ip in batch_ips:
            data = batch_results.get(ip)
            if not data:
                continue
            for row in data['results']:
                if row.get('Vendor') == vendor_name:
                    rows.append({
                        'ip': ip,
                        'status': row.get('Blocked', 'N/A'),
                        'reason': row.get('Reason', 'Nil'),
                        'last_reported': row.get('Last_Reported', 'Nil'),
                        'total_reports': row.get('Total_Reports', 'N/A')
                    })
                    break

    elif latest_ip and latest_results:
        for row in latest_results:
            if row.get('Vendor') == vendor_name:
                rows.append({
                    'ip': latest_ip,
                    'status': row.get('Blocked', 'N/A'),
                    'reason': row.get('Reason', 'Nil'),
                    'last_reported': row.get('Last_Reported', 'Nil'),
                    'total_reports': row.get('Total_Reports', 'N/A')
                })
                break

    return rows

@app.route("/vendor/<vendor_name>")
def vendor_details(vendor_name):
    """Show one vendor's status/reason/last-reported info across all the
    IPs that have been checked, instead of sending the user to the
    vendor's own external website."""

    rows = get_vendor_rows(vendor_name)

    if not rows:
        flash(f"No results found for vendor '{vendor_name}'.", "danger")
        return redirect("/")

    return render_template(
        "vendor_details.html",
        vendor_name=vendor_name,
        rows=rows,
        is_batch=bool(batch_ips)
    )

def whois_lookup(ip):

    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        network = result.get("network", {})

        return {

            # ASN Information
            "asn": result.get("asn", "N/A"),
            "asn_registry": result.get("asn_registry", "N/A"),
            "asn_cidr": result.get("asn_cidr", "N/A"),
            "asn_country_code": result.get("asn_country_code", "N/A"),
            "asn_date": result.get("asn_date", "N/A"),
            "asn_description": result.get("asn_description", "N/A"),

            # Network Information
            "network_name": network.get("name", "N/A"),
            "network_handle": network.get("handle", "N/A"),
            "network_type": network.get("type", "N/A"),
            "country": network.get("country", "N/A"),
            "cidr": network.get("cidr", "N/A"),
            "start_address": network.get("start_address", "N/A"),
            "end_address": network.get("end_address", "N/A"),

            # Registration Information
            "created": network.get("events", [{}])[0].get("timestamp", "N/A")
            if network.get("events") else "N/A",

            # Raw Data
            "remarks": network.get("remarks", "N/A"),

        }

    except Exception:

        return {

            "asn": "N/A",
            "asn_registry": "N/A",
            "asn_cidr": "N/A",
            "asn_country_code": "N/A",
            "asn_date": "N/A",
            "asn_description": "N/A",

            "network_name": "N/A",
            "network_handle": "N/A",
            "network_type": "N/A",
            "country": "N/A",
            "cidr": "N/A",
            "start_address": "N/A",
            "end_address": "N/A",

            "created": "N/A",
            "remarks": "N/A"
        }

@app.route("/download/<ip>")
def download_csv(ip):

    global latest_results

    df = pd.DataFrame(latest_results)

    csv_buffer = StringIO()

    df.to_csv(csv_buffer, index=False)

    return Response(
        csv_buffer.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            f"attachment; filename={ip}_results.csv"
        }
    )

def build_blocked_report_rows():
    """Build the list of blocked-vendor rows for whichever mode is active
    (single-IP or batch), reusing already-cached results where possible.

    This is the shared logic behind both:
      - the manual "Download Blocked Report" button (download_blocked_report)
      - the automated hourly scheduler job (services/scheduler.py)

    Returns (report_rows, mode, ip_count) where mode is "batch", "single",
    or "none" (nothing has been scanned yet in this process).
    """
    global batch_ips, batch_results, latest_ip, latest_results, latest_analyzed_at

    report_rows = []

    if batch_ips:
        ips = batch_ips

        for ip in ips:
            if ip not in batch_results:
                batch_results[ip] = process_single_ip(ip)

        for ip in ips:
            data = batch_results.get(ip)
            if not data:
                continue
            analyzed_at = data.get('analyzed_at', datetime.now().strftime("%Y-%m-%d %H:%M"))
            for row in data['results']:
                if row.get('Blocked') == 'Blocked':
                    report_rows.append({
                        "Date of Analyzing the IP": analyzed_at,
                        "IP": ip,
                        "Blocked Vendor Name": row.get('Vendor', 'N/A'),
                        "Status": row.get('Blocked', 'N/A'),
                        "Reason": row.get('Reason', 'Nil'),
                        "Last Reported Date": row.get('Last_Reported', 'Nil'),
                        "Total Reports": row.get('Total_Reports', 'N/A')
                    })

        return report_rows, "batch", len(ips)

    elif latest_ip and latest_results:
        analyzed_at = latest_analyzed_at or datetime.now().strftime("%Y-%m-%d %H:%M")

        for row in latest_results:
            if row.get('Blocked') == 'Blocked':
                report_rows.append({
                    "Date of Analyzing the IP": analyzed_at,
                    "IP": latest_ip,
                    "Blocked Vendor Name": row.get('Vendor', 'N/A'),
                    "Status": row.get('Blocked', 'N/A'),
                    "Reason": row.get('Reason', 'Nil'),
                    "Last Reported Date": row.get('Last_Reported', 'Nil'),
                    "Total Reports": row.get('Total_Reports', 'N/A')
                })

        return report_rows, "single", 1

    return report_rows, "none", 0


def build_blocked_report_rows_for_ips(ips):
    """Like build_blocked_report_rows(), but always processes a specific
    list of IPs fresh against the cache (used by the scheduler, which
    always wants the full uploads/IP.txt list regardless of whatever
    single-IP/batch state the web UI happens to be in).

    Does NOT touch the global batch_ips/current_batch_index/etc. used by
    the web UI, so it can run in the background without disturbing
    whatever a user is currently looking at in the browser.
    """
    global batch_results

    report_rows = []
    blocked_ip_count = 0

    for ip in ips:
        if ip not in batch_results:
            batch_results[ip] = process_single_ip(ip)

        data = batch_results.get(ip)
        if not data:
            continue

        analyzed_at = data.get('analyzed_at', datetime.now().strftime("%Y-%m-%d %H:%M"))
        ip_was_blocked = False

        for row in data['results']:
            if row.get('Blocked') == 'Blocked':
                ip_was_blocked = True
                report_rows.append({
                    "Date of Analyzing the IP": analyzed_at,
                    "IP": ip,
                    "Blocked Vendor Name": row.get('Vendor', 'N/A'),
                    "Status": row.get('Blocked', 'N/A'),
                    "Reason": row.get('Reason', 'Nil'),
                    "Last Reported Date": row.get('Last_Reported', 'Nil'),
                    "Total Reports": row.get('Total_Reports', 'N/A')
                })

        if ip_was_blocked:
            blocked_ip_count += 1

    return report_rows, blocked_ip_count


@app.route("/download_blocked_report")
def download_blocked_report():
    """Build a CSV of every vendor that blocked an IP.

    - Single-IP scan (batch_ips is empty): report covers ONLY that one IP,
      built straight from the results already fetched for it - no extra
      vendor API calls, so this is instant.
    - Batch run from the file (batch_ips is populated): report covers
      every IP in the file, processing (and caching) any IP not yet
      analyzed so the report is always complete in one click.
    """
    columns = [
        "Date of Analyzing the IP", "IP", "Blocked Vendor Name",
        "Status", "Reason", "Last Reported Date", "Total Reports"
    ]

    report_rows, mode, _ = build_blocked_report_rows()

    if mode == "none":
        flash("Scan an IP first before downloading a blocked report.", "danger")
        return redirect("/")

    filename_prefix = f"{latest_ip}_Blocked_Report" if mode == "single" else "Blocked_Report"

    if not report_rows:
        flash("No vendors blocked this IP." if mode == "single" else "No vendors blocked any IP in the file.", "info")
        return redirect(request.referrer or "/")

    df = pd.DataFrame(report_rows, columns=columns)

    csv_buffer = StringIO()
    df.to_csv(csv_buffer, index=False)

    filename = f"{filename_prefix}_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"

    return Response(
        csv_buffer.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )

@app.route("/details/<ip>")
def details(ip):

    whois_data = whois_lookup(ip)

    abuse_data = abuseipdb(ip)

    return render_template(
        "details.html",
        ip = ip,
        whois = whois_data,
        abuse = abuse_data
    )


if __name__ == "__main__":
    # WERKZEUG_RUN_MAIN is only set in the actual worker process when Flask's
    # debug reloader is active (it spawns a watcher process AND a worker
    # process). Without this guard, debug=True would start two copies of
    # the scheduler - one in each process - doubling every email sent.
    if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        start_scheduler(IP_FILE_PATH, extract_ips_from_file, build_blocked_report_rows_for_ips)

    app.run(debug=True)