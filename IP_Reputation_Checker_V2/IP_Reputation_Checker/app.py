from io import StringIO, BytesIO
from flask import Flask, render_template, request, send_file, Response, flash, redirect, session, jsonify
from services.main_file import abuseipdb, virustotal
from services.extra_vendors import greynoise, ipqualityscore, shodan_internetdb
from ipwhois import IPWhois
import pandas as pd
import ipaddress
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = "aathi24"

latest_results = []
latest_ip = None
batch_ips = []
batch_results = {}
current_batch_index = 0

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'csv'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

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
    try:
        abuse_data = abuseipdb(ip)
        vt_results = virustotal(ip) or []

        # Build the unified "extra vendors" portion of the table: AbuseIPDB
        # (previously fetched above but never shown) plus any other free
        # vendor that isn't already one of VirusTotal's bundled engines.
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

        # Total reports / last reported date for the summary panel: prefer
        # VirusTotal's figures (same value on every VT row), then fall back
        # to AbuseIPDB's if VirusTotal had no data at all.
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
            'error': str(e)
        }

@app.route("/", methods=["GET", "POST"])

def home():

    global latest_results, latest_ip, batch_ips, batch_results, current_batch_index

    if request.method == "POST":

        # Check if it's a file upload or single IP
        if 'file' in request.files and request.files['file'].filename != '':
            file = request.files['file']
            
            if file and allowed_file(file.filename):
                try:
                    file_content = file.read().decode('utf-8')
                    ips = extract_ips_from_file(file_content)
                    
                    if not ips:
                        flash("No valid IPs found in the file.", "danger")
                        return redirect("/")
                    
                    batch_ips = ips
                    batch_results = {}
                    current_batch_index = 0
                    
                    flash(f"Successfully loaded {len(ips)} IP(s) from file.", "success")
                    
                    # Process first IP
                    return redirect(f"/batch/0")
                
                except Exception as e:
                    flash(f"Error reading file: {str(e)}", "danger")
                    return redirect("/")
            else:
                flash("Please upload a .txt or .csv file.", "danger")
                return redirect("/")
        
        else:
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

            # A single-IP lookup means we're no longer in "batch" context;
            # clear any leftover batch state from a previous upload so the
            # vendor-details page doesn't mix the two up.
            batch_ips = []
            batch_results = {}
            current_batch_index = 0

            return render_template(
                "results.html", 
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
    
    return render_template("index.html")

@app.route("/batch/<int:index>")
def view_batch_ip(index):
    """View results for a specific IP in batch"""
    global batch_ips, batch_results, current_batch_index, latest_results, latest_ip
    
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
    
    batch_info = {
        'current': index + 1,
        'total': len(batch_ips),
        'has_next': index < len(batch_ips) - 1,
        'has_prev': index > 0
    }
    
    return render_template(
        "results.html", 
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
    app.run(debug=True)