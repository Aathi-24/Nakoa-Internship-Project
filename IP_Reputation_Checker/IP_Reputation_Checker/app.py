from io import StringIO
from flask import Flask, render_template, request, send_file, Response, flash, redirect
from services.main_file import abuseipdb, virustotal
from ipwhois import IPWhois
import pandas as pd
import ipaddress

app = Flask(__name__)
app.secret_key = "aathi24"

latest_results = []

@app.route("/", methods=["GET", "POST"])

def home():

    global latest_results

    if request.method == "POST":

        ip = request.form["ip"]

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            flash("Please enter a valid IPv4 or IPv6 address.", "danger")

            return redirect("/")

        abuse_res = abuseipdb(ip)
        results = virustotal(ip)

        latest_results = results
        current_ip = ip

        total = len(results)

        blocked = len([x for x in results if x["Blocked"] == "Blocked"])

        safe = total - blocked

        if blocked > 0:
            verdict = "Suspicious"
        else:
            verdict = "Safe"
        
        total_reports = results[4].get("Total_Reports")
        last_reported = results[4].get("Last_Reported")
        
        return render_template(
            "result.html", 
            results = results, 
            total = total, 
            safe = safe, 
            blocked = blocked, 
            ip = ip,
            verdict = verdict,
            total_reports = total_reports,
            last_reported = last_reported,
            error = None
            )
    
    return render_template("index.html")

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