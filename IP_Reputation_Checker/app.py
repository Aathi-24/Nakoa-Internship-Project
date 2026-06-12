from io import StringIO
from flask import Flask, render_template, request, send_file, Response
from services.main_file import abuseipdb, virustotal
import pandas as pd

app = Flask(__name__)

latest_results = []

@app.route("/", methods=["GET", "POST"])

def home():

    global latest_results

    if request.method == "POST":

        ip = request.form["ip"]
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
            last_reported = last_reported
            )
    
    return render_template("index.html")

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


if __name__ == "__main__":
    app.run(debug=True)