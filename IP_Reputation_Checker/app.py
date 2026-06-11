from flask import Flask, render_template, request
from services.main_file import abuseipdb, virustotal

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        ip = request.form["ip"]
        abuse_res = abuseipdb(ip)
        results = virustotal(ip)

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

if __name__ == "__main__":
    app.run(debug=True)