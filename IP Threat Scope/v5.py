import requests
import pandas as pd
import json
from datetime import datetime

def abuseipdb(ip):
    API_KEY = "0ef8bc21a09b3512c27bad77fb63602851a760ed70efb89b49be2eba0c0e3fb30ac3ca8098cdc17f"
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": ""
    }

    response = requests.get(
        url,
        headers=headers,
        params=params
    )

    if response.status_code == 200:
        data = response.json()
        score = data["data"]["abuseConfidenceScore"]
        reports = data["data"]["totalReports"]

        if score >= 50 and reports >= 10:
            status = "Blocked"
        else:
            status = "Safe"
        
        if(status == "Blocked"):
            if score == 0:
                reason = "Clean"
            elif score < 50:
                reason = "Suspicious"
            else:
                reason = "Malicious"
        else:
            reason = "Nil"
        
        date_str = data["data"]["lastReportedAt"]
        dt_obj = datetime.fromisoformat(date_str)
        date = dt_obj.date()

        dict = {
            "Vendor" : "AbuseIPDB",
            "Score" : data["data"]["abuseConfidenceScore"],
            "Blocked" : status,
            "Reason" : reason,
            "Total Reports" : data["data"]["totalReports"],
            "Last Reported" : date
        }
        return dict
    
    else:
        print("Error:", response.status_code)
        print(response.text)
        return None
    
def virustotal(ip):
    API_KEY = "1840ec0af3668a612149e6b3aae3895f7048b52de22d3ba2018059f1f01b3b95"

    url1 = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(
        url1, 
        headers=headers
    )

    if response.status_code == 200:
        data = response.json()
        attributes = data["data"]["attributes"]
        stats = attributes["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0:
            status = "Blocked"
            reason = "Malicious"

        elif suspicious > 0:
            status = "Suspicious"
            reason = "Suspicious Activity"

        else:
            status = "Safe"
            reason = "Nil"
        
    timestamp = attributes.get("last_modification_date")

    if timestamp:
        timestamp = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d")

        return {
            "Vendor": "VirusTotal",
            "Score": malicious,
            "Blocked": status,
            "Reason": reason,
            "Total Reports": malicious + suspicious,
            "Last Reported": timestamp,
        }

    else:
        print("Error:", response.status_code)
        print(response.text)
    
if __name__ == "__main__":
    ip = input("Enter an IP : ")
    result = []
    abip = abuseipdb(ip)
    result.append(abip) 
    vt = virustotal(ip)
    result.append(vt)

    df = pd.DataFrame(result, index = (range(1,len(result)+1)))
    df.to_csv("Reports_of_IP.csv", mode = "a", index = False)
    print(df)
    