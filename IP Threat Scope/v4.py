import requests
import pandas as pd
import json

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
        
        dict = {
            "IP Address" : data["data"]["ipAddress"],
            "Vendor" : "AbuseIPDB",
            "Score" : data["data"]["abuseConfidenceScore"],
            "Total Reports" : data["data"]["totalReports"],
            "Last Reported" : data["data"]["lastReportedAt"],
            "Country" : data["data"]["countryCode"],
            "ISP" : data["data"]["isp"],
            "Blocked" : status,
            "Reason" : reason
        }
        return dict
    
    else:
        print("Error:", response.status_code)
        print(response.text)
        return None
    
if __name__ == "__main__":
    result = []
    with open("IP_file.txt") as file:
        list = [line.strip() for line in file]
        for ip in list:
            res = abuseipdb(ip)
            result.append(res)  

    df = pd.DataFrame(result, index = (range(1,len(result)+1)))
    df.to_csv("Reports_of_IP.csv", mode = "a", index = False)
    print(df)
    