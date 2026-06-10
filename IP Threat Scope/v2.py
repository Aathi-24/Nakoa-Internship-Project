import requests
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
        dict = {
            "IP Address" : data["data"]["ipAddress"],
            "Vendor" : "AbuseIPDB",
            "Score" : data["data"]["abuseConfidenceScore"],
            "Total Reports" : data["data"]["totalReports"],
            "Last Reported" : data["data"]["lastReportedAt"],
            "Country" : data["data"]["countryCode"],
            "ISP" : data["data"]["isp"]
        }
        return dict
        
    else:
        print("Error:", response.status_code)
        print(response.text)
        return None

if __name__ == "__main__":
    n = int(input("Enter the number of IP's : "))
    list = []
    for i in range(1,n+1):
        list.append(input(f"Enter IP {i} : "))

    for ip in list:
        print("=========================================================")
        result = json.dumps(abuseipdb(ip))
        print(type(result))
        print()