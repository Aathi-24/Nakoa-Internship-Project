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
    result = []
    with open("IP_file.txt") as file:
        list = [line.strip() for line in file]
        for ip in list:
            res= json.dumps(abuseipdb(ip))
            result.append(res)  

    records = [json.loads(item) for item in result]
    headers = tuple(records[0].keys())

    widths = {}
    for header in headers:
        max_len = len(header)
        for record in records:
            max_len = max(max_len, len(str(record.get(header, ""))))
        widths[header] = max_len

    header_row = " | ".join(f"{h:<{widths[h]}}" for h in headers)
    print(header_row)

    separator = "-+-".join("-" * widths[h] for h in headers)
    print(separator)

    for record in records:
        row = " | ".join(
            f"{str(record.get(h, '')):<{widths[h]}}"
            for h in headers
        )
        print(row)