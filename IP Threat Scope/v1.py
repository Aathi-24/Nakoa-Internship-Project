import requests
import json

API_KEY = "0ef8bc21a09b3512c27bad77fb63602851a760ed70efb89b49be2eba0c0e3fb30ac3ca8098cdc17f"

url = "https://api.abuseipdb.com/api/v2/check"
def iprep(ip):
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
        print("IP Address : ", data["data"]["ipAddress"])
        print("Abuse Confidence Score : ", data["data"]["abuseConfidenceScore"])
        print("Country : ", data["data"]["countryCode"])
        print("ISP : ", data["data"]["isp"])
        print("Domain : ", data["data"]["domain"])
        print("Last Reported:", data["data"]["lastReportedAt"])
        #print("Total Reports : ", data["data"]["totalReports"])
    else:
        print("Error:", response.status_code)
        print(response.text)

n = int(input("Enter the number of IP's : "))
list = []
for i in range(1,n+1):
    list.append(input(f"Enter IP {i} : "))
for ip in list:
    print("=========================================================")
    print(f"For ip {ip} : ",end='\n')
    print("=========================================================")
    iprep(ip)
    print()