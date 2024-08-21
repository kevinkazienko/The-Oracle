import requests
from api.api_keys import abuseipdb_api_key
from IPython.display import clear_output, HTML, display  # Added import

# Fetches AbuseIPDB report for IP
def get_abuseipdb_report(ip, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching IP report from AbuseIPDB for {ip}...</b>'))
            display(progress_bar)
    print(f"Fetching IP report in AbuseIPDB for {ip}")
    url = f"https://api.abuseipdb.com/api/v2/check"
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '30'
    }
    headers = {
        'Accept': 'application/json',
        'Key': abuseipdb_api_key
    }
    response = requests.get(url=url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()['data']
        
        if data:
            report = {
                "abuseConfidenceScore": data.get("abuseConfidenceScore", "N/A"),
                "isTor": data.get("isTor", False),
                "lastSeen": data.get("lastReportedAt", "N/A"),
                "totalReports": data.get("totalReports", "N/A"),
                "domain": data.get("domain", "N/A")
            }
            return report
        else:
            print(f"AbuseIPDB has no information about IP {ip}")
            return {"error": f"AbuseIPDB has no information about IP {ip}"}
    else:
        error_message = f"  Failed to fetch AbuseIPDB report for {ip}. Status Code: {response.status_code}"
        print(error_message)
        return {"error": error_message}