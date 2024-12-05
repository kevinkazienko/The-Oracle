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
        'maxAgeInDays': '14',
        'verbose': True  # Ensure detailed reports including comments
    }
    headers = {
        'Accept': 'application/json',
        'Key': abuseipdb_api_key
    }
    response = requests.get(url=url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json().get('data', {})
        if data:
            # Extracting comments from reports
            reports = data.get('reports', [])
            top_comments = []
            
            for report in reports:
                comment = report.get('comment', '').strip()
                reported_at = report.get('reportedAt', 'N/A')
                reporter_id = report.get('reporterId', 'Anonymous')
                
                if comment:
                    top_comments.append({
                        "comment": comment,
                        "reportedAt": reported_at,
                        "reporterId": reporter_id
                    })
            
            # Limit to top 10 comments
            top_comments = top_comments[:10]
    
            report = {
                "abuseConfidenceScore": data.get("abuseConfidenceScore", "N/A"),
                "isTor": data.get("isTor", False),
                "lastSeen": data.get("lastReportedAt", "N/A"),
                "totalReports": data.get("totalReports", "N/A"),
                "domain": data.get("domain", "N/A"),
                "country_code": data.get("countryCode", "N/A"),
                "isp": data.get("isp", "N/A"),
                "topComments": top_comments  # Include structured comments
            }
            return report
        else:
            print(f"AbuseIPDB has no information about IP {ip}")
            return {"error": f"AbuseIPDB has no information about IP {ip}"}
    else:
        error_message = f"  Failed to fetch AbuseIPDB report for {ip}. Status Code: {response.status_code}"
        print(error_message)
        return {"error": error_message}