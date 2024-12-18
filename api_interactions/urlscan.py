import requests
import time
from api.api_keys import urlscan_api_key
from IPython.display import clear_output, HTML, display  # Added import

def submit_url_to_urlscan(url, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'Submitting {url} to URLScan'))
            display(progress_bar)
    print(f"Submitting {url} to URLScan")
    headers = {
        'API-Key': urlscan_api_key,
        'Content-Type': 'application/json',
    }
    data = {
        'url': url,
        'visibility': 'public'
    }
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data)
    if response.status_code == 200:
        return response.json()['uuid']
    elif response.status_code == 400:
        print(f"Failed to submit to urlscan.io analysis. Status Code: 400 - Not resolving.")
        return "domain_not_resolving"
    else:
        print(f"Failed to submit to urlscan.io analysis. Status Code: {response.status_code}")
        return None

def get_urlscan_report(uuid, retries=10, delay=20, status_output=None, progress_bar=None):
    if uuid == "domain_not_resolving":
        return {"Resolving": False}

    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'Fetching URLScan report for {uuid}'))
            display(progress_bar)
    print(f"Fetching URLScan report for {uuid}.")
    for attempt in range(retries):
        response = requests.get(f'https://urlscan.io/api/v1/result/{uuid}/')
        if response.status_code == 200:
            report = response.json()

            # Check if the domain is resolving by inspecting multiple indicators
            domain = report.get('page', {}).get('domain', None)
            url = report.get('page', {}).get('url', None)
            ip = report.get('page', {}).get('ip', None)

            resolving = domain is not None and url is not None and ip is not None

            if not resolving:
                print("DEBUG: Domain is not resolving.")
                return {"Resolving": False}

            # Extract ASN and ISP data
            asn_data = report.get('meta', {}).get('processors', {}).get('asn', {}).get('data', [])
            if isinstance(asn_data, list) and len(asn_data) > 0:
                asn = asn_data[0].get('asn', 'N/A')
                isp = asn_data[0].get('name', 'N/A')
            else:
                asn = 'N/A'
                isp = 'N/A'

            # Extract the screenshot URL
            screenshot_url = report.get('task', {}).get('screenshotURL', 'N/A')

            # Return the parsed data
            data = {
                'URL': report.get('page', {}).get('url', 'N/A'),
                'Domain': report.get('page', {}).get('domain', 'N/A'),
                'IP': report.get('page', {}).get('ip', 'N/A'),
                'Country': report.get('geoip', {}).get('country_name', 'N/A'),
                'City': report.get('geoip', {}).get('city', 'N/A'),
                'ASN': asn,
                'ISP': isp,
                'Malicious Score': report.get('verdicts', {}).get('urlscan', {}).get('score', 0),
                'Malicious Categories': report.get('verdicts', {}).get('urlscan', {}).get('categories', []),
                'TLS Issuer': report.get('page', {}).get('tlsIssuer', 'N/A'),
                'TLS Age (days)': report.get('page', {}).get('tlsAgeDays', 'N/A'),
                'TLS Validity (days)': report.get('page', {}).get('tlsValidDays', 'N/A'),
                'Redirected': report.get('page', {}).get('redirected', 'N/A'),
                'Screenshot URL': screenshot_url,
                'Resolving': resolving,  # Set the resolving status
                'Last Analysis Date': report.get('task', {}).get('time', 'N/A')
            }
            return data
        elif response.status_code == 404:
            print(f"Scan not finished yet, retrying in {delay} seconds... (Attempt {attempt + 1}/{retries})")
            time.sleep(delay)
        elif response.status_code == 400:
            print(f"Failed to fetch urlscan.io report for UUID: {uuid}. Not resolving.")
            return {"Resolving": False}
        else:
            print(f"Failed to fetch urlscan.io report for UUID: {uuid}. Status Code: {response.status_code}")
            print(response.text)
            return {"error": "Error fetching URLScan report"}
    return None