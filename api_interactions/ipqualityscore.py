import requests
import json
from api.api_keys import ipqualityscore_api_key
from IPython.display import clear_output, HTML, display  # Added import

def get_ipqualityscore_report(ip, full_report=False, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching IPQualityScore report for: {ip}...</b>'))
            display(progress_bar)
    print(f"Fetching IPQualityScore report for: {ip}")
    try:
        url = f"https://ipqualityscore.com/api/json/ip/{ipqualityscore_api_key}/{ip}"
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        #print("API Response:", json.dumps(data, indent=4))  # Debugging output

        if data.get("success"):
            # Build a string report
            report = (
                f"IPQualityScore Report:\n"
                f"  - Fraud Score: {data.get('fraud_score', 'N/A')}\n"
                f"  - Country Code: {data.get('country_code', 'N/A')}\n"
                f"  - Region: {data.get('region', 'N/A')}\n"
                f"  - City: {data.get('city', 'N/A')}\n"
                f"  - ISP: {data.get('ISP', 'N/A')}\n"
                f"  - ASN: {data.get('ASN', 'N/A')}\n"
                f"  - Organization: {data.get('organization', 'N/A')}\n"
                f"  - Proxy: {data.get('proxy', 'N/A')}\n"
                f"  - VPN: {data.get('vpn', 'N/A')}\n"
                f"  - Tor: {data.get('tor', 'N/A')}\n"
                f"  - Active VPN: {data.get('active_vpn', 'N/A')}\n"
                f"  - Active Tor: {data.get('active_tor', 'N/A')}\n"
                f"  - Recent Abuse: {data.get('recent_abuse', 'N/A')}\n"
                f"  - Bot Status: {data.get('bot_status', 'N/A')}\n"
                f"  - Connection Type: {data.get('connection_type', 'N/A')}\n"
                f"  - Abuse Velocity: {data.get('abuse_velocity', 'N/A')}\n"
                f"  - Latitude: {data.get('latitude', 'N/A')}\n"
                f"  - Longitude: {data.get('longitude', 'N/A')}\n"
                f"  - Zip Code: {data.get('zip_code', 'N/A')}\n"
                f"  - Timezone: {data.get('timezone', 'N/A')}\n"
                f"  - Is Crawler: {data.get('is_crawler', 'N/A')}\n"
                f"  - Mobile: {data.get('mobile', 'N/A')}\n"
                f"  - Host: {data.get('host', 'N/A')}\n"
            )

            return report.strip()

        else:
            error_message = data.get("message", "Unknown error")
            print(f"IPQualityScore Error: {error_message}")
            return f"Error: {error_message}"
            
    except requests.RequestException as e:
        print(f"Error getting IPQualityScore report: {e}")
        return f"Error getting IPQualityScore report: {e}"