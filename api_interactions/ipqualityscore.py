import requests
import json
import urllib.parse
import re
from api.api_keys import ipqualityscore_api_key
from file_operations.file_utils import is_ip, is_url, is_domain
from IPython.display import clear_output, HTML, display  # Added import

def is_ip(ioc):
    """Check if the IOC is a valid IPv4 or IPv6 address."""
    ipv4_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    ipv6_pattern = (
        r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"  # Full IPv6 address
        r"^([0-9a-fA-F]{1,4}:){1,7}:$|"               # Leading zeros omitted
        r"^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$"  # Zero-compressed
    )
    
    return re.match(ipv4_pattern, ioc) is not None or re.match(ipv6_pattern, ioc) is not None

def get_ipqualityscore_report(ioc, full_report=False, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching IPQualityScore report for: {ioc}...</b>'))
            display(progress_bar)
    print(f"Fetching IPQualityScore report for: {ioc}")
    
    try:
        # Set the strictness level to 2
        strictness_level = 2

        # Determine the correct API URL based on IOC type (IP or URL)
        if is_ip(ioc):
            url = f"https://ipqualityscore.com/api/json/ip/{ipqualityscore_api_key}/{ioc}?strictness={strictness_level}"
        elif is_url(ioc) or is_domain(ioc):
            # URL-encode the IOC if it's a URL or domain
            encoded_ioc = urllib.parse.quote_plus(ioc)
            url = f"https://ipqualityscore.com/api/json/url/{ipqualityscore_api_key}/{encoded_ioc}?strictness={strictness_level}"
        else:
            raise ValueError(f"Unsupported IOC type: {ioc}")
            

        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        #print(f"DEBUG: Full IPQualityScore response for {ioc}: {json.dumps(data, indent=2)}")

        if data.get("success"):
            # Report for IPs
            if is_ip(ioc):
                report = (
                    f"IPQualityScore Report:\n"
                    f"  - IOC: {ioc}\n"
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
                    f"  - Latitude: {data.get('latitude', 'N/A')}\n"
                    f"  - Longitude: {data.get('longitude', 'N/A')}\n"
                    f"  - Connection Type: {data.get('connection_type', 'N/A')}\n"
                )
            # Report for domains
            else:
                report = (
                    f"IPQualityScore Report:\n"
                    f"  - IOC: {ioc}\n"
                    f"  - Domain: {data.get('domain', 'N/A')}\n"
                    f"  - Root Domain: {data.get('root_domain', 'N/A')}\n"
                    f"  - IP Address: {data.get('ip_address', 'N/A')}\n"
                    f"  - Server: {data.get('server', 'N/A')}\n"
                    f"  - Status Code: {data.get('status_code', 'N/A')}\n"
                    f"  - Page Size: {data.get('page_size', 'N/A')} bytes\n"
                    f"  - Domain Rank: {data.get('domain_rank', 'N/A')}\n"
                    f"  - DNS Valid: {data.get('dns_valid', 'N/A')}\n"
                    f"  - Parking: {data.get('parking', 'N/A')}\n"
                    f"  - Risk Score: {data.get('risk_score', 'N/A')}\n"
                    f"  - Malware: {data.get('malware', 'N/A')}\n"
                    f"  - Phishing: {data.get('phishing', 'N/A')}\n"
                    f"  - Suspicious: {data.get('suspicious', 'N/A')}\n"
                    f"  - Redirected: {data.get('redirected', 'N/A')}\n"
                    f"  - Final URL: {data.get('final_url', 'N/A')}\n"
                    f"  - Domain Age: {data.get('domain_age', {}).get('human', 'N/A')}\n"
                    f"  - Risky TLD: {data.get('risky_tld', 'N/A')}\n"
                    f"  - SPF Record: {data.get('spf_record', 'N/A')}\n"
                    f"  - DMARC Record: {data.get('dmarc_record', 'N/A')}\n"
                )

            # Print and return the report
            return report.strip()

        else:
            error_message = data.get("message", "Unknown error")
            print(f"IPQualityScore Error: {error_message}")
            return f"Error: {error_message}"
            
    except requests.RequestException as e:
        print(f"Error getting IPQualityScore report: {e}")
        return f"Error getting IPQualityScore report: {e}"

# Parsing function for IPQualityScore report (handles both IP and URL)
def parse_ipqualityscore_report(report_str):
    parsed_data = {}
    for line in report_str.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            key = key.strip().lower().replace(" ", "_").lstrip("-_")
            value = value.strip()

            # Check if the value is numeric but not an IP address
            if value.replace(".", "").isdigit() and not all(part.isdigit() and 0 <= int(part) <= 255 for part in value.split(".")): 
                parsed_data[key] = float(value) if "." in value else int(value)
            elif value.lower() == "true":
                parsed_data[key] = True
            elif value.lower() == "false":
                parsed_data[key] = False
            else:
                parsed_data[key] = value if value != "N/A" else None

    return parsed_data