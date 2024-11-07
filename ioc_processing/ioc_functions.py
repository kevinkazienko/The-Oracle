import os
import re
import time
import json
import textwrap
import logging
import ast
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from IPython.display import clear_output, HTML, display
from utils.common_utils import print_help
from api_interactions.malwarebazaar import (
    get_malwarebazaar_hash_report
)
from api_interactions.abuseipdb import get_abuseipdb_report
from file_operations.file_utils import (
    is_ip,
    is_url,
    is_hash,
    read_file,
    write_to_file,
    clean_input,
    sanitize_and_defang,
    is_domain,
    is_cve,
    is_org,
    is_port,
    is_product
)
from api_interactions.virustotal import (
    get_ip_report,
    submit_url_for_analysis,
    get_url_report,
    get_hash_report,
    get_domain_report,
    needs_rescan,
    submit_ip_for_rescan,
    submit_url_for_rescan,
    submit_domain_for_rescan,
    submit_hash_for_rescan
)
from api_interactions.shodan import get_shodan_report, search_shodan_cve_country, search_shodan_product_country, search_shodan_org, search_shodan_by_port, search_shodan_product_in_country, search_shodan_product_port_country
from api_interactions.alienvault import get_alienvault_report
from api_interactions.ipqualityscore import get_ipqualityscore_report, parse_ipqualityscore_report
from api_interactions.greynoise import get_greynoise_report
from api_interactions.urlscan import (
    submit_url_to_urlscan,
    get_urlscan_report
)
from api_interactions.censys import get_censys_data, search_cves_on_censys, search_censys_org, search_censys_by_port, search_censys_product_country, search_censys_product_port_country
from api.api_keys import censys_api_key, censys_secret, metadefender_api_key
from api_interactions.borealis import request_borealis, format_borealis_report
from api_interactions.binaryedge import get_binaryedge_report, search_binaryedge_by_port, search_binaryedge_product, search_binaryedge_product_port_country
from api_interactions.metadefender import analyze_with_metadefender, process_metadefender_ip_report, process_metadefender_url_report, process_metadefender_hash_report
from api_interactions.hybridanalysis import needs_hybridrescan, get_hybrid_analysis_hash_report, submit_hybridhash_for_rescan, parse_hybrid_analysis_report, print_hybrid_analysis_report, process_hybrid_analysis_report
from api_interactions.malshare import get_malshare_hash_report

# Configure logging to file
#logging.basicConfig(filename='debug.log', level=logging.DEBUG)


def safe_join(separator, items):
    # Convert all items to strings, handle dictionaries by converting them to key-value pairs or extracting a specific key
    def stringify(item):
        if isinstance(item, dict):
            # Extract relevant field from the dictionary or convert to key-value pairs
            if 'name' in item:
                return item['name']
            return str(item)  # fallback to converting whole dict to string
        return str(item)  # Ensure all other types are strings
    
    return separator.join(stringify(item) for item in items)

# Function to classify the IOC based on the detected pattern
def classify_ioc(ioc):
    ioc = ioc.strip()
    
    # Check for product with port specified (e.g., "prod:product, port")
    if ioc.lower().startswith('prod:'):
        product_info = ioc[5:].strip()
        parts = product_info.split(',')
        product = parts[0].strip() if parts else None
        port = parts[1].strip() if len(parts) > 1 else None
        return 'product_with_port', (product, port)
    
    # Handle other types
    if ioc.lower().startswith('org:'):
        return 'org', ioc[4:].strip()
    elif is_ip(ioc):
        return 'ip', ioc
    elif is_url(ioc):
        return 'url', ioc
    elif is_domain(ioc):
        return 'domain', ioc
    elif is_hash(ioc):
        return 'hash', ioc
    elif is_cve(ioc):
        return 'cve', ioc
    elif is_port(ioc):
        return 'port', ioc
    elif is_org(ioc):
        return 'org', ioc
    else:
        return 'unknown', ioc

def auto_detect_ioc_type(iocs):
    if iocs['ips']:
        return 'ip'
    elif iocs['urls']:
        return 'url'
    elif iocs['hashes']:
        return 'hash'
    elif iocs['cves']:  # Detect CVEs
        return 'cve'
    elif iocs['orgs']:  # Detect Organizations
        return 'org'
    elif iocs['product_port_combinations']:
        return 'product_port_combination'
    else:
        return 'unknown'


def parse_bulk_iocs(content):
    iocs = {'ips': [], 'urls': [], 'domains': [], 'hashes': [], 'cves': [], 'orgs': [], 'ports': [], 'products': []}
    if not content:
        return iocs
    for line in content.splitlines():
        line = line.strip()
        if line:
            ioc_type = classify_ioc(line)
            if ioc_type != 'unknown':
                if ioc_type == 'hash':
                    iocs['hashes'].append(line)
                elif ioc_type == 'product':
                    iocs['products'].append(line)
                else:
                    iocs[f'{ioc_type}s'].append(line)
    return iocs


def wrap_text(text, width=80, indent=4):
    """Utility function to wrap text and preserve indentation."""
    indent_space = ' ' * indent
    return textwrap.fill(text, width=width, initial_indent=indent_space, subsequent_indent=indent_space)


def extract_last_analysis_date(report):
    last_analysis_date = report.get('data', {}).get('attributes', {}).get('last_analysis_date')
    
    # Convert ISO 8601 formatted strings to UTC-aware datetime
    if isinstance(last_analysis_date, str):
        try:
            # Parse ISO 8601 format and convert to UTC
            last_analysis_date = datetime.fromisoformat(last_analysis_date.replace("Z", "+00:00"))
        except ValueError as e:
            print(f"ERROR: Failed to parse date: {e}")
            return None
    elif isinstance(last_analysis_date, int):
        # If it's already a timestamp, convert it to UTC-aware datetime
        last_analysis_date = datetime.utcfromtimestamp(last_analysis_date).replace(tzinfo=timezone.utc)
    
    return last_analysis_date


def format_date(timestamp):
    if isinstance(timestamp, (int, float)):
        try:
            # Check if the timestamp is in milliseconds (larger than 1e12)
            if timestamp > 1e12:
                timestamp = timestamp / 1000  # Convert milliseconds to seconds
            return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        except (OSError, ValueError):
            return 'Invalid timestamp'
    return 'N/A'


def defang_shodan_report(report):
    defanged_report = {}
    if isinstance(report, dict):
        for key, value in report.items():
            if isinstance(value, str) and (is_ip(value) or is_url(value)):
                defanged_report[key] = sanitize_and_defang(value)
            else:
                defanged_report[key] = value
    return defanged_report


def format_crowdsourced_context(crowdsourced_context):
    formatted_context = ""
    if isinstance(crowdsourced_context, list):
        for item in crowdsourced_context:
            context_details = item.get('details', 'N/A')
            formatted_context += f"  {context_details}\n"
    elif isinstance(crowdsourced_context, dict):  # Ensure dictionary handling
        formatted_context = ', '.join([f"{k}: {v}" for k, v in crowdsourced_context.items()])
    else:
        formatted_context = crowdsourced_context if isinstance(crowdsourced_context, str) else "N/A"
    return formatted_context.strip()


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


def parse_binaryedge_report(report_data, ioc_type):
    parsed_info = []

    # Ensure 'events' exist and it's a list
    if not report_data or 'events' not in report_data or not isinstance(report_data['events'], list):
        #print("Debug: No 'events' found in report_data or it's not a list.")
        return "No relevant data found."

    # Extract IP from 'query' (since 'ip' may not exist directly)
    target_ip = report_data.get('query', 'N/A')
    parsed_info.append(f"  - IP: {target_ip}")
    #print(f"Debug: Target IP: {target_ip}")

    # Total Events count
    total_events = report_data.get('total', 0)
    parsed_info.append(f"  - Total Events: {total_events}")
    #print(f"Debug: Total Events: {total_events}")

    # Loop through events to extract details
    events = report_data.get('events', [])
    for idx, event in enumerate(events, start=1):
        parsed_info.append(f"  - Event {idx}:")
        #print(f"Debug: Processing Event {idx}")

        # Attempt to extract target info from event or result
        target_info = event.get('target', {}) or {}  # Default to empty dict if None
        port = target_info.get('port', 'N/A')  # Extract port
        protocol = target_info.get('protocol', 'N/A')  # Extract protocol
        ip_address = target_info.get('ip', 'N/A')

        # Check in result data if target info is empty
        if ip_address == 'N/A' or port == 'N/A' or protocol == 'N/A':
            result = event.get('results', [{}])[0]  # Get first result if available
            target_info_from_result = result.get('target', {}) or {}
            ip_address = target_info_from_result.get('ip', 'N/A')
            port = target_info_from_result.get('port', 'N/A')
            protocol = target_info_from_result.get('protocol', 'N/A')

        parsed_info.append(f"    - Target IP: {ip_address}, Port: {port}, Protocol: {protocol}")
        #print(f"Debug: Target IP: {ip_address}, Port: {port}, Protocol: {protocol}")

        # Extract origin details from 'origin' in results
        origin_info = result.get('origin', {}) or {}
        #print(f"Debug: Origin Info: {origin_info}")
        origin_ip = origin_info.get('ip', 'N/A')
        origin_country = origin_info.get('country', 'N/A')
        origin_ts = origin_info.get('ts', 'N/A')
        
        # Convert the timestamp using the format_date function
        if origin_ts != 'N/A':
            origin_ts = format_date(origin_ts)

        parsed_info.append(f"    - Origin IP: {origin_ip}\n    - Country: {origin_country}\n    - Timestamp: {origin_ts}")
        #print(f"Debug: Origin IP: {origin_ip}, Country: {origin_country}, Timestamp: {origin_ts}")

        # Extract result data (with proper None checking)
        result_data = result.get('result', {}).get('data', {}) or {}

        if not result_data:
            parsed_info.append("    - No data available for this result")
            print("Debug: No result data available.")
            continue

        # Extract service details
        service_data = result_data.get('service', {}) or {}
        #print(f"Debug: Service Data: {service_data}")
        service_product = service_data.get('product', 'N/A')
        cpe_list = service_data.get('cpe', [])
        
        cpe = ", ".join(cpe_list) if cpe_list else 'N/A'
        banner = service_data.get('banner', 'N/A')
        parsed_info.append(f"    - Service Product: {service_product}")
        parsed_info.append(f"    - CPE: {cpe}")
        parsed_info.append(f"    - Banner: {banner}")
        #print(f"Debug: Service Product: {service_product}, CPE: {cpe}, Banner: {banner}")

        # Extract JARM details if present
        # jarm = result_data.get('jarm', 'N/A')
        # jarm_hash = result_data.get('jarm_hash', 'N/A')
        # parsed_info.append(f"    - JARM: {jarm}\n    - JARM Hash: {jarm_hash}")
        # #print(f"Debug: JARM: {jarm}, JARM Hash: {jarm_hash}")

        # Extract SSL details if present
        cert_info = result_data.get('cert_info', {}).get('certificate_chain', []) or []
        if cert_info:
            cert_pem = [cert.get('as_pem', 'N/A') for cert in cert_info]
            parsed_info.append(f"    - Certificates: {cert_pem}")
           # print(f"Debug: Certificates: {cert_pem}")

        # Extract TLS handshake and other SSL/TLS-related details
        tls_data = result_data.get('tls', {}) or {}
        handshake_log = tls_data.get('handshake_log', {}) or {}
        server_key_exchange = handshake_log.get('server_key_exchange', {}) or {}
        if server_key_exchange:
            server_public_key = server_key_exchange.get('ecdh_params', {}).get('server_public', {}) or {}
            parsed_info.append(f"    - Server Public Key X: {server_public_key.get('x', 'N/A')}")
            parsed_info.append(f"    - Server Public Key Y: {server_public_key.get('y', 'N/A')}")
            

        # Extract additional details related to encryption and ciphers
        algorithms = result_data.get('algorithms', {}) or {}
        if algorithms:
            encryption = algorithms.get('encryption', []) or []
            
            parsed_info.append(f"    - Supported Encryption: {', '.join(encryption) if encryption else 'N/A'}")
            macs = algorithms.get('mac', []) or []
            
            parsed_info.append(f"    - Supported MACs: {', '.join(macs) if macs else 'N/A'}")
            server_host_keys = algorithms.get('server_host_key', []) or []
            
            parsed_info.append(f"    - Server Host Keys: {', '.join(server_host_keys) if server_host_keys else 'N/A'}")
            #print(f"Debug: Supported Encryption: {encryption}, Supported MACs: {macs}, Server Host Keys: {server_host_keys}")

    
    return "\n".join(parsed_info)


def extract_vt_analysis(vt_report):
    """
    Extracts common analysis information from a VirusTotal report.
    Works for IPs, URLs, and hashes, and now includes tags, registrar, and creation date.
    """
    malicious_count = 0
    suspicious_count = 0
    last_analysis_date_formatted = "N/A"  # Default to N/A if not found
    crowdsourced_context = 'N/A'
    tags = 'N/A'
    registrar = 'N/A'
    creation_date = 'N/A'
    signature_info = {}

    #print("DEBUG: vt_report received", vt_report)  # Debug to see the full report

    if vt_report and 'data' in vt_report and 'attributes' in vt_report['data']:
        attributes = vt_report['data']['attributes']

        # Malicious and suspicious counts
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        malicious_count = last_analysis_stats.get('malicious', 0)
        suspicious_count = last_analysis_stats.get('suspicious', 0)

        # Extract and format last_analysis_date (as Unix timestamp)
        last_analysis_epoch = attributes.get('last_analysis_date', None)
        print(f"DEBUG: Last analysis epoch: {last_analysis_epoch}")  # Debugging last_analysis_date

        if last_analysis_epoch:
            try:
                # Assuming the timestamp is in seconds, convert it
                last_analysis_date = datetime.utcfromtimestamp(int(last_analysis_epoch))
                last_analysis_date_formatted = last_analysis_date.strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, OSError) as e:
                print(f"ERROR: Invalid last_analysis_date: {e}")
                last_analysis_date_formatted = "Invalid date"

        # Crowdsourced context
        crowdsourced_context = attributes.get('crowdsourced_context', 'N/A')

        # Extract tags (if present)
        
        tags = ', '.join(attributes.get('tags', [])) if attributes.get('tags') else 'N/A'

        # Extract registrar and creation date for domains/URLs (if available)
        registrar = attributes.get('registrar', 'N/A')
        creation_date = attributes.get('creation_date', 'N/A')
        #print(f"DEBUG: Creation date (raw): {creation_date}")  # Debugging creation date

        if creation_date != 'N/A':
            try:
                creation_date = datetime.utcfromtimestamp(int(creation_date)).strftime('%Y-%m-%d %H:%M:%S')
            except ValueError as e:
                print(f"ERROR: Invalid creation_date: {e}")
                creation_date = 'Invalid date'

    #print(f"DEBUG: Returning values: Malicious: {malicious_count}, Suspicious: {suspicious_count}, Last Analysis: {last_analysis_date_formatted}, Context: {crowdsourced_context}, Tags: {tags}, Registrar: {registrar}, Creation Date: {creation_date}")
    
    return malicious_count, suspicious_count, last_analysis_date_formatted, crowdsourced_context, tags, registrar, creation_date



def ensure_list(breakdown):
    """
    Ensures the breakdown is a list. If it's a string, it converts it to a list.
    """
    if isinstance(breakdown, str):
        return [breakdown]  # Convert string to a single-item list
    return breakdown  # Return if it's already a list

# Vendor Intel
def parse_vendor_intel(vendor_intel):
    formatted_vendor_intel = ""
    if vendor_intel:
        for vendor, details in vendor_intel.items():
            formatted_vendor_intel += f"  - {vendor}:\n"
            if isinstance(details, dict):
                detection = details.get("detection") or details.get("family_name") or details.get("threat_name") or details.get("malware_family") or details.get("status") or "N/A"
                link = details.get("link", "N/A") or details.get("analysis_url", "N/A")
                verdict = details.get("verdict", details.get("score", "N/A"))
                first_seen = details.get("first_seen", "N/A")
                scanner_count = details.get("scanner_count", "N/A")
                scanner_match = details.get("scanner_match", "N/A")
                
                formatted_vendor_intel += f"    Detection: {detection}\n"
                if link != "N/A":
                    formatted_vendor_intel += f"    Link: {link}\n"
                if verdict != "N/A":
                    formatted_vendor_intel += f"    Verdict: {verdict}\n"
                if first_seen != "N/A":
                    formatted_vendor_intel += f"    First Seen: {first_seen}\n"
                if scanner_count != "N/A":
                    formatted_vendor_intel += f"    Scanner Count: {scanner_count}\n"
                if scanner_match != "N/A":
                    formatted_vendor_intel += f"    Scanner Match: {scanner_match}\n"
            elif isinstance(details, list):
                for item in details:
                    detection = item.get('detection') or item.get('family_name') or "N/A"
                    link = item.get('link', "N/A")
                    formatted_vendor_intel += f"    Detection: {detection}\n"
                    if link != "N/A":
                        formatted_vendor_intel += f"    Link: {link}\n"
    else:
        formatted_vendor_intel = "None"
    
    return formatted_vendor_intel


# Trusted ASN List for specific providers
trusted_asn_list = {
    "Google": 15169,
    "Cloudflare": 13335,
    "Amazon": 16509,
    "Microsoft": 8075,
    #"Akamai": 20940,
    #"Shodan": 20473,  # Shodan is trusted but does not count towards malicious score.
}


def check_trusted_provider(asn, organization, isp):
    """
    Check if the ASN, organization, or ISP matches a trusted provider.
    Handles cases where organization or ISP might be a list.
    """

    trusted_providers = {
        "13335": "Cloudflare",
        "15169": "Google",
        "8075": "Microsoft",
        "16509": "Amazon" 
        # Add other ASNs or organizations as needed
    }

    # Check ASN first
    if asn in trusted_providers:
        return trusted_providers[asn]

    # Default empty strings for None values
    asn = asn or ""
    organization = organization or ""
    isp = isp or ""

    # Ensure all values are strings before applying lower
    asn = str(asn).lower() if isinstance(asn, (str, int)) else ""
    organization = str(organization).lower() if isinstance(organization, str) else ""
    isp = str(isp).lower() if isinstance(isp, str) else ""

    # If organization or isp are lists, convert them to a comma-separated string
    if isinstance(organization, list):
        organization = ', '.join(organization)
    if isinstance(isp, list):
        isp = ', '.join(isp)

    # List of trusted providers with variations
    trusted_variations = {
        "Amazon": ["Amazon", "amazonaws.com", "amazon.com", "amazon"],
        "Google": ["Google", "GOOGLE", "google.com", "google.ca", "GOOGLE-CLOUD-PLATFORM", "google", "AS15169 google llc"],
        "Cloudflare": ["Cloudflare", "CLOUDFLARENET", "AS13335 cloudflare", "cloudflare"],
        "Microsoft": ["Microsoft", "MICROSOFT-CORP"],
        # Add other trusted providers as needed
    }

    # Normalize all values to lowercase for case-insensitive matching
    asn = asn.lower()
    organization = organization.lower()
    isp = isp.lower()

    # Check organization or ISP if ASN doesn't match
    if "cloudflare" in organization or "cloudflare" in isp or "cloudflarenet" in isp:
        return "Cloudflare"
    elif "google" in organization or "google" in isp:
        return "Google"
    elif "microsoft" in organization or "microsoft" in isp:
        return "Microsoft"

    # Check each provider and its variations
    for provider, variations in trusted_variations.items():
        if (asn == str(trusted_asn_list.get(provider, "")).lower()) or \
           any(var.lower() in organization for var in variations) or \
           any(var.lower() in isp for var in variations):
            return provider

    return None


def get_trusted_provider_text(ioc_type, trusted_provider):
    if trusted_provider:
        if ioc_type == "IP":
            return f"(Belongs to Trusted Provider: {trusted_provider})"
        elif ioc_type in ["Domain", "URL"]:
            return f"(Hosted on Trusted Provider: {trusted_provider})"
    else:
        return "(No Trusted Provider Detected)"



def calculate_total_malicious_score(reports, borealis_report, ioc_type, status_output=None, progress_bar=None):
    total_score = 0
    score_breakdown = []
    malicious_count = 0
    total_sources = 0
    trusted_provider_found = None
    breakdown_str = ""
    signature_info = {}
    current_date = datetime.now(timezone.utc)
    days_threshold = 14  # The 14-day threshold for recentness
    recent_analysis_weight_boost = 1.2  # Adjust weight by 20% if analysis is recent
    last_analysis_date = None
    # Define the threshold at the top of the script or within the scoring function
    high_malicious_count_threshold = 3


    # # Debugging to check Borealis report status
    # if borealis_report is None:
    #     print("DEBUG: Borealis report is None, skipping Borealis module processing.")
    # else:
    #     print("DEBUG: Borealis report received, proceeding with module extraction.")
        
    #  # Ensure status_output is passed if needed for VirusTotal
    # if status_output is None:
    #     status_output = []  # Default to an empty list or appropriate default object

    # Define maximum possible scores per validation source
    vendor_weights = {
        "VirusTotal": 4,
        "AbuseIPDB": 1,
        "AlienVault": 0.5,
        "GreyNoise": 1,
        "IPQualityScore": 1,
        "MalwareBazaar": 1,
        "URLScan": 1,
        "BinaryEdge": 1,
        "MetaDefender": 1,
        "AUWL": 1,
        "TOP1MILLION": 1,
        "ALPHABETSOUP": 1,
        "STONEWALL": 1,
        "Hybrid-Analysis": 1,
        "Censys": 1,
        # Adjust weights as necessary for new vendors or specific cases
    }


    # Function to calculate vendor score with recentness check
    def calculate_vendor_score(vendor, score, last_analysis_date=None):
        weight_factor = vendor_weights.get(vendor, 0)
    
        # Ensure current date is timezone-naive UTC
        current_date = datetime.utcnow().replace(tzinfo=None)
        
        # Boost weight if analysis is recent
        if last_analysis_date:
            # Make sure last_analysis_date is also timezone-naive for comparison
            last_analysis_date = last_analysis_date.replace(tzinfo=None)
            if current_date - last_analysis_date <= timedelta(days=days_threshold):
                weight_factor *= recent_analysis_weight_boost
    
        return score * weight_factor

    try:
        if ioc_type in ["ip", "url", "domain", "hash", "cve"]:

            # Extract Borealis report details
            borealis_breakdown = ""
            borealis_score = 0  # Set a default score for Borealis if not available
            if borealis_report and isinstance(borealis_report, dict):
                try:
                    # Attempt to extract details if available
                    borealis_breakdown, borealis_score = extract_borealis_info(borealis_report)
                    total_score += borealis_score
                except Exception as e:
                    # Log the error and continue without adding borealis_score
                    print(f"DEBUG: Error processing Borealis report: {e}")
                    borealis_breakdown = "Borealis report could not be processed due to an error."
            else:
                print("DEBUG: Borealis report is missing or invalid.")
                borealis_breakdown = "No Borealis report data available."
            
            # IP-based IOC
            if ioc_type == "ip":
                # VirusTotal parsing
                if 'VirusTotal' in reports:
                    vt_report = reports['VirusTotal']
                    malicious_count, suspicious_count, last_analysis_date_formatted, crowdsourced_context, tags, registrar, creation_date = extract_vt_analysis(vt_report)
                
                    # Adjusting VirusTotal score
                    vt_score = (malicious_count * 1) + (suspicious_count * 0.5)
                    vt_weighted_score = calculate_vendor_score("VirusTotal", vt_score, last_analysis_date)
                    total_score += vt_weighted_score
                    # Check if the last analysis date is within the last 14 days
                    
                    last_analysis_date = extract_last_analysis_date(vt_report)
                    if last_analysis_date:
                        last_analysis_date_formatted = last_analysis_date.strftime('%Y-%m-%d %H:%M:%S')
                        if isinstance(last_analysis_date, datetime) and (current_date - last_analysis_date <= timedelta(days=days_threshold)):
                            recent_analysis = True
                
                    # Safely extract additional fields with defaults
                    tags = ', '.join(vt_report['data']['attributes'].get('tags', [])) if vt_report['data']['attributes'].get('tags') else 'N/A'
                    registrar = vt_report['data']['attributes'].get('registrar', 'N/A')
                    creation_date = vt_report['data']['attributes'].get('creation_date', 'N/A')
                    
                    # Format creation date if available
                    if creation_date != 'N/A':
                        creation_date = format_date(creation_date)
                
                    # Extract and process categories and popularity ranks
                    categories = vt_report.get('data', {}).get('attributes', {}).get('categories', {})
                    categories_str = process_dynamic_field(categories)
                    popularity_ranks = vt_report.get('data', {}).get('attributes', {}).get('popularity_ranks', {})
                    popularity_str = process_dynamic_field(popularity_ranks)
                
                    # Update breakdown with extracted information
                    score_breakdown.append(f"VirusTotal:\n  Malicious={malicious_count}\n  Suspicious={suspicious_count}")
                    score_breakdown.append(f"  Tags: {tags}")
                    score_breakdown.append(f"  Categories: {categories_str}")
                    score_breakdown.append(f"  Popularity Ranks: {popularity_str}")
                    score_breakdown.append(f"  Registrar: {registrar}")
                    score_breakdown.append(f"  Creation Date: {creation_date}")
                    score_breakdown.append(f"  Last Analysis Date: {last_analysis_date_formatted}")
                    score_breakdown.append(f"  VirusTotal Score (Weighted): {vt_weighted_score}")
                
                    # Crowdsourced context, if present
                    if crowdsourced_context != 'N/A':
                        crowdsourced_context_formatted = format_crowdsourced_context(crowdsourced_context)
                        total_score += 1  # Additional weight for malicious indication in crowdsourced context
                        score_breakdown.append(f"  Crowdsourced Context:\n  {crowdsourced_context_formatted}")
                
                    # Process Livehunt YARA Rules
                    if 'Livehunt YARA Rules' in reports:
                        yara_rules = reports['Livehunt YARA Rules']
                        if yara_rules:
                            yara_score = len(yara_rules) * 1  # Weight each YARA rule
                            total_score += yara_score
                            score_breakdown.append(f"  Livehunt YARA Rules: {', '.join(yara_rules)}")
                
                    # Process Crowdsourced IDS Rules
                    if 'Crowdsourced IDS Rules' in reports:
                        ids_rules = reports['Crowdsourced IDS Rules']
                        if ids_rules:
                            formatted_ids_rules = "\n".join(
                                [f"    - {rule.get('rule_msg', 'N/A')} (Severity: {rule.get('alert_severity', 'N/A')}, Source: {rule.get('rule_source', 'N/A')}, URL: {rule.get('rule_url', 'N/A')})"
                                 for rule in ids_rules]
                            )
                            ids_score = len(ids_rules) * 1  # Weight each IDS rule
                            total_score += ids_score
                            score_breakdown.append(f"  Crowdsourced IDS Rules:\n  {formatted_ids_rules}")
                
                    # Process Dynamic Analysis Sandbox Detections
                    if 'Dynamic Analysis Sandbox Detections' in reports:
                        sandbox_detections = reports['Dynamic Analysis Sandbox Detections']
                        if sandbox_detections:
                            sandbox_score = len(sandbox_detections) * 1  # Weight each sandbox detection
                            total_score += sandbox_score
                            score_breakdown.append(f"  Dynamic Analysis Sandbox Detections: {', '.join(sandbox_detections)}")
                
                    # Process Signature Information
                    if 'Signature Information' in reports:
                        signature_info = reports['Signature Information']
                        if signature_info.get('valid_signature', False):
                            score_breakdown.append("  Signature Information: Valid Signature found")
                        else:
                            total_score += 1  # Increase score if signature is invalid or missing
                            score_breakdown.append("  Signature Information: Invalid or no signature")
    
                # AbuseIPDB parsing
                if 'AbuseIPDB' in reports:
                    abuseipdb_report = reports['AbuseIPDB']
                    confidence_score = int(abuseipdb_report.get('abuseConfidenceScore', 0))
                    last_seen = abuseipdb_report.get('lastSeen', None)
                    if last_seen:
                        try:
                            last_analysis_date = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                        except ValueError:
                            last_analysis_date = None
                    abuse_weighted_score = calculate_vendor_score("AbuseIPDB", confidence_score, last_analysis_date)
                    total_score += abuse_weighted_score
                    score_breakdown.append(f"AbuseIPDB Score (Weighted): {abuse_weighted_score}")
    
                # IPQualityScore parsing
                if 'IPQualityScore' in reports:
                    ipqs_report = reports.get("IPQualityScore", {})
                    if isinstance(ipqs_report, str):
                        ipqs_report = parse_ipqualityscore_report(ipqs_report)
                    
                    if isinstance(ipqs_report, dict) and ipqs_report:
                        # Extract relevant fields from IPQualityScore report
                        score_ipqs = int(ipqs_report.get("fraud_score", 0))  # Fraud score
                        vpn = ipqs_report.get("vpn", False)                  # VPN flag
                        tor = ipqs_report.get("tor", False)                  # TOR flag
                        proxy = ipqs_report.get("proxy", False)              # Proxy flag
                        malware = ipqs_report.get("malware", False)          # Malware flag
                        phishing = ipqs_report.get("phishing", False)        # Phishing flag
                        suspicious = ipqs_report.get("suspicious", False)    # Suspicious flag
                        
                        # Weights for each component
                        fraud_weight = 1       # Weight for fraud score
                        vpn_weight = 10        # VPN increases score by 10 if True
                        tor_weight = 15        # TOR increases score by 15 if True
                        proxy_weight = 5       # Proxy increases score by 5 if True
                        phishing_weight = 20   # Phishing increases score by 20 if True
                        malware_weight = 30    # Malware increases score by 30 if True
                        suspicious_weight = 10 # Suspicious increases score by 10 if True
                        
                        # Calculate total score for IPQualityScore by applying the weights
                        total_ipqs_score = (
                            score_ipqs * fraud_weight +
                            (vpn_weight if vpn else 0) +
                            (tor_weight if tor else 0) +
                            (proxy_weight if proxy else 0) +
                            (phishing_weight if phishing else 0) +
                            (malware_weight if malware else 0) +
                            (suspicious_weight if suspicious else 0)
                        )
                
                        # Add the weighted IPQualityScore contribution to the total score
                        ipqs_weighted_score = calculate_vendor_score("IPQualityScore", total_ipqs_score)
                        total_score += ipqs_weighted_score
                        malicious_count += 1  # If any conditions are flagged, consider it malicious
                        
                        # Append IPQualityScore details to the breakdown
                        score_breakdown.append(
                            f"IPQualityScore:\n  Fraud Score={score_ipqs}\n  VPN={vpn}\n"
                            f"  Tor={tor}\n  Proxy={proxy}\n  Phishing={phishing}\n"
                            f"  Malware={malware}\n  Suspicious={suspicious}\n"
                            f"  IPQS Score Contribution (Weighted): {ipqs_weighted_score}"
                        )
                        
                        # Trusted Provider Detection
                        asn = str(ipqs_report.get("asn", ""))
                        isp = ipqs_report.get("isp", "")
                        organization = ipqs_report.get("organization", "")
                        
                        # Check for trusted provider
                        provider = check_trusted_provider(asn, organization, isp)
                        if provider:
                            trusted_provider_found = provider
                            score_breakdown.append(f"  IP belongs to trusted provider ({trusted_provider_found})...Proceed with caution")
                        else:
                            score_breakdown.append("  No Trusted Provider Detected in IPQualityScore")
                    else:
                        score_breakdown.append("IPQualityScore: No data available")
    
                # GreyNoise parsing
                if 'GreyNoise' in reports:
                    greynoise_report = reports.get("GreyNoise", {})
                    if isinstance(greynoise_report, dict):
                        classification = greynoise_report.get("classification", "unknown")
                        total_sources += 1
                        if classification != "benign":
                            malicious_count += 1
                            #vendor_contributions["GreyNoise"] += 1
                        score_breakdown.append(f"GreyNoise:\n  Classification={classification}")
    
                # AlienVault parsing
                if 'AlienVault' in reports:
                    alienvault_report = reports.get("AlienVault", {})
                    if isinstance(alienvault_report, dict):
                        # Extract relevant fields
                        pulses = alienvault_report.get("pulse_count", 0)
                        malware_families = alienvault_report.get("malware_families", 0)
                        asn = alienvault_report.get("asn", "").split()[0] if alienvault_report.get("asn") else "N/A"  # Extract ASN if available
                        organization = alienvault_report.get("organization", "")
                        isp = alienvault_report.get("isp", "")
                        indicator = alienvault_report.get("indicator", "")
                        
                        # Calculate score based on AlienVault fields
                        pulses_score = pulses * 2    # Weight each pulse by 2
                        malware_score = malware_families * 5  # Weight each malware family by 5
                        total_alienvault_score = pulses_score + malware_score
                        
                        # Calculate weighted AlienVault score, applying recentness boost if applicable
                        alienvault_weighted_score = calculate_vendor_score("AlienVault", total_alienvault_score)
                        total_score += alienvault_weighted_score
                        malicious_count += 1 if pulses > 0 or malware_families > 0 else 0  # Consider it malicious if any pulses or malware families exist
                        
                        # Debug: Output extracted values
                        print(f"DEBUG: ASN = {asn}, Organization = {organization}, ISP = {isp}, Indicator = {indicator}")
                        
                        # Add AlienVault details to the breakdown
                        score_breakdown.append(
                            f"AlienVault:\n  Pulses={pulses}\n  Malware Families={malware_families}\n"
                            f"  ASN={asn}\n  AlienVault Score Contribution (Weighted): {alienvault_weighted_score}"
                        )
                        
                        # Check for trusted provider using ASN, organization, and ISP
                        provider = check_trusted_provider(asn, organization, isp)
                        if provider:
                            trusted_provider_found = provider
                            score_breakdown.append(f"  Trusted Provider Detected in AlienVault: {trusted_provider_found}...Proceed with caution")
                        else:
                            score_breakdown.append("  No Trusted Provider Detected in AlienVault")
                    else:
                        score_breakdown.append("AlienVault: No data available")
                
                    
    
                # Shodan parsing
                if 'Shodan' in reports:
                    shodan_report = reports.get("Shodan", {})
                    if isinstance(shodan_report, dict):
                        # Extract ASN and organization for trusted provider check
                        asn = str(shodan_report.get("asn", ""))
                        organization = shodan_report.get("organization", "")
                        isp = shodan_report.get("isp", "")
                
                        # Trusted provider detection using ASN, organization, and ISP
                        provider = check_trusted_provider(asn, organization, isp)
                        if provider:
                            trusted_provider_found = provider
                            score_breakdown.append(f"Trusted Provider Detected in Shodan: {trusted_provider_found}...Proceed with caution")
                        else:
                            score_breakdown.append("No Trusted Provider Detected in Shodan")
                    else:
                        score_breakdown.append("Shodan: No data available")
    
                # BinaryEdge parsing
                if 'BinaryEdge' in reports:
                    binaryedge_report = reports.get("BinaryEdge", {})
                    if isinstance(binaryedge_report, dict):
                        # Get the total number of events from BinaryEdge report
                        events = binaryedge_report.get('total', 0)
                        
                        # Calculate the BinaryEdge score based on the event count
                        binaryedge_weighted_score = calculate_vendor_score("BinaryEdge", events)
                        total_score += binaryedge_weighted_score
                        
                        # Add BinaryEdge details to the breakdown
                        score_breakdown.append(f"BinaryEdge:\n  Total Events={events}\n  BinaryEdge Score Contribution (Weighted): {binaryedge_weighted_score}")
                    else:
                        score_breakdown.append("BinaryEdge: No data available")
    
                # Metadefender parsing
                if 'Metadefender' in reports:
                    metadefender_report = reports.get("Metadefender", {})
                    if isinstance(metadefender_report, dict):
                        detected_by = metadefender_report.get('detected_by', 0)
                        
                        # Calculate weighted score based on the number of detections
                        metadefender_score = detected_by * 3  # Weight each detection by 3
                        metadefender_weighted_score = calculate_vendor_score("MetaDefender", metadefender_score)
                        total_score += metadefender_weighted_score
                        
                        # Add Metadefender details to the breakdown
                        score_breakdown.append(f"Metadefender:\n  Detected By={detected_by}\n  Metadefender Score Contribution (Weighted): {metadefender_weighted_score}")
                    else:
                        score_breakdown.append("Metadefender: No data available")
    
                # Append Borealis info if present
                if borealis_breakdown:
                    score_breakdown.append(f"Borealis Report:\n{borealis_breakdown}")
    
                # Stonewall parsing (approval for blocking)
                if 'STONEWALL' in borealis_report:
                    stonewall_report = borealis_report.get("STONEWALL", {})
                    approved_for_blocking = stonewall_report.get("approved", False)
                    
                    # Apply a high score for Stonewall-approved blocking
                    if approved_for_blocking:
                        stonewall_weighted_score = calculate_vendor_score("STONEWALL", approved_for_blocking * 1)
                        total_score += stonewall_weighted_score
                        malicious_count += 1  # Mark as malicious due to blocking approval
                        score_breakdown.append(f"Stonewall: Approved for blocking (malicious)\n  Stonewall Score Contribution (Weighted): {stonewall_weighted_score}")
                    else:
                        score_breakdown.append("Stonewall: Not approved for blocking")
                else:
                    score_breakdown.append("Stonewall: No relevant data found.")
    
            # URL and Domain-based IOC
            elif ioc_type in ["url", "domain"]:
                # VirusTotal parsing
                if 'VirusTotal' in reports:
                    vt_report = reports['VirusTotal']
                    try:
                        print("DEBUG: Processing VirusTotal report for score breakdown...")  # Debugging statement
                
                        # Extract main data from VirusTotal
                        malicious_count, suspicious_count, last_analysis_date, crowdsourced_context, *_ = extract_vt_analysis(vt_report)
                
                        # Convert last_analysis_date to timezone-naive UTC
                        if isinstance(last_analysis_date, str):
                            try:
                                # Convert from ISO string to a UTC timezone-naive datetime
                                last_analysis_date = datetime.fromisoformat(last_analysis_date.replace("Z", "+00:00"))
                                last_analysis_date = last_analysis_date.astimezone(timezone.utc).replace(tzinfo=None)
                            except ValueError:
                                last_analysis_date = None  # Set to None if conversion fails
                        elif isinstance(last_analysis_date, (int, float)):
                            # Convert timestamp to naive UTC datetime
                            last_analysis_date = datetime.utcfromtimestamp(last_analysis_date).replace(tzinfo=None)
                        elif isinstance(last_analysis_date, datetime):
                            # Handle existing datetime by making it naive in UTC
                            last_analysis_date = last_analysis_date.astimezone(timezone.utc).replace(tzinfo=None)
                        
                        # Ensure any other datetime in calculations is also naive
                        current_time = datetime.utcnow().replace(tzinfo=None)
                
                        print(f"DEBUG: last_analysis_date (timezone-naive) is {last_analysis_date}")  # Debugging statement
                
                        # Calculate score and add to total
                        vt_score = (malicious_count * 1) + (suspicious_count * 0.5)
                        vt_weighted_score = calculate_vendor_score("VirusTotal", vt_score, last_analysis_date)
                        total_score += vt_weighted_score
                        print(f"DEBUG: VirusTotal Score: {vt_weighted_score}, Total Score: {total_score}")  # Debugging statement
                
                        # Extract and safely format additional fields with defaults
                        tags = ', '.join(vt_report['data']['attributes'].get('tags', [])) if vt_report['data']['attributes'].get('tags') else 'N/A'
                        registrar = vt_report['data']['attributes'].get('registrar', 'N/A')
                        creation_date = format_date(vt_report['data']['attributes'].get('creation_date', 'N/A'))
                        categories_str = process_dynamic_field(vt_report.get('data', {}).get('attributes', {}).get('categories', {}))
                        popularity_str = process_dynamic_field(vt_report.get('data', {}).get('attributes', {}).get('popularity_ranks', {}))
                
                        # Append VirusTotal details to the score breakdown
                        score_breakdown.append("VirusTotal:")
                        score_breakdown.append(f"  Malicious={malicious_count}, Suspicious={suspicious_count}")
                        score_breakdown.append(f"  Tags: {tags}")
                        score_breakdown.append(f"  Categories: {categories_str}")
                        score_breakdown.append(f"  Popularity Ranks: {popularity_str}")
                        score_breakdown.append(f"  Registrar: {registrar}")
                        score_breakdown.append(f"  Creation Date: {creation_date}")
                        score_breakdown.append(f"  Last Analysis Date: {last_analysis_date.strftime('%Y-%m-%d %H:%M:%S') if last_analysis_date else 'N/A'}")
                
                        print("DEBUG: VirusTotal score breakdown added.")  # Debugging statement
                
                        # Last downloaded file info
                        last_downloaded_file_hash = vt_report['data']['attributes'].get('last_http_response_content_sha256', None)
                        last_downloaded_file_info = "No last downloaded file found"
                
                        if last_downloaded_file_hash:
                            try:
                                # Attempt to retrieve the file report based on hash
                                file_report = get_hash_report(last_downloaded_file_hash, status_output=status_output, progress_bar=progress_bar)
                                
                                if file_report and isinstance(file_report, dict):
                                    file_name = file_report['basic_properties'].get('file_name', 'N/A')
                                    file_type = file_report['basic_properties'].get('file_type', 'N/A')
                                    detection_count = len(file_report.get('malicious_vendors', []))
                                    total_vendors = file_report['basic_properties'].get('total_av_engines', 63)
                                    file_analysis_date = file_report['basic_properties'].get('last_analysis_date', 'N/A')
                
                                    detection_info = f"{detection_count}/{total_vendors} security vendors detected this file"
                                    last_downloaded_file_info = (
                                        f"  {file_name} of type {file_type}\n"
                                        f"  with sha256 {last_downloaded_file_hash}\n  detected by {detection_info}\n"
                                        f"  on {file_analysis_date} UTC"
                                    )
                                else:
                                    last_downloaded_file_info = f"Last downloaded file SHA256: {last_downloaded_file_hash} (No details found)"
                            except Exception as e:
                                print(f"DEBUG: Error fetching file report for hash {last_downloaded_file_hash}: {e}")
                                last_downloaded_file_info = f"Last downloaded file SHA256: {last_downloaded_file_hash} (Error fetching details)"
                        
                        score_breakdown.append(f"  Last Downloaded File:\n{last_downloaded_file_info}")
                
                        # Crowdsourced context
                        if crowdsourced_context != 'N/A':
                            crowdsourced_context_formatted = format_crowdsourced_context(crowdsourced_context)
                            total_score += 15  # Additional score for malicious crowdsourced context
                            score_breakdown.append(f"  Crowdsourced Context:\n  {crowdsourced_context_formatted}")
                            print("DEBUG: Crowdsourced context added to score breakdown.")  # Debugging statement
                
                    except Exception as e:
                        print(f"DEBUG: Error in VirusTotal parsing: {e}")
            
                # URLScan parsing
                if 'URLScan' in reports:
                    urlscan_report = reports.get("URLScan", {})
                    if isinstance(urlscan_report, dict):
                        try:
                            if not urlscan_report.get('Resolving', True):
                                score_breakdown.append("URLScan:\n  The domain isn't resolving. No malicious score.")
                            else:
                                malicious_urls = urlscan_report.get('Malicious Score', 0)
                                tls_issuer = urlscan_report.get('TLS Issuer', 'N/A')
                                tls_age = urlscan_report.get('TLS Age (days)', 'N/A')
                                redirected = urlscan_report.get('Redirected', 'N/A')
                                asn = str(urlscan_report.get("ASN", ""))
                                organization = urlscan_report.get("Organization", "")
                                domain = urlscan_report.get("Domain", "N/A")
                                isp = urlscan_report.get("ISP", "N/A")
                                last_analysis_date_str = urlscan_report.get("Last Analysis Date", "N/A")
                                
                                # Convert last_analysis_date to datetime if it's a string
                                if isinstance(last_analysis_date_str, str) and last_analysis_date_str != "N/A":
                                    try:
                                        last_analysis_date = datetime.fromisoformat(last_analysis_date_str.replace("Z", "+00:00"))
                                    except ValueError:
                                        print(f"DEBUG: Unable to parse last_analysis_date '{last_analysis_date_str}' as datetime")
                                        last_analysis_date = None
                                else:
                                    last_analysis_date = last_analysis_date_str  # Keep as is if already datetime or not available
                                
                                # Calculate URLScan score contribution
                                urlscan_weighted_score = calculate_vendor_score("URLScan", malicious_urls, last_analysis_date)
                                total_score += urlscan_weighted_score
                                malicious_count += 1 if malicious_urls > 0 else 0
                
                                # Append URLScan details to the breakdown
                                score_breakdown.append(
                                    f"URLScan:\n  Malicious Score={malicious_urls}\n  ISP={isp}\n"
                                    f"  TLS Issuer={tls_issuer}\n  TLS Age={tls_age} days\n"
                                    f"  Redirected={redirected}\n  Last Analysis Date={last_analysis_date_str}\n"
                                    f"  URLScan Score Contribution (Weighted): {urlscan_weighted_score}"
                                )
                
                                # Trusted provider detection
                                provider = check_trusted_provider(asn, organization, isp)
                                if provider:
                                    trusted_provider_found = provider
                                    score_breakdown.append(f"  Domain is hosted on a trusted provider (ISP: {trusted_provider_found})...Proceed with caution")
                                else:
                                    score_breakdown.append("  No Trusted Provider Detected in URLScan")
                        except Exception as e:
                            print(f"DEBUG: Error in URLScan parsing: {e}")
                    else:
                        score_breakdown.append("URLScan: No data available")
            
                # IPQualityScore parsing for URLs/Domains
                if 'IPQualityScore' in reports:
                    ipqs_report = reports.get("IPQualityScore", {})
                    if isinstance(ipqs_report, dict):
                        try:
                            score_ipqs = int(ipqs_report.get("risk_score", 0))
                            vpn = ipqs_report.get("vpn", False)
                            tor = ipqs_report.get("tor", False)
                            proxy = ipqs_report.get("proxy", False)
                            phishing = ipqs_report.get("phishing", False)
                            malware = ipqs_report.get("malware", False)
                            server = ipqs_report.get("server", "N/A")
                            suspicious = ipqs_report.get("suspicious", False)
            
                            total_ipqs_score = (
                                score_ipqs * 1 +
                                (10 if vpn else 0) +
                                (15 if tor else 0) +
                                (5 if proxy else 0) +
                                (20 if phishing else 0) +
                                (30 if malware else 0) +
                                (10 if suspicious else 0)
                            )
            
                            ipqs_weighted_score = calculate_vendor_score("IPQualityScore", total_ipqs_score)
                            total_score += ipqs_weighted_score
                            malicious_count += 1 if total_ipqs_score > 0 else 0
            
                            score_breakdown.append(
                                f"IPQualityScore:\n  Risk Score={score_ipqs}\n  VPN={vpn}\n"
                                f"  Tor={tor}\n  Proxy={proxy}\n  Phishing={phishing}\n"
                                f"  Malware={malware}\n  Server={server}\n  Suspicious={suspicious}\n"
                                f"  IPQS Score Contribution (Weighted): {ipqs_weighted_score}"
                            )
            
                            provider = check_trusted_provider("", "", server)
                            if provider:
                                trusted_provider_found = provider
                                score_breakdown.append(f"  Domain is hosted on a trusted provider (ISP: {trusted_provider_found})...Proceed with caution")
                            else:
                                score_breakdown.append("  No Trusted Provider Detected in IPQualityScore")
                        except Exception as e:
                            print(f"DEBUG: Error in IPQualityScore parsing: {e}")
                    else:
                        score_breakdown.append("IPQualityScore: No data available")
                
                # AlienVault parsing for URLs/Domains
                if 'AlienVault' in reports:
                    alienvault_report = reports.get("AlienVault", {})
                    if isinstance(alienvault_report, dict):
                        try:
                            pulses = alienvault_report.get("pulse_count", 0)
                            malware_families = alienvault_report.get("malware_families", 0)
                            asn = str(alienvault_report.get("asn", ""))
                            organization = alienvault_report.get("organization", "")
                            domain = alienvault_report.get("domain", "N/A")
                            isp = alienvault_report.get("isp", "N/A")
            
                            alienvault_score = (pulses * 1) + (malware_families * 2)
                            alienvault_weighted_score = calculate_vendor_score("AlienVault", alienvault_score)
                            total_score += alienvault_weighted_score
            
                            score_breakdown.append(
                                f"AlienVault:\n  Pulses={pulses}\n  Malware Families={malware_families}\n"
                                f"  ASN={asn}\n  Organization={organization}\n  Domain={domain}\n  ISP={isp}\n"
                                f"  AlienVault Score Contribution (Weighted): {alienvault_weighted_score}"
                            )
            
                            provider = check_trusted_provider(asn, organization, isp)
                            if provider:
                                trusted_provider_found = provider
                                score_breakdown.append(f"  Domain is hosted on a trusted provider: {trusted_provider_found}...Proceed with caution")
                            else:
                                score_breakdown.append("  No Trusted Provider Detected in AlienVault")
                        except Exception as e:
                            print(f"DEBUG: Error in AlienVault parsing: {e}")
                    else:
                        score_breakdown.append("AlienVault: No data available")
            
                # BinaryEdge parsing for URLs/Domains
                if 'BinaryEdge' in reports:
                    binaryedge_report = reports.get("BinaryEdge", {})
                    if isinstance(binaryedge_report, dict):
                        try:
                            events = binaryedge_report.get('total', 0)
                            binaryedge_weighted_score = calculate_vendor_score("BinaryEdge", events)
                            total_score += binaryedge_weighted_score
                            score_breakdown.append(f"BinaryEdge:\n  Total Events={events}\n  BinaryEdge Score Contribution (Weighted): {binaryedge_weighted_score}")
                            
                            parsed_binaryedge_info = parse_binaryedge_report(binaryedge_report, ioc_type)
                            score_breakdown.append(f"  Details:\n{parsed_binaryedge_info}")
                        except Exception as e:
                            print(f"DEBUG: Error in BinaryEdge parsing: {e}")
                    else:
                        score_breakdown.append("BinaryEdge: No data available")
            
                # Metadefender parsing for URLs/Domains
                if 'MetaDefender' in reports:
                    metadefender_report = reports.get("MetaDefender", {})
                    if isinstance(metadefender_report, dict):
                        try:
                            detected_by = metadefender_report.get('detected_by', 0)
                            metadefender_weighted_score = calculate_vendor_score("MetaDefender", detected_by * 3)
                            total_score += metadefender_weighted_score
                            score_breakdown.append(f"MetaDefender:\n  Detected By={detected_by}\n  MetaDefender Score Contribution (Weighted): {metadefender_weighted_score}")
                        except Exception as e:
                            print(f"DEBUG: Error in MetaDefender parsing: {e}")
                    else:
                        score_breakdown.append("MetaDefender: No data available")
            
                # Borealis-related sections (AUWL, AlphabetSoup, etc.)
                if borealis_breakdown:
                    try:
                        score_breakdown.append(f"Borealis Report:\n{borealis_breakdown}")
                    except Exception as e:
                        print(f"DEBUG: Error in Borealis parsing: {e}")
            
                # AUWL parsing for URLs/Domains
                if "AUWL" in borealis_report:
                    try:
                        auwl_report = borealis_report.get("AUWL", [])
                        phishing_count = 0
                        for cluster in auwl_report:
                            cluster_name = cluster.get('clusterName', 'N/A')
                            cluster_category = cluster.get('clusterCategory', 'N/A')
                            if cluster_category.lower() == "phishing":
                                phishing_count += 1
                            score_breakdown.append(f"AUWL Cluster: {cluster_name}, Category: {cluster_category}")
                        
                        auwl_weighted_score = calculate_vendor_score("AUWL", phishing_count)
                        total_score += auwl_weighted_score
                        malicious_count += phishing_count
                        score_breakdown.append(f"AUWL: - Score Contribution: {auwl_weighted_score}")
                    except Exception as e:
                        print(f"DEBUG: Error in AUWL parsing: {e}")
                else:
                    score_breakdown.append("AUWL: No relevant data found.")
            
                # AlphabetSoup parsing (DGA detection)
                if "ALPHABETSOUP" in borealis_report:
                    try:
                        alphabetsoup_report = borealis_report.get("ALPHABETSOUP", {})
                        
                        # Check if DGA is detected
                        dga_detected = alphabetsoup_report.get("isDGA", False)
                        
                        if dga_detected:
                            # If DGA is detected, add a score contribution
                            alphabetsoup_weighted_score = calculate_vendor_score("ALPHABETSOUP", 1)
                            total_score += alphabetsoup_weighted_score
                            malicious_count += 1
                            score_breakdown.append(f"AlphabetSoup: DGA Detected (malicious) - Score Contribution: {alphabetsoup_weighted_score}")
                        else:
                            score_breakdown.append("AlphabetSoup: No DGA detected")
                    
                    except Exception as e:
                        print(f"DEBUG: Error in AlphabetSoup parsing: {e}")
                else:
                    score_breakdown.append("AlphabetSoup: No relevant data found.")
            
                # Top1M parsing (Majestic, Tranco, Cisco block detection)
                if "TOP1MILLION" in borealis_report:
                    try:
                        top1m_report = borealis_report.get("TOP1MILLION", [])
                        
                        # Initialize counters
                        blocked_by = []
                        
                        # Loop through each entry in TOP1MILLION report
                        for entry in top1m_report:
                            list_name = entry.get("listName", "Unknown")
                            in_list = entry.get("inList", False)
                            
                            # If the domain is blocked in this list, include it in scoring
                            if in_list:
                                blocked_by.append(list_name)
                                
                                # Optionally include rank or other details in the breakdown
                                rank = entry.get("rank", "N/A")
                                score_breakdown.append(f"  {list_name.capitalize()} list - In List: {in_list}, Rank: {rank}")
                        
                        # Calculate score based on the number of lists blocking this domain
                        if blocked_by:
                            top1m_weighted_score = calculate_vendor_score("TOP1MILLION", len(blocked_by))
                            total_score += top1m_weighted_score
                            malicious_count += 1
                            score_breakdown.append(f"Top1M: Blocked by {', '.join(blocked_by)} - Score Contribution: {top1m_weighted_score}")
                        else:
                            score_breakdown.append("Top1M: Not blocked by Majestic, Tranco, or Cisco")
                    
                    except Exception as e:
                        print(f"DEBUG: Error in Top1M parsing: {e}")
                else:
                    score_breakdown.append("Top1M: No relevant data found.")
            
                # Stonewall parsing (approval for blocking)
                if "STONEWALL" in borealis_report:
                    try:
                        stonewall_report = borealis_report.get("STONEWALL", {})
                        approved_for_blocking = stonewall_report.get("approved", False)
                        if approved_for_blocking:
                            stonewall_weighted_score = calculate_vendor_score("STONEWALL", 1)
                            total_score += stonewall_weighted_score
                            malicious_count += 1
                            score_breakdown.append(f"Stonewall: Approved for blocking (malicious) - Score Contribution: {stonewall_weighted_score}")
                        else:
                            score_breakdown.append("Stonewall: Not approved for blocking")
                    except Exception as e:
                        print(f"DEBUG: Error in Stonewall parsing: {e}")
                else:
                    score_breakdown.append("Stonewall: No relevant data found.")
    
            # Hash-based IOC
            elif ioc_type == "hash":
                # VirusTotal parsing
                if 'VirusTotal' in reports:
                    vt_report = reports['VirusTotal']
                    malicious_count, suspicious_count, last_analysis_date_formatted, crowdsourced_context, tags, registrar, creation_date = extract_vt_analysis(vt_report)
                
                    malicious_count = malicious_count or 0
                    suspicious_count = suspicious_count or 0
                
                    # Calculate and add VirusTotal score directly without max score limit
                    vt_score = (malicious_count * 1) + (suspicious_count * 0.5)
                    total_score += vt_score
                
                    # Extract categories, popularity ranks, and additional details
                    categories = vt_report.get('data', {}).get('attributes', {}).get('categories', {})
                    categories_str = process_dynamic_field(categories)
                    popularity_ranks = vt_report.get('data', {}).get('attributes', {}).get('popularity_ranks', {})
                    popularity_str = process_dynamic_field(popularity_ranks)
                
                    # Update score breakdown with extracted details
                    score_breakdown.append(f"VirusTotal:\n  Malicious={malicious_count}\n  Suspicious={suspicious_count}")
                    score_breakdown.append(f"  Categories: {categories_str}")
                    score_breakdown.append(f"  Popularity Ranks: {popularity_str}")
                    score_breakdown.append(f"  Tags: {tags}")
                    score_breakdown.append(f"  Last Analysis Date: {last_analysis_date_formatted}")
                
                    # Process and score signature information
                    signature_info = vt_report.get('data', {}).get('attributes', {}).get('signature_info', {})
                    if isinstance(signature_info, dict):
                        verified = signature_info.get('verified', 'Invalid')
                        signers = ', '.join(signature_info.get('signers', 'Unknown')) if isinstance(signature_info.get('signers'), list) else "Unknown"
                        
                        if verified == 'Signed':
                            score_breakdown.append(f"  Signature: Valid (Signed by: {signers})")
                            total_score -= 2  # Reduce score for valid signature
                        else:
                            score_breakdown.append("  Signature: Invalid or not present")
                            total_score += 20  # Increase score if invalid or not found
                    else:
                        score_breakdown.append("  Signature: No signature information available")
                
                    # Format and add crowdsourced context
                    crowdsourced_context_formatted = format_crowdsourced_context(crowdsourced_context) if isinstance(crowdsourced_context, dict) else crowdsourced_context or 'N/A'
                    score_breakdown.append(f"  Crowdsourced Context: {crowdsourced_context_formatted}")
                
                    # Process and score threat severity
                    threat_severity = vt_report.get('data', {}).get('attributes', {}).get('threat_severity', {})
                    severity_level = threat_severity.get('level_description', 'N/A')
                    threat_category = threat_severity.get('threat_severity_data', {}).get('popular_threat_category', 'N/A')
                    num_gav_detections = threat_severity.get('threat_severity_data', {}).get('num_gav_detections', 0)
                    
                    score_breakdown.append(f"  Threat Severity: {severity_level}, Category: {threat_category}, GAV Detections: {num_gav_detections}")
                    total_score += 10  # Adjust score based on threat severity
                
                    # Process Sigma rules and add score
                    sigma_rules = vt_report.get('data', {}).get('attributes', {}).get('sigma_analysis_results', [])
                    if sigma_rules:
                        sigma_rule_names = [rule.get('rule_title', 'Unknown Sigma Rule') for rule in sigma_rules]
                        score_breakdown.append(f"  Sigma Rules: {', '.join(sigma_rule_names)}")
                        total_score += len(sigma_rules) * 5
                
                    # YARA Rules (Livehunt) parsing and scoring
                    livehunt_yara_rules = vt_report.get('livehunt_yara_rules', [])
                    if livehunt_yara_rules:
                        total_score += len(livehunt_yara_rules) * 10  # Weight for each matching YARA rule
                        score_breakdown.append(f"  Livehunt YARA Rules: {', '.join([rule['rule_name'] for rule in livehunt_yara_rules])}")
                
                    # Crowdsourced YARA rules parsing and scoring
                    crowdsourced_yara_rules = vt_report.get('crowdsourced_yara_rules', [])
                    if crowdsourced_yara_rules:
                        total_score += len(crowdsourced_yara_rules) * 5  # Weight for each community YARA rule
                        score_breakdown.append(f"  Crowdsourced YARA Rules: {', '.join([rule['rule_name'] for rule in crowdsourced_yara_rules])}")
                
                    # Dynamic Analysis Sandbox Detections parsing and scoring
                    sandbox_detections = vt_report.get('sandbox_verdicts', [])
                    if sandbox_detections:
                        total_score += len(sandbox_detections) * 8  # Weight for each sandbox detection
                        score_breakdown.append(f"  Dynamic Analysis Sandbox Detections: {', '.join([d['verdict'] for d in sandbox_detections])}")
                
                else:
                    score_breakdown.append("VirusTotal: No data available")
    
    
                # MalwareBazaar parsing
                if 'MalwareBazaar' in reports:
                    malwarebazaar_report = reports.get("MalwareBazaar", {})
                    if isinstance(malwarebazaar_report, dict):
                        country = malwarebazaar_report.get("origin_country", "N/A")
                        intelligence = malwarebazaar_report.get("intelligence", {})
                        downloads = int(intelligence.get("downloads", 0))
                        uploads = int(intelligence.get("uploads", "0"))
                        delivery_method = malwarebazaar_report.get("delivery_method", "N/A")
                        
                        tags = ', '.join(malwarebazaar_report.get('tags', [])) if malwarebazaar_report.get('tags') else 'N/A'
                        filename = malwarebazaar_report.get("file_name", "N/A")
                
                        if country != "N/A" or downloads > 0:
                            malicious_count += 1
                        score_breakdown.append(f"MalwareBazaar:\n  Country={country}\n  Downloads={downloads}\n  Filename={filename}\n  Uploads={uploads}\n  Delivery Method={delivery_method}\n  Tags={tags}")
                        total_sources += 1
                        total_score += downloads
                    else:
                        score_breakdown.append("MalwareBazaar: No data available")
    
                # AlienVault parsing for hashes
                if 'AlienVault' in reports:
                    alienvault_report = reports.get("AlienVault", {})
                    if isinstance(alienvault_report, dict):
                        pulses = alienvault_report.get("pulse_count", 0)
                        malware_families = alienvault_report.get("malware_families", 0)
                        total_sources += 1
                        if pulses + malware_families > 0:
                            malicious_count += 1
                        score_breakdown.append(f"AlienVault:\n  Pulses={pulses}\n  Malware Families={malware_families}")
                    else:
                        score_breakdown.append("AlienVault: No data available")
    
                # Metadefender parsing for hashes
                if 'MetaDefender' in reports:
                    metadefender_report = reports.get("MetaDefender", {})
                    if isinstance(metadefender_report, dict):
                        detected_by = metadefender_report.get('detected_by', 0) or 0
                        total_score += detected_by * 3
                        score_breakdown.append(f"MetaDefender:\n  Detected By={detected_by}")
                    else:
                        score_breakdown.append("MetaDefender: No data available")
    
    
                # Hybrid Analysis parsing
                if 'Hybrid-Analysis' in reports:
                    hybrid_analysis_report = reports.get("Hybrid-Analysis", {})
                    if isinstance(hybrid_analysis_report, dict):
                        # Extract relevant fields
                        file_name = hybrid_analysis_report.get("submit_name", hybrid_analysis_report.get("file_name", "N/A"))
                        threat_score = hybrid_analysis_report.get("threat_score", 0) or 0
                        verdict = hybrid_analysis_report.get("verdict", "N/A")
                        classification_tags = ''.join(hybrid_analysis_report.get("classification_tags", [])) if hybrid_analysis_report.get("classification_tags") else "None"
                        vx_family = hybrid_analysis_report.get("vx_family", "N/A")
                        total_processes = hybrid_analysis_report.get("total_processes", 0)
                        total_network_connections = hybrid_analysis_report.get("total_network_connections", 0)
                        
                        # Process MITRE ATT&CK data
                        mitre_attcks = hybrid_analysis_report.get("mitre_attcks", [])
                        mitre_attcks_str = ', '.join(
                            [f"{attack.get('tactic', 'N/A')} - {attack.get('technique', 'N/A')} (ID: {attack.get('attck_id', 'N/A')})" for attack in mitre_attcks]
                        ) if isinstance(mitre_attcks, list) else mitre_attcks if isinstance(mitre_attcks, str) else "None"
                        
                        # Calculate Hybrid-Analysis contribution based on threat score, weighted by 3
                        ha_score = threat_score * 3
                        total_score += ha_score  # Directly add the calculated score
                        
                        # Append Hybrid-Analysis details to the score breakdown
                        score_breakdown.append(
                            f"Hybrid Analysis:\n  Verdict: {verdict}\n  Threat Score: {threat_score}\n"
                            f"  File Name: {file_name}\n  Classification Tags: {classification_tags}\n"
                            f"  Family: {vx_family}\n  Total Processes: {total_processes}\n"
                            f"  Total Network Connections: {total_network_connections}\n"
                            f"  MITRE ATT&CK Tactics: {mitre_attcks_str}\n"
                            f"  Hybrid Analysis Score Contribution: {ha_score}"
                        )
                    else:
                        score_breakdown.append("Hybrid Analysis: No data available")
    
            elif ioc_type == "cve":
                
                if 'Shodan' in reports:
                    shodan_report = reports.get("Shodan", {})
                
                    if isinstance(shodan_report, dict):
                        cve_results = shodan_report.get("matches", [])
                    
                        # Extract facets for reporting
                        facets = shodan_report.get("facets", {})
                        if facets:
                            score_breakdown.append("Shodan CVE Facet Information:")
                            for key, values in facets.items():
                                if isinstance(values, list) and values:
                                    # Extract the first facet item for reporting purposes
                                    facet_value = values[0]
                                    value_name = facet_value.get("value", "Unknown")
                                    count = facet_value.get("count", 0)
                                    score_breakdown.append(f"  {key.capitalize()}: {value_name} (Count: {count})")
                    
                        # Process CVE results
                        if isinstance(cve_results, list) and cve_results:
                            score_breakdown.append("Shodan CVE Report:\n  Found CVE entries.")
                    
                            for match in cve_results:
                                if isinstance(match, dict):
                                    vulns = match.get('vulns', {})  # Access 'vulns' inside each 'match'
                    
                                    if isinstance(vulns, dict):
                                        for cve_id, details in vulns.items():  # Iterate over CVEs in 'vulns'
                                            if isinstance(details, dict):
                                                cvss_score = details.get('cvss', 'N/A')
                    
                                                # Append CVE details without adding to total score
                                                if isinstance(cvss_score, (int, float)):
                                                    score_breakdown.append(f"  CVE: {cve_id}, CVSS Score: {cvss_score}")
                                                else:
                                                    score_breakdown.append(f"  CVE: {cve_id}, CVSS Score: Not Available")
                                            else:
                                                score_breakdown.append(f"Invalid format for CVE {cve_id}. Expected a dictionary.")
                                    else:
                                        score_breakdown.append("Invalid 'vulns' format, expected a dictionary.")
                                else:
                                    score_breakdown.append("Invalid match format: Expected a dictionary")
                        else:
                            score_breakdown.append("Shodan CVE Report: No CVSS scores found or invalid data format")
                    else:
                        score_breakdown.append("Shodan CVE Report: No valid report data")
    
                # Censys parsing for CVEs and Score Breakdown
                if ioc_type == "cve" and 'Censys' in reports:
                    censys_report = reports['Censys']
                    
                    if isinstance(censys_report, list):
                        score_breakdown.append("Censys CVE Report:\n  Found CVE entries.")
                        
                        for result in censys_report:
                            ip = result.get("IP", "N/A")
                            services = result.get("Services", [])
                            cves = result.get("CVEs", [])
                            
                            # Collect CVE scores for each service without affecting the total score
                            for service in services:
                                cve_list = result.get("CVEs", [])
                                for cve in cve_list:
                                    cve_id = cve.get("CVE ID", "N/A")
                                    cvss_score = cve.get("CVSS", "N/A")  # Use 'N/A' if no CVSS score is found
                                    score_breakdown.append(f"  IP: {ip}, CVE: {cve_id}, CVSS Score: {cvss_score}")
                                    
                    else:
                        score_breakdown.append("Censys CVE Report: No valid CVE data found")

        

            # Determine verdict based on raw total_score thresholds
            if total_score == 0:
                verdict = "Not Malicious"
            elif 1 <= total_score <= 15:
                verdict = "Not Malicious"
            elif 16 <= total_score <= 30:
                verdict = "Suspicious"
            elif 31 <= total_score <= 50:
                verdict = "Probably Malicious"
            else:
                verdict = "Malicious"
            
            # Additional handling based on IOC type
            if ioc_type == "ip" and trusted_provider_found:
                verdict = "Not Malicious"
                score_breakdown.append(f"Note: IP belongs to trusted provider ({trusted_provider_found}). Verdict set to 'Not Malicious'.")
            elif ioc_type in ["url", "domain"]:
                if total_score == 0 and malicious_count == 0:
                    verdict = "Not Malicious"
                elif malicious_count >= high_malicious_count_threshold:
                    verdict = "Malicious" if recent_analysis else "Probably Malicious"
                elif total_score > 0 and ("trackers" in tags or "external-resources" in tags):
                    verdict = "Suspicious"
            
            # Output final score and verdict in the breakdown
            verdict_str = f"Verdict: {verdict}"
            total_score_str = f"Total Score: {total_score}"
                        
            # Add verdict and score to the breakdown
            score_breakdown.insert(0, verdict_str)
            score_breakdown.insert(1, total_score_str)
            breakdown_str = "\n".join(score_breakdown)
            
            return total_score, breakdown_str, verdict
        
    except Exception as e:
        print(f"ERROR: Exception encountered during score calculation: {str(e)}")
        return 0, f"Error during score calculation: {str(e)}", "Unknown"




def process_categories_field(categories):
    """
    Processes the 'categories' field and returns a formatted string.
    Handles both dictionary and string types, and defaults to 'N/A' if empty or unexpected.
    """
    if isinstance(categories, dict):
        
        return ', '.join([f"{source}: {category}" for source, category in categories.items()])
    elif isinstance(categories, str):
        return categories
    elif categories is None:
        return 'N/A'
    else:
        return 'N/A'  # Fallback for unexpected types

def process_dynamic_field(field, default='N/A'):
    if isinstance(field, dict):
        # Convert dictionary to string in a readable format
        return ', '.join([f"{key}: {value}" for key, value in field.items()])
    elif isinstance(field, list):
        # Ensure all list items are strings
        return ', '.join([str(item) for item in field])
    elif isinstance(field, str):
        return field
    return default


def extract_av_vendors(vt_report):
    av_vendors = {'malicious': [], 'suspicious': []}
    if vt_report and 'data' in vt_report and 'attributes' in vt_report['data']:
        scans = vt_report['data']['attributes'].get('last_analysis_results', {})
        for vendor, result in scans.items():
            if result['category'] == 'malicious':
                av_vendors['malicious'].append(vendor)
            elif result['category'] == 'suspicious':
                av_vendors['suspicious'].append(vendor)
    return av_vendors


def is_malicious_last_14_days(report_data, ioc_type):
    total_score, breakdown, verdict = calculate_total_malicious_score(report_data, ioc_type)
    threshold_value = 200  # Define a threshold for malicious detection
    return total_score >= threshold_value, breakdown


def format_alienvault_report(alienvault_report):
    formatted_report = "AlienVault Report:\n"

    if isinstance(alienvault_report, dict):

        def add_field_to_report(field_name, field_value):
            nonlocal formatted_report
            if field_value or field_value == 0:
                formatted_report += f"  - {field_name}: {field_value}\n"

        def safe_join(separator, items):
            def stringify(item):
                if isinstance(item, dict):
                    # Extract relevant field from the dictionary or convert to string
                    return item.get('display_name', str(item))
                return str(item)
            return separator.join(stringify(item) for item in items)

        # Basic Indicator Information
        add_field_to_report("Indicator", sanitize_and_defang(alienvault_report.get('indicator', 'N/A')))
        add_field_to_report("Reputation", alienvault_report.get('reputation', 'N/A'))
        add_field_to_report("Type", alienvault_report.get('type', 'N/A'))
        add_field_to_report("Type Title", alienvault_report.get('type_title', 'N/A'))
        add_field_to_report("ASN", alienvault_report.get('asn', 'N/A'))
        add_field_to_report("Country", alienvault_report.get('country_name', 'N/A'))
        add_field_to_report("Latitude", alienvault_report.get('latitude', 'N/A'))
        add_field_to_report("Longitude", alienvault_report.get('longitude', 'N/A'))
        add_field_to_report("Accuracy Radius", alienvault_report.get('accuracy_radius', 'N/A'))
        add_field_to_report("Postal Code", alienvault_report.get('postal_code', 'N/A'))
        add_field_to_report("DMA Code", alienvault_report.get('dma_code', 'N/A'))
        add_field_to_report("Area Code", alienvault_report.get('area_code', 'N/A'))
        add_field_to_report("Flag URL", alienvault_report.get('flag_url', 'N/A'))
        add_field_to_report("Flag Title", alienvault_report.get('flag_title', 'N/A'))

        # Expiration Information
        add_field_to_report("Expiration", alienvault_report.get('expiration', 'N/A'))
        add_field_to_report("Is Active", alienvault_report.get('is_active', 'N/A'))

        # Malware Families and Adversary
        malware_families = alienvault_report.get('malware_families', [])
        if malware_families:
            #print(f"DEBUG: Joining fields, current values: {malware_families}")
            add_field_to_report("Malware Families", safe_join(', ', malware_families))

        related_info = alienvault_report.get('related', {})
        if related_info:
            add_field_to_report("Related Adversary", related_info.get('adversary', 'N/A'))
            #print(f"DEBUG: Joining fields, current values: {related_info}")
            add_field_to_report("Related Industries", safe_join(', ', related_info.get('industries', [])))

        # Sections and Pulse Information
        #print(f"DEBUG: Joining fields, current values: {alienvault_report}")
        add_field_to_report("Sections", safe_join(', ', alienvault_report.get('sections', [])))
        
        pulse_info = alienvault_report.get('pulse_info', {})
        if pulse_info:
            add_field_to_report("Pulse Count", pulse_info.get('count', 'N/A'))
            if 'pulses' in pulse_info:
                add_field_to_report("Top 3 Pulses", "")
                for i, pulse in enumerate(pulse_info['pulses'][:3], start=1):
                    add_field_to_report(f"  Pulse Name", pulse.get('name', 'N/A'))
                    add_field_to_report(f"  Adversary", pulse.get('adversary', 'N/A'))
                    #print(f"DEBUG: Joining fields, current values: {pulse_info}")
                    add_field_to_report(f"  Malware Families", safe_join(', ', pulse.get('malware_families', [])))
                    #print(f"DEBUG: Joining fields, current values: {pulse.get('industries', [])}")
                    add_field_to_report(f"  Industries", safe_join(', ', pulse.get('industries', [])))

        return formatted_report.strip()
    else:
        return "Invalid format for AlienVault report"


def process_individual_ioc_file(file_contents, category='auto'):
    cleaned_content = clean_input(file_contents)
    
    # Parsing IOCs from the cleaned content
    iocs = parse_bulk_iocs(cleaned_content)
    
    if category == 'auto':
        return iocs  # Auto-detect and return all types of IOCs
    else:
        return {category: cleaned_content.splitlines()}  # Return based on selected category

    
def extract_censys_data_analysis(censys_report):
    if censys_report:
        censys_data = (
            f"  Ip: {sanitize_and_defang(censys_report.get('ip', 'N/A'))}\n"
            f"  Asn: {censys_report.get('asn', 'N/A')}\n"
            f"  Organization: {censys_report.get('organization', 'N/A')}\n"
            f"  Country: {censys_report.get('country', 'N/A')}\n"
            f"  City: {censys_report.get('city', 'N/A')}\n"
            f"  Latitude: {censys_report.get('latitude', 'N/A')}\n"
            f"  Longitude: {censys_report.get('longitude', 'N/A')}\n"
            f"  Operating_system: {censys_report.get('operating_system', 'N/A')}\n"
            f"  Services:"
        )
        for service in censys_report.get('services', []):
            censys_data += (
                f"\n    - Port: {service.get('port', 'N/A')}, Service Name: {service.get('service_name', 'N/A')}, Observed At: {service.get('observed_at', 'N/A')}"
            )
        censys_data += f"\nLast_updated: {censys_report.get('last_updated', 'N/A')}"
        return censys_data
    return "No relevant information available"
    

def extract_borealis_info(borealis_report):
    breakdown = []
    total_score = 0

    # Spur Section
    spur_info = borealis_report.get("modules", {}).get("SPUR", [])
    if spur_info and isinstance(spur_info, list):
        breakdown.append("SPUR:")
        for spur_entry in spur_info:
            asn = spur_entry.get("as", {}).get("number", "N/A")
            org = spur_entry.get("as", {}).get("Organization", "N/A")
            tunnels = spur_entry.get("tunnels", [])
            for tunnel in tunnels:
                tunnel_type = tunnel.get("type", "N/A")
                operator = tunnel.get("operator", "N/A")
                anonymous = tunnel.get("anonymous", "N/A")
                breakdown.append(f"  ASN: {asn}\n  Organization: {org}\n  Tunnel Type: {tunnel_type}\n  Operator: {operator}\n  Anonymous: {anonymous}")
    else:
        breakdown.append("SPUR Info: No relevant data available.")

    # Stonewall Section
    stonewall_info = borealis_report.get("modules", {}).get("STONEWALL", {})
    if stonewall_info and isinstance(stonewall_info, dict):
        decision = stonewall_info.get("decision", "N/A")
        reason = stonewall_info.get("reason", "N/A")
        filename = stonewall_info.get("filename", "N/A")
        breakdown.append("Stonewall:")
        breakdown.append(f"  Decision: {decision}")
        breakdown.append(f"  Reason: {reason}")
        breakdown.append(f"  Filename: {filename}")
    else:
        breakdown.append("Stonewall: No relevant data available.")

    # AUWL Section
    if borealis_report and "AUWL" in borealis_report.get("modules", {}):
        auwl_entries = borealis_report["modules"]["AUWL"]
        if isinstance(auwl_entries, list):
            for entry in auwl_entries:
                cluster_name = entry.get("clusterName", "N/A")
                cluster_category = entry.get("clusterCategory", "N/A")
                url = entry.get("url", "N/A")
                breakdown.append(f"AUWL:\n  Cluster Name: {cluster_name}\n  Cluster Category: {cluster_category}\n  URL: {url}")

                # Check for malicious terms in the clusterCategory
                if cluster_category.lower() in ['phishing', 'malware', 'suspicious']:
                    total_score += 20  # Add to the malicious score if the category is malicious
                    breakdown.append(f"  * AUWL category '{cluster_category}' indicates malicious activity. Added 20 to score.")
        else:
            breakdown.append("AUWL: No relevant data available.")

    # Return the breakdown and the updated total_score
    #print(f"DEBUG: Joining fields, current values: {breakdown}")
    return "\n".join(breakdown), total_score



def analysis(selected_category, output_file_path=None, progress_bar=None, status_output=None, selected_country=None, port=None):
    print(f"DEBUG: analysis function started with selected_category = {selected_category}")
    print(f"DEBUG: selected_country passed to analysis = {selected_country}")
    individual_combined_reports = {}
    product_port_combination_searched = False
    ioc_scores = []
    tags = 'N/A'
    registrar = 'N/A'
    creation_date = 'N/A'
    categories_str = 'N/A'
    popularity_ranks = 'N/A'
    popularity_str = 'N/A'
    categories = 'N/A'
    vt_report = None
    

    # Ensure selected_category is not None
    if selected_category is None:
        print("DEBUG: selected_category is None")
        return "Error: selected_category is None"


    # Handle category-specific processing and ensure all IOC types are present
    selected_category.setdefault('ips', [])
    selected_category.setdefault('urls', [])
    selected_category.setdefault('domains', [])  # Add this line to handle domains
    selected_category.setdefault('hashes', [])
    selected_category.setdefault('cves', [])
    selected_category.setdefault('orgs', [])
    selected_category.setdefault('ports', [])
    selected_category.setdefault('products', [])

    print(f"DEBUG: Updated selected_category = {selected_category}")

    # Calculate total API calls based on the number of IOCs in each category
    total_api_calls = (
        len(selected_category['ips']) * 10  # 10 API calls per IP
        + len(selected_category['urls']) * 9  # 9 API calls per URL
        + len(selected_category['domains']) * 9  # 9 API calls per domain (if treated separately from URLs)
        + len(selected_category['hashes']) * 5  # 4 API calls per hash
        + len(selected_category['cves']) * 2
        + len(selected_category['orgs']) * 2
        + len(selected_category['ports']) * 3
        + len(selected_category['products']) * 3
        + len(selected_category['product_port_combinations']) * 3
    )

    # Initialize the progress bar
    if progress_bar:
        progress_bar.max = total_api_calls
        progress_bar.value = 0  # Reset progress to 0

    for category, entries in selected_category.items():
        if entries:  # Only process if there are entries in the category
            print(f"Processing {category.upper()}...")
            individual_combined_reports[category] = []
            ioc_type = category.rstrip('s')  # Converts 'ips' to 'ip', 'urls' to 'url', etc.
            
            
            # # Calculate dynamic progress step based on the total number of reports
            # progress_step = 100 / total_reports if total_reports > 0 else 1
    
            for count, entry in enumerate(entries, start=1):
                breakdown = []
                if status_output:
                    clear_output(wait=True)
                    display(HTML(f'<b>Scanning {category.capitalize()} [{count}/{len(entries)}]: {sanitize_and_defang(entry)}</b>'))
                    display(progress_bar)
    
                print(f"\nScanning {category.capitalize()} [{count}/{len(entries)}]: {sanitize_and_defang(entry)}")

                #combined_report = f"Analysis for {sanitize_and_defang(entry)} ({category.upper()}):\n\n"
                combined_report = ""
                
                if category == "ips":
                    trusted_provider_found = []
                    report_vt_ip = None
                    report_abuseipdb = None
                    report_shodan = None
                    report_alienvault = None
                    report_ipqualityscore = None
                    report_greynoise = None
                    report_censys = None
                    report_binaryedge_ip = None
                    report_metadefender_ip = None

                    
                    report_vt_ip = get_ip_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                
                
                    report_abuseipdb = get_abuseipdb_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                
                
                    report_shodan = get_shodan_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                
                
                    report_alienvault = get_alienvault_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                
                
                    report_ipqualityscore = get_ipqualityscore_report(entry, full_report=True, status_output=status_output, progress_bar=progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                
                
                    report_greynoise = get_greynoise_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                
                
                    report_censys = get_censys_data(censys_api_key, censys_secret, entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                
                
                    report_binaryedge_ip = get_binaryedge_report(entry, ioc_type=ioc_type, status_output=status_output, progress_bar=progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                
                
                    report_metadefender_ip = analyze_with_metadefender(entry, ioc_type=ioc_type, metadefender_api_key=metadefender_api_key, status_output=status_output, progress_bar=progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                
                # Borealis Report
                
                    borealis_report = request_borealis(entry, ioc_type=ioc_type, status_output=status_output, progress_bar=progress_bar)
                    if progress_bar:
                            progress_bar.value += 1
                    


                    # List of reports to check for trusted provider detection
                    all_reports = [
                        ("VirusTotal", report_vt_ip),
                        ("AbuseIPDB", report_abuseipdb),
                        ("IPQualityScore", report_ipqualityscore),
                        ("AlienVault", report_alienvault)
                    ]

                    

                    # Iterate over each report to check for trusted provider
                    for vendor, report in all_reports:
                        if report:
                            #print(f"DEBUG: Checking trusted provider in {vendor} report")

                            # Handle specific logic for each vendor
                            if vendor == "VirusTotal":
                                asn = report.get("data", {}).get("attributes", {}).get("asn", "")
                                organization = report.get("data", {}).get("attributes", {}).get("organization", "")
                                indicator = report.get("data", {}).get("attributes", {}).get("indicator", "")

                                provider = check_trusted_provider(asn, organization, "")
                                if provider:
                                    trusted_provider_found = provider
                                    breakdown.append(f"VirusTotal Trusted Provider Detected: {trusted_provider_found}")
                                    #print(f"DEBUG: Trusted provider detected from VirusTotal: {trusted_provider_found}")

                            elif vendor == "IPQualityScore":
                                # Check if report is a dictionary
                                if isinstance(report, dict):
                                    asn = report.get("ASN", "")
                                    isp = report.get("ISP", "")
                                    #indicator = entry  # IP or domain entry itself as the indicator
                                else:
                                    #print(f"DEBUG: IPQualityScore report is not a dictionary. Report content: {report}")
                                    asn = ""  # Default to empty string
                                    isp = ""
                                    #indicator = entry

                            elif vendor == "AlienVault":
                                if isinstance(report, dict):
                                    asn = report.get("ASN", "")
                                    organization = report.get("organization", "")
                                    isp = report.get("isp", "")
                                else:
                                    # Handle the case when report is not a dict (it's a string or other type)
                                    print(f"DEBUG: AlienVault report is not a dictionary. Report content: {report}")
                                    asn = ""
                                    organization = ""
                                    isp = ""


                    # Calculate verdict and score breakdown
                    total_score, score_breakdown, verdict = calculate_total_malicious_score(
                        {
                            "VirusTotal": report_vt_ip,
                            "AbuseIPDB": report_abuseipdb,
                            "IPQualityScore": report_ipqualityscore,
                            "GreyNoise": report_greynoise,
                            "AlienVault": report_alienvault,
                            "BinaryEdge": report_binaryedge_ip,
                            "MetaDefender": report_metadefender_ip,
                        },
                        borealis_report,
                        ioc_type="ip"
                    )

                    #print(f"DEBUG: trusted_provider_found before appending to verdict = {trusted_provider_found}")

                    if trusted_provider_found:
                        combined_report += f"Verdict: {verdict} (Score: {total_score}) (Belongs to {trusted_provider_found})\n"
                        combined_report += f"Scoring is to be taken with a HUGE grain of salt...Please use judgement.\n\n"
                    else:
                        combined_report += f"Verdict: {verdict} (Score: {total_score})\n"
                        combined_report += f"Scoring is to be taken with a HUGE grain of salt...Please use judgement.\n\n"
                 
                                        
                        # VirusTotal Report
                    if report_vt_ip and report_vt_ip != f"Failed to fetch VirusTotal IP report for {entry}.":
                        malicious_score = report_vt_ip['data']['attributes']['last_analysis_stats']['malicious']
                        suspicious_score = report_vt_ip['data']['attributes']['last_analysis_stats']['suspicious']
                        last_analysis_date = report_vt_ip.get('data', {}).get('attributes', {}).get('last_analysis_date', None)
                        if last_analysis_date:
                            # Format the date as needed, e.g., converting from timestamp if necessary
                            last_analysis_date_formatted = datetime.utcfromtimestamp(last_analysis_date).strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            last_analysis_date_formatted = "N/A"
                        # last_analysis_date = format_date(extract_last_analysis_date(report_vt_ip))
                        av_vendors = extract_av_vendors(report_vt_ip)
                        crowdsourced_context = report_vt_ip['data']['attributes'].get('crowdsourced_context', 'N/A')
                        crowdsourced_context_formatted = format_crowdsourced_context(crowdsourced_context)
                        
                        tags = ', '.join(report_vt_ip['data']['attributes'].get('tags', [])) if report_vt_ip['data']['attributes'].get('tags') else 'N/A'
                        categories = report_vt_ip.get('data', {}).get('attributes', {}).get('categories', None)
                        categories_str = process_dynamic_field(categories)
                        popularity_ranks = report_vt_ip.get('data', {}).get('attributes', {}).get('popularity_ranks', {})
                        
                        popularity_str = ', '.join([f"{source}: {info.get('rank')}" for source, info in popularity_ranks.items()])
                    
                        vt_result = (
                            f"  - IOC: {sanitize_and_defang(entry)}\n"
                            f"  - Malicious Vendor Score: {malicious_score}\n"
                            f"  - Malicious Detections: {malicious_score}\n"
                            f"  - Suspicious Detections: {suspicious_score}\n"
                            f"  - Malicious Vendors: {', '.join(av_vendors['malicious'])}\n"
                            f"  - Suspicious Vendors: {', '.join(av_vendors['suspicious'])}\n"
                            f"  - Tags: {tags}\n"
                            f"  - Categories: {categories_str}\n"
                            f"  - Popularity Ranks: {popularity_str}\n"
                            f"  - Registrar: {registrar}\n"
                            f"  - Creation Date: {creation_date}\n"
                            f"  - Crowdsourced Context:\n    {crowdsourced_context_formatted}\n"
                            f"  - Last Analysis Date: {last_analysis_date_formatted}\n"
                        )
                        
                        
                        # Append the report
                        combined_report += f"VirusTotal Report:\n{vt_result}\n"
                    
    
                    # AbuseIPDB Report
                    if report_abuseipdb and not report_abuseipdb.get("error"):
                        last_analysis_date = report_abuseipdb.get('lastSeen', 'N/A')
                        abuse_confidence_score = report_abuseipdb.get('abuseConfidenceScore', 'N/A')
                        is_tor = report_abuseipdb.get('isTor', 'N/A')
                        total_reports = report_abuseipdb.get('totalReports', 'N/A')
                        domain = report_abuseipdb.get('domain', 'N/A')
                        country_code = report_abuseipdb.get('country_code', 'N/A')
                        isp = report_abuseipdb.get('isp', 'N/A')
                        combined_report += (
                            f"AbuseIPDB Report:\n"
                            f"  - Abuse Confidence Score: {abuse_confidence_score}\n"
                            f"  - Is Tor Exit Node: {is_tor}\n"
                            f"  - Total Reports: {total_reports}\n"
                            f"  - Country Code: {country_code}\n"
                            f"  - ISP: {isp}\n"
                            f"  - Domain: {sanitize_and_defang(domain)}\n"
                            f"  - Last Seen: {last_analysis_date}\n\n"
                        )
                    else:
                        combined_report += "AbuseIPDB Report:\nN/A\n\n"

                    
    
                    # Shodan Report
                    if report_shodan and isinstance(report_shodan, dict):
                        shodan_report = report_shodan.get("report", {})
                        if isinstance(shodan_report, dict):
                            last_analysis_date = report_shodan.get('last_update', 'N/A')
                            combined_report += f"Shodan Report:\n"
                            for key, value in shodan_report.items():
                                if isinstance(value, list):
                                    
                                    combined_report += f"  {key}: {', '.join(map(str, value))}\n"
                                else:
                                    combined_report += f"  {key}: {sanitize_and_defang(value)}\n"
                            combined_report += "\n"
                        else:
                            combined_report += f"Shodan Report:\n{sanitize_and_defang(shodan_report)}\n\n"
                    else:
                        combined_report += f"Shodan Report:\nN/A\n\n"

                    
    
                    # IPQualityScore Report
                    if isinstance(report_ipqualityscore, str):
                        combined_report += f"{sanitize_and_defang(report_ipqualityscore)}\n\n"
                        match = re.search(r'Country Code:\s+(\w+)', report_ipqualityscore)
                        country_code = match.group(1) if match else 'N/A'  # Get the country code if it exists
                    elif isinstance(report_ipqualityscore, dict):
                        # If somehow the report is a dict, parse it as needed (though this shouldn't happen in your case)
                        parsed_ipqs = parse_ipqualityscore_report(json.dumps(report_ipqualityscore))
                        combined_report += f"IPQualityScore Report (Parsed):\n{parsed_ipqs}\n\n"
                        match = re.search(r'Country Code:\s+(\w+)', report_ipqualityscore)
                        country_code = match.group(1) if match else 'N/A'  # Get the country code if it exists
                    else:
                        combined_report += "IPQualityScore Report: No data available\n\n"
                    
                        
    
                    # AlienVault OTX Report
                    if isinstance(report_alienvault, dict):
                        combined_report += format_alienvault_report(report_alienvault) + "\n\n"
                    else:
                        combined_report += "AlienVault OTX Report:\nN/A\n\n"
                    
    
                    # GreyNoise Report
                    if report_greynoise and not report_greynoise.get("error"):
                        last_analysis_date = report_greynoise.get('last_seen', 'N/A')
                        combined_report += f"GreyNoise Report:\n"
                        combined_report += f"  - IP: {sanitize_and_defang(report_greynoise.get('ip', 'N/A'))}\n"
                        combined_report += f"  - Noise: {report_greynoise.get('noise', 'N/A')}\n"
                        combined_report += f"  - Riot: {report_greynoise.get('riot', 'N/A')}\n"
                        combined_report += f"  - Classification: {report_greynoise.get('classification', 'N/A')}\n"
                        combined_report += f"  - Name: {sanitize_and_defang(report_greynoise.get('name', 'N/A'))}\n"
                        combined_report += f"  - Link: {sanitize_and_defang(report_greynoise.get('link', 'N/A'))}\n"
                        combined_report += f"  - First Seen: {report_greynoise.get('first_seen', 'N/A')}\n"
                        combined_report += f"  - Last Seen: {last_analysis_date}\n\n"
                    else:
                        combined_report += "GreyNoise Report:\nN/A\n\n"
                    
    
                    # Censys Report
                    if report_censys:
                        combined_report += (
                            f"Censys Report:\n"
                            f"  - IP: {sanitize_and_defang(report_censys.get('ip', 'N/A'))}\n"
                            f"  - Asn: {report_censys.get('asn', 'N/A')}\n"
                            f"  - Organization: {report_censys.get('organization', 'N/A')}\n"
                            f"  - Country: {report_censys.get('country', 'N/A')}\n"
                            f"  - City: {report_censys.get('city', 'N/A')}\n"
                            f"  - Latitude: {report_censys.get('latitude', 'N/A')}\n"
                            f"  - Longitude: {report_censys.get('longitude', 'N/A')}\n"
                            f"  - Operating System: {report_censys.get('operating_system', 'N/A')}\n"
                            f"  - Services:\n"
                        )
                        for service in report_censys.get('services', []):
                            combined_report += f"    - Port: {service.get('port', 'N/A')}, Service Name: {service.get('service_name', 'N/A')}, Observed At: {service.get('observed_at', 'N/A')}\n"
                        combined_report += f"  - Last Updated: {report_censys.get('last_updated', 'N/A')}\n\n"
                    else:
                        combined_report += "Censys Report:\nN/A\n\n"
                    

                    # BinaryEdge Report
                    if report_binaryedge_ip:
                        parsed_binaryedge_info = parse_binaryedge_report(report_binaryedge_ip, "ip")
                        combined_report += f"BinaryEdge Report:\n{sanitize_and_defang(parsed_binaryedge_info)}\n\n"
                    else:
                        combined_report += "BinaryEdge Report:\n  - No relevant data found.\n\n"
                    

                    
                    # MetaDefender Report
                    if report_metadefender_ip:
                        combined_report += f"{sanitize_and_defang(report_metadefender_ip)}\n\n"
                    else:
                        combined_report += "Metadefender Report:\n  - No relevant data found.\n\n"
                    

                    # Format and append the Borealis report to the combined report
                    if borealis_report:
                        formatted_borealis_report = format_borealis_report(borealis_report, ioc_type="ip", request=entry)
                        combined_report += f"{sanitize_and_defang(formatted_borealis_report)}\n\n"
                    else:
                        combined_report += "Borealis Report:\nN/A\n\n"
            

                    # combined_report += f"Verdict: {verdict} (Score: {total_score})\n\nScore Breakdown\n{breakdown}\n\n"
                    combined_report += f"-------------------\n| Score Breakdown |\n-------------------\n{score_breakdown}\n\n"


                    # Append to scores list for sorting
                    print(f"DEBUG: Appending to ioc_scores - IOC: {entry}, Score: {total_score}")
                    ioc_scores.append((entry, total_score, combined_report, verdict, country_code))
    
                    individual_combined_reports[category].append(combined_report)
    
                elif category == "urls" or category == "domains":
                    trusted_provider_found = []
                    report_vt_url = None
                    report_urlscan = None
                    report_alienvault = None
                    report_ipqualityscore = None
                    report_binaryedge_url = None
                    report_metadefender_url = None

                    
                    urlscan_uuid = submit_url_to_urlscan(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                
                
                    url_id = submit_url_for_analysis(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                
                
                    report_ipqualityscore = get_ipqualityscore_report(entry, full_report=True, status_output=status_output, progress_bar=progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                
                
                    report_alienvault = get_alienvault_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                
                
                    if url_id:
                        time.sleep(16)
                        report_vt_url = get_url_report(url_id, status_output, progress_bar)
                        if progress_bar:
                            progress_bar.value += 1
                
                    
                        if urlscan_uuid:
                            report_urlscan = get_urlscan_report(urlscan_uuid, status_output=status_output, progress_bar=progress_bar)
                            if progress_bar:
                                progress_bar.value += 1
                    
                        else:
                            report_urlscan = None
                
                    report_binaryedge_url = get_binaryedge_report(entry, ioc_type=ioc_type, status_output=status_output, progress_bar=progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                
                
                    report_metadefender_url = analyze_with_metadefender(entry, ioc_type=ioc_type, metadefender_api_key=metadefender_api_key, status_output=status_output, progress_bar=progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                    
                
                    # Check if the domain is resolving
                    if report_urlscan and isinstance(report_urlscan, dict) and not report_urlscan.get('Resolving', True):
                        combined_report += f"URLScan Report:\n  - The domain isn't resolving.\n\n"
                        combined_report += f"Verdict: Not Malicious (Domain Not Resolving)\n\n"
                        continue  # Skip further checks for this URL as it's not resolving
                        
                    
                    borealis_report = request_borealis(entry, status_output=status_output, ioc_type=ioc_type, progress_bar=progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                    


                    # List of reports to check for trusted provider (URLScan, AlienVault, IPQualityScore)
                    all_reports = [
                        ("URLScan", report_urlscan),
                        ("AlienVault", report_alienvault),
                        ("IPQualityScore", report_ipqualityscore)
                    ]

                    trusted_provider_found = []
                    
                    # Iterate over each report to check for trusted provider
                    for vendor, report in all_reports:
                        if report:
                            if vendor == "URLScan":
                                asn = str(report_urlscan.get("ASN", ""))
                                isp = report_urlscan.get("ISP", "") or ""
                                # Debug for URLScan
                                print(f"DEBUG: URLScan ASN: {asn}, ISP: {isp}")
                                
                                # Check trusted provider
                                provider = check_trusted_provider(asn, "", isp)
                                print(f"DEBUG: URLScan trusted provider found: {provider}")
                                if provider and provider not in trusted_provider_found:
                                    trusted_provider_found.append(provider)
                                    breakdown.append(f"URLScan Trusted Provider Detected: {provider}")
                                    
                            elif vendor == "IPQualityScore":
                                if isinstance(report_ipqualityscore, dict):
                                    # Use 'report' to get the 'server' field
                                    server = report_ipqualityscore.get("server", False)
                                else:
                                    server = ""
                                
                                # Debug for IPQualityScore
                                print(f"DEBUG: IPQualityScore Server: {server}")
                                
                                # Check trusted provider
                                provider = check_trusted_provider("", "", server)
                                print(f"DEBUG: IPQS trusted provider found: {provider}")
                                
                                if provider and provider not in trusted_provider_found:
                                    trusted_provider_found.append(provider)
                                    breakdown.append(f"IPQualityScore Trusted Provider Detected: {provider}")
                                    
                            elif vendor == "AlienVault":
                                if isinstance(report, dict):
                                    asn = report.get("ASN", "")
                                    isp = report.get("isp", "")
                                    # Check trusted provider for AlienVault
                                    provider = check_trusted_provider(asn, "", isp)
                                    if provider:
                                        trusted_provider_found = provider
                                        breakdown.append(f"AlienVault Trusted Provider Detected: {provider}")
                                else:
                                    asn = ""
                                    isp = ""
                
                    # After looping through all reports, combine the trusted providers
                    if trusted_provider_found:
                        provider_list = ', '.join(trusted_provider_found)

                            
                
                    # Calculate verdict and score breakdown
                    total_score, score_breakdown, verdict = calculate_total_malicious_score(
                        {
                            "VirusTotal": report_vt_url,
                            "URLScan": report_urlscan,
                            "AlienVault": report_alienvault,
                            "IPQualityScore": report_ipqualityscore,
                            "BinaryEdge": report_binaryedge_url,
                            "MetaDefender": report_metadefender_url,
                        },
                        borealis_report,
                        ioc_type = "url" if ioc_type in ["url", "domain"] else ioc_type
                    )

                    if trusted_provider_found:
                        provider_list = ', '.join(trusted_provider_found)
                        combined_report += f"Verdict: {verdict} (Score: {total_score}) (Hosted on: {provider_list})\n"
                        combined_report += f"Scoring is to be taken with a HUGE grain of salt...Please use judgement.\n\n"
                    else:
                        combined_report += f"Verdict: {verdict} (Score: {total_score})\n"
                        combined_report += f"Scoring is to be taken with a HUGE grain of salt...Please use judgement.\n\n"
                    # #print(f"DEBUG: trusted_provider_found before appending to verdict = {trusted_provider_found}")
                    # if trusted_provider_found:
                    #     combined_report += f"Verdict: {verdict} (Score: {total_score}) (Hosted on {trusted_provider_found})\n\n"
                    # else:
                    #     combined_report += f"Verdict: {verdict} (Score: {total_score})\n\n"
                
                    # VirusTotal Report
                    if report_vt_url and isinstance(report_vt_url, dict):
                        try:
                            last_analysis_stats = report_vt_url['data']['attributes'].get('last_analysis_stats', {})
                            harmless = last_analysis_stats.get('harmless', 'N/A')
                            malicious = last_analysis_stats.get('malicious', 'N/A')
                            suspicious = last_analysis_stats.get('suspicious', 'N/A')
                            timeout = last_analysis_stats.get('timeout', 'N/A')
                            undetected = last_analysis_stats.get('undetected', 'N/A')
                    
                            last_analysis_date = report_vt_url.get('data', {}).get('attributes', {}).get('last_analysis_date', None)
                            last_analysis_date_formatted = (
                                datetime.utcfromtimestamp(last_analysis_date).strftime('%Y-%m-%d %H:%M:%S')
                                if last_analysis_date else "N/A"
                            )
                    
                            av_vendors = extract_av_vendors(report_vt_url)
                            tags = safe_join(', ', report_vt_url['data']['attributes'].get('tags', [])) or 'N/A'
                            categories = report_vt_url['data']['attributes'].get('categories', {})
                            categories_str = process_dynamic_field(categories)
                            popularity_ranks = report_vt_url['data']['attributes'].get('popularity_ranks', {})
                            popularity_str = safe_join(', ', [f"{source}: {info.get('rank')}" for source, info in popularity_ranks.items() if isinstance(info, dict)])
                    
                            # Extract last downloaded file
                            last_downloaded_file_hash = report_vt_url['data']['attributes'].get('last_http_response_content_sha256', None)
                            last_downloaded_file_info = "No last downloaded file found"
                            if last_downloaded_file_hash:
                                last_downloaded_file_info = f"Last downloaded file SHA256: {last_downloaded_file_hash}"
                                
                                # Fetch details about the last downloaded file
                                file_report = get_hash_report(last_downloaded_file_hash, status_output, progress_bar)
                                if file_report:
                                    file_name = file_report['basic_properties'].get('file_name', 'N/A')
                                    file_type = file_report['basic_properties'].get('file_type', 'N/A')
                                    detections = f"{file_report['basic_properties'].get('last_analysis_date', 'N/A')} UTC"
                                    detection_count = len(file_report.get('malicious_vendors', []))
                                    total_vendors = file_report.get('basic_properties', {}).get('total_av_engines', 63)
                                    detection_info = f"{detection_count}/{total_vendors} security vendors detected this file"
                                    last_downloaded_file_info = (
                                        f"Last seen downloading file {file_name} of type {file_type} "
                                        f"with sha256 {last_downloaded_file_hash} which was detected by {detection_info} "
                                        f"on {detections}"
                                    )
                    
                            vt_result = (
                                f"  - IOC: {sanitize_and_defang(entry)}\n"
                                f"  - Harmless: {harmless}, Malicious: {malicious}, Suspicious: {suspicious}, Timeout: {timeout}, Undetected: {undetected}\n"
                                f"  - Malicious Vendors: {', '.join(av_vendors['malicious'])}\n"
                                f"  - Suspicious Vendors: {', '.join(av_vendors['suspicious'])}\n"
                                f"  - Tags: {tags}\n"
                                f"  - Categories: {categories_str}\n"
                                f"  - Popularity Ranks: {popularity_str}\n"
                                f"  - Last Analysis Date: {last_analysis_date_formatted}\n"
                                f"  - {last_downloaded_file_info}"
                            )
                            combined_report += f"VirusTotal Report:\n{vt_result}\n"
                        except KeyError as e:
                            combined_report += f"Error parsing VirusTotal report: {e}\n"
                    
                        crowdsourced_context = report_vt_url.get("data", {}).get("attributes", {}).get("crowdsourced_context", "N/A")
                        crowdsourced_context_formatted = format_crowdsourced_context(crowdsourced_context)
                        combined_report += f"  - Crowdsourced Context:\n    {crowdsourced_context_formatted}\n"
                    else:
                        combined_report += "VirusTotal Report:\nN/A\n"
                
                    # AlienVault Report
                    if isinstance(report_alienvault, dict) and 'error' not in report_alienvault:
                        combined_report += f"\n{format_alienvault_report(report_alienvault)}\n\n"
                    else:
                        combined_report += "\nAlienVault OTX Report:\nN/A or Error\n\n"
                
                    # URLScan Report
                    if report_urlscan and isinstance(report_urlscan, dict):
                        # Check if the domain is resolving
                        if not report_urlscan.get('Resolving', True):
                            combined_report += "URLScan Report:\n  - The domain isn't resolving.\n\n"
                            combined_report += "Verdict: Not Malicious (Domain Not Resolving)\n\n"
                            continue  # Skip further checks for this URL as it's not resolving
                        else:
                            combined_report += "URLScan Report:\n"
                            combined_report += safe_join('\n', [f"  - {key}: {sanitize_and_defang(value)}" for key, value in report_urlscan.items()])
                            combined_report += "\n"
                    else:
                        combined_report += "URLScan Report:\nN/A\n\n"
                
                    # IPQualityScore Report
                    if isinstance(report_ipqualityscore, str):
                        combined_report += f"\n{sanitize_and_defang(report_ipqualityscore)}\n\n"
                    elif isinstance(report_ipqualityscore, dict):
                        parsed_ipqs = parse_ipqualityscore_report(json.dumps(report_ipqualityscore))
                        combined_report += f"IPQualityScore Report (Parsed):\n{parsed_ipqs}\n\n"
                    else:
                        combined_report += "IPQualityScore Report:\nN/A\n\n"
                
                    # BinaryEdge Report
                    if report_binaryedge_url and isinstance(report_binaryedge_url, dict):
                        parsed_binaryedge_info = parse_binaryedge_report(report_binaryedge_url, "domain")
                        combined_report += f"BinaryEdge Report:\n{parsed_binaryedge_info}\n\n"
                    else:
                        combined_report += "BinaryEdge Report:\n  - No relevant data found.\n\n"
                
                    # MetaDefender Report
                    if report_metadefender_url and isinstance(report_metadefender_url, str):
                        combined_report += f"{report_metadefender_url}\n\n"
                    else:
                        combined_report += "Metadefender Report:\n  - No relevant data found.\n\n"
                
                    # Borealis Report
                    if borealis_report:
                        formatted_borealis_report = format_borealis_report(borealis_report, category, entry)
                        combined_report += f"{formatted_borealis_report}\n\n"
                    else:
                        combined_report += "Borealis Report:\nN/A\n\n"
                
                    # Score Breakdown
                    combined_report += f"-------------------\n| Score Breakdown |\n-------------------\n{score_breakdown}\n\n"
                
                    # Append to scores list for sorting
                    ioc_scores.append((entry, total_score, combined_report, verdict))
                    individual_combined_reports[category].append(combined_report)
    
                elif category == "hashes":
                    report_vt_hash = None
                    report_alienvault = None
                    report_malwarebazaar = None
                    report_metadefender_hash = None
                    report_hybrid_analysis = None
                    report_malshare = None

                    
                    report_vt_hash = get_hash_report(entry, status_output, progress_bar)
                  # print(json.dumps(report_vt_hash, indent=4))
                    if progress_bar:
                        progress_bar.value += 1
                

                
                    report_malwarebazaar = get_malwarebazaar_hash_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                

                
                    report_alienvault = get_alienvault_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                

                    
                    report_metadefender_hash = analyze_with_metadefender(entry, ioc_type="hash", metadefender_api_key=metadefender_api_key, status_output=status_output, progress_bar=progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                

                
                # Fetch Hybrid Analysis report
                    report_hybrid_analysis = get_hybrid_analysis_hash_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                

                
                # Fetch Malshare Hash Report
                    report_malshare = get_malshare_hash_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                    
                
                    breakdown_str = ""
                    verdict = "Not Malicious"
                    total_score = 0
                
                    # Calculate verdict and score breakdown
                    total_score, score_breakdown, verdict = calculate_total_malicious_score(
                        {
                            "VirusTotal": report_vt_hash,
                            "MalwareBazaar": report_malwarebazaar,
                            "AlienVault": report_alienvault,
                            "MetaDefender": report_metadefender_hash,
                            "Hybrid-Analysis": report_hybrid_analysis,
                            "MalShare": report_malshare
                        },
                        None,  # Borealis is not used for hashes, so pass None
                        ioc_type="hash"
                    )
                    combined_report += f"Verdict: {verdict} (Score: {total_score})\n"
                    combined_report += f"Scoring is to be taken with a HUGE grain of salt...Please use judgement.\n\n"
                
                    # VirusTotal Hash Report
                    if report_vt_hash and report_vt_hash != f"Failed to fetch VirusTotal hash report for {entry}.":
                        attributes = report_vt_hash.get('data', {}).get('attributes', {})
                        # print(f"DEBUG: VirusTotal result attributes: {json.dumps(attributes, indent=2)}")
                        av_vendors = extract_av_vendors(report_vt_hash)
                        livehunt_yara_rules = attributes.get('livehunt_yara_results', [])
                        
                        
                        # Extract basic properties (File Name, File Type, File Size)
                        file_name = attributes.get('meaningful_name', 'N/A')
                        file_type = attributes.get('type_description', 'N/A')
                        file_size = attributes.get('size', 'N/A')
                        
                        # Tags extraction
                        
                        tags = ', '.join(attributes.get('tags', [])) if attributes.get('tags') else 'N/A'
                    
                        # Initial VirusTotal result formatting
                        vt_result = (
                            f"  - Hash: {sanitize_and_defang(entry)} \n"
                            f"  - File Name: {file_name}\n"
                            f"  - File Type: {file_type}\n"
                            f"  - File Size: {file_size} bytes\n"
                            f"  - Tags: {tags}\n"
                        )
                    
                        # Signature information
                        signature_info = attributes.get('signature_info', {})
                        verified = signature_info.get('verified', 'Invalid')
                        signers = signature_info.get('signers', 'Unknown')
                        
                        if verified == 'Signed':
                            vt_result += f"  - Signature: Valid (Signed by: {signers})\n"
                            breakdown.append(f"Valid signature by {signers}, deemed non-malicious")
                        else:
                            vt_result += "  - Signature: Invalid\n"
                    
                        # Threat severity, suggested threat label, and popular threat names
                        threat_severity = attributes.get('threat_severity', {})
                        if threat_severity:
                            severity_level = threat_severity.get('level_description', 'N/A')
                            threat_category = threat_severity.get('threat_severity_data', {}).get('popular_threat_category', 'N/A')
                            num_gav_detections = threat_severity.get('threat_severity_data', {}).get('num_gav_detections', 'N/A')
                            last_analysis_date = report_vt_hash.get('data', {}).get('attributes', {}).get('last_analysis_date', None)
                            if last_analysis_date:
                                # Format the date as needed, e.g., converting from timestamp if necessary
                                last_analysis_date_formatted = datetime.utcfromtimestamp(last_analysis_date).strftime('%Y-%m-%d %H:%M:%S')
                            else:
                                last_analysis_date_formatted = "N/A"
                            # last_analysis_date = threat_severity.get('last_analysis_date', 'N/A')
                            formatted_severity = (
                                f"  - Severity Level: {severity_level}\n"
                                f"  - Threat Category: {threat_category}\n"
                                f"  - Number of GAV Detections: {num_gav_detections}\n"
                                f"  - Last Analysis Date: {last_analysis_date_formatted}"
                            )
                            vt_result += f"  - Threat Severity:\n    {formatted_severity}\n"
                            breakdown.append(f"Threat Severity: {severity_level}, Category: {threat_category}, GAV Detections: {num_gav_detections}")
                    
                        # Suggested threat label and popular threat names
                        popular_threat_label = attributes.get('popular_threat_classification', {}).get('suggested_threat_label', 'N/A')
                        popular_threat_name = attributes.get('popular_threat_classification', {}).get('popular_threat_name', [])
                        
                        if popular_threat_label:
                            vt_result += f"  - Suggested Threat Label: {popular_threat_label}\n"
                            breakdown.append(f"Suggested Threat Label: {popular_threat_label}")
                        
                        if popular_threat_name:
                            
                            threat_names = ', '.join([name['value'] for name in popular_threat_name])
                            vt_result += f"  - Popular Threat Names: {threat_names}\n"
                            breakdown.append(f"Popular Threat Names: {threat_names}")
                    
                        vt_result += (
                            f"  - Malicious Detection Count: {attributes.get('last_analysis_stats', {}).get('malicious', 0)}\n"
                            f"  - Malicious Vendors: {', '.join(av_vendors['malicious'])}\n"
                            f"  - Suspicious Vendors: {', '.join(av_vendors['suspicious'])}\n"
                            f"  - Tags: {tags}\n"
                        )
                        
                        # Process categories and popularity ranks
                        categories = attributes.get('categories', None)
                        categories_str = process_dynamic_field(categories)
                        popularity_ranks = attributes.get('popularity_ranks', {})
                        
                        popularity_str = ', '.join([f"{source}: {info.get('rank')}" for source, info in popularity_ranks.items()])
                    
                        vt_result += (
                            f"  - Categories: {categories_str}\n"
                            f"  - Popularity Ranks: {popularity_str}\n"
                        )
                    
                        # Sigma and YARA Rules, Sandbox Detections
                        sigma_rules = attributes.get('sigma_analysis_results', [])
                        if sigma_rules:
                            sigma_rule_names = [rule.get('rule_title', 'Unknown Sigma Rule') for rule in sigma_rules]
                            
                            vt_result += f"  - Sigma Rules:\n    {', '.join(sigma_rule_names)}\n"
                            
                            breakdown.append(f"Sigma Rules: {', '.join(sigma_rule_names)}")
                        
                        crowdsourced_yara_rules = attributes.get('crowdsourced_yara_results', [])
                        if crowdsourced_yara_rules:
                            # Iterate through the YARA rules and extract detailed information
                            yara_rules_info = []
                            for rule in crowdsourced_yara_rules:
                                rule_name = rule.get('rule_name', 'Unknown YARA Rule')
                                ruleset_id = rule.get('ruleset_id', 'N/A')
                                ruleset_name = rule.get('ruleset_name', 'N/A')
                                description = rule.get('description', 'No description available')
                                author = rule.get('author', 'N/A')
                                source = rule.get('source', 'N/A')
                        
                                # Combine all extracted info into a formatted string
                                yara_rules_info.append(
                                    f" - Rule Name: {rule_name}\n"
                                    f"       - Ruleset ID: {ruleset_id}\n"
                                    f"       - Ruleset Name: {ruleset_name}\n"
                                    f"       - Description: {description}\n"
                                    f"       - Author: {author}\n"
                                    f"       - Source: {source}"
                                )
                            
                            # Append the collected YARA rule info to the report
                            vt_result += "  - Crowdsourced YARA Rules:\n    " + "\n    ".join(yara_rules_info) + "\n"
                            breakdown.append(f"Crowdsourced YARA Rules: {', '.join([rule['rule_name'] for rule in crowdsourced_yara_rules])}")
                        else:
                            vt_result += "  - Crowdsourced YARA Rules:\n    None\n"
                            breakdown.append("Crowdsourced YARA Rules: None")
                    
                        # Extracting Livehunt YARA rules
                        livehunt_yara_rules = attributes.get('livehunt_yara_results', [])
                        if livehunt_yara_rules:
                            #print(f"Livehunt YARA Rules Raw: {attributes.get('livehunt_yara_results', 'No YARA rules found')}")
                            # Extract the rule names, ensure defaults if no rule name found
                            livehunt_yara_rule_names = ', '.join([rule.get('rule_name', 'Unknown YARA Rule') for rule in livehunt_yara_rules])
                            if livehunt_yara_rule_names:
                                vt_result += f"  - Livehunt YARA Rules:\n   {livehunt_yara_rule_names}\n"
                                breakdown.append(f"Livehunt YARA Rules: {livehunt_yara_rule_names}")
                            else:
                                vt_result += "  - Livehunt YARA Rules:\n     None\n"
                                breakdown.append("Livehunt YARA Rules: None")
                        else:
                            vt_result += "  - Livehunt YARA Rules:\n    None\n"
                            breakdown.append("Livehunt YARA Rules: None")
                    
                        # Dynamic Analysis Sandbox Detections
                        sandbox_detections = attributes.get('sandbox_verdicts', {})
                        if sandbox_detections:
                            
                            sandbox_detections_str = ', '.join(
                                [verdict.get('malware_names', ['Unknown Verdict'])[0] for verdict in sandbox_detections.values()]
                            )
                            vt_result += f"  - Dynamic Analysis Sandbox Detections:\n    {sandbox_detections_str}"
                            breakdown.append(f"Dynamic Analysis Sandbox Detections: {sandbox_detections_str}")
                        else:
                            vt_result += "  - Dynamic Analysis Sandbox Detections:\n    None"
                            breakdown.append("Dynamic Analysis Sandbox Detections: None")
                        
                        # Append VirusTotal result to the combined report
                        combined_report += f"VirusTotal Report:\n{vt_result}\n"
                    
                        # Extract and handle crowdsourced IDS rules from the VirusTotal report and place it at the bottom
                        if 'crowdsourced_ids_results' in attributes and attributes['crowdsourced_ids_results']:
                            # Process the crowdsourced IDS results
                            
                            ids_rules_output = "\n".join(
                                [
                                    f"    - Rule: {rule.get('rule_msg', 'N/A')}\n      - Category: {rule.get('rule_category', 'N/A')}\n      - Severity: {rule.get('alert_severity', 'N/A')} "
                                    f"\n      - Source: {rule.get('rule_source', 'N/A')}\n      - URL: {rule.get('rule_url', 'N/A')}"
                                    for rule in attributes['crowdsourced_ids_results']
                                ]
                            )
                            
                            # Add the extracted IDS rules to the bottom of the report
                            combined_report += f"  - Crowdsourced IDS Rules:\n{ids_rules_output}\n\n"
                        else:
                            combined_report += "  - Crowdsourced IDS Rules:\n    None\n\n"
                    
                    # MalwareBazaar Report
                    if report_malwarebazaar:
                        # Extract key details
                        country = report_malwarebazaar.get("origin_country", "N/A")
                        intelligence = report_malwarebazaar.get("intelligence", {})
                        downloads = intelligence.get("downloads", 0)
                        uploads = intelligence.get("uploads", "N/A")  # Added uploads field
                        clamav_detections = intelligence.get("clamav", [])  # Added ClamAV detections
                        filename = report_malwarebazaar.get("file_name", "N/A")
                        sha256_hash = report_malwarebazaar.get("sha256_hash", "N/A")  # SHA256 hash
                        sha1_hash = report_malwarebazaar.get("sha1_hash", "N/A")  # SHA1 hash
                        md5_hash = report_malwarebazaar.get("md5_hash", "N/A")  # MD5 hash
                        first_seen = report_malwarebazaar.get("first_seen", "N/A")  # First seen
                        last_seen = report_malwarebazaar.get("last_seen", "N/A")  # Last seen
                        malwarebazaar_url = report_malwarebazaar.get("malwarebazaar_url", "N/A")  # MalwareBazaar URL
                        delivery_method = report_malwarebazaar.get("delivery_method", "N/A")  # Delivery Method
                        if delivery_method is None or delivery_method == "N/A":  # Handle missing field case
                            delivery_method = report_malwarebazaar.get("method_of_delivery", "N/A")  # Check alternative key
                        if clamav_detections is None or not isinstance(clamav_detections, list):
                            clamav_detections = []  # Ensure it's an empty list if none or invalid
                        
                        tags = ', '.join(report_malwarebazaar.get('tags', [])) if report_malwarebazaar.get('tags') else 'N/A'  # Tags
                    
                        # Vendor Threat Intelligence
                        vendor_threat_intel = parse_vendor_intel(report_malwarebazaar.get('vendor_intel', {}))
                    
                        combined_report += (
                            f"MalwareBazaar Report:\n"
                            f"  - Filename: {filename}\n"
                            f"  - Origin Country: {country}\n"
                            f"  - Downloads: {downloads}\n"
                            f"  - Uploads: {uploads}\n"
                            f"  - ClamAV Detections: {', '.join(clamav_detections)}\n"
                            f"  - SHA256 Hash: {sha256_hash}\n"
                            f"  - SHA1 Hash: {sha1_hash}\n"
                            f"  - MD5 Hash: {md5_hash}\n"
                            f"  - First Seen: {first_seen}\n"
                            f"  - Last Seen: {last_seen}\n"
                            f"  - Delivery Method: {delivery_method}\n"  # Add Delivery Method
                            f"  - Tags: {tags}\n"  # Add Tags
                            f"  - MalwareBazaar URL: {malwarebazaar_url}\n"
                            f"  - Vendor Threat Intelligence:\n{vendor_threat_intel}\n"
                        )
                       
                    
                    else:
                        combined_report += "MalwareBazaar Report: N/A\n\n"
                
                    # AlienVault OTX Report
                    if isinstance(report_alienvault, dict):
                        combined_report += f"{format_alienvault_report(report_alienvault)}\n\n"
                    else:
                        combined_report += "AlienVault OTX Report:\nN/A\n\n"

                    # MetaDefender Report
                    if report_metadefender_hash:
                        combined_report += f"{report_metadefender_hash}\n\n"
                    else:
                        combined_report += "Metadefender Report:\nNo relevant data found.\n\n"


                    # Hybrid Analysis report
                    if report_hybrid_analysis:
                        #print(f"DEBUG: Hybrid Analysis report type: {type(report_hybrid_analysis)}")
                        #print(f"DEBUG: Hybrid Analysis report content: {report_hybrid_analysis}")
                    
                        if isinstance(report_hybrid_analysis, list):  # Handle multiple reports
                            parsed_report = parse_hybrid_analysis_report(report_hybrid_analysis)  # Now it selects only one report
                            if parsed_report:
                                combined_report += print_hybrid_analysis_report(parsed_report)
                            else:
                                combined_report += "Hybrid-Analysis Report: N/A\n\n"
                        elif isinstance(report_hybrid_analysis, dict):  # Single report case
                            #print(f"DEBUG: Processing single report: {report_hybrid_analysis}")
                            parsed_report = parse_hybrid_analysis_report(report_hybrid_analysis)
                            if parsed_report:
                                combined_report += print_hybrid_analysis_report(parsed_report)
                            else:
                                combined_report += "Hybrid-Analysis Report: N/A\n\n"
                        else:
                            print(f"Unexpected type for Hybrid Analysis report: {type(report_hybrid_analysis)}")
                            combined_report += "Hybrid-Analysis Report: N/A\n\n"
                    else:
                        print("DEBUG: No Hybrid-Analysis report found")
                        combined_report += "Hybrid-Analysis Report: N/A\n\n"


                    # Malshare Report
                    if report_malshare:
                        combined_report += f"Malshare Report:\n"
                    
                        file_name = report_malshare.get("file_name", "N/A")
                        sha256_hash = report_malshare.get("sha256", "N/A")
                        md5_hash = report_malshare.get("md5", "N/A")
                        sha1_hash = report_malshare.get("sha1", "N/A")
                        file_type = report_malshare.get("file_type", "N/A")
                    
                        # Safeguard any score calculations
                        if sha256_hash != "N/A":
                            recency_score = 5  # Example logic
                            multiplier = 2  # Example multiplier
                        else:
                            recency_score = 0
                            multiplier = 1
                    
                        total_score += recency_score * multiplier  # Ensure this doesn't cause NoneType errors
                    
                        # Combine the extracted fields into the report
                        combined_report += (
                            f"  - File Name: {file_name}\n"
                            f"  - SHA256 Hash: {sha256_hash}\n"
                            f"  - MD5 Hash: {md5_hash}\n"
                            f"  - SHA1 Hash: {sha1_hash}\n"
                            f"  - File Type: {file_type}\n\n"
                        )
                    else:
                        combined_report += "Malshare Report: No data available\n\n"

                        combined_report += f"-------------------\n| Score Breakdown |\n-------------------\n{score_breakdown}\n\n"
    
                        # Append to scores list for sorting
                        ioc_scores.append((entry, total_score, combined_report, verdict))
                    
                        # Append the final CVE report
                        individual_combined_reports[category].append(combined_report)


                elif category == "cves":
                    report_shodan_cve = None
                    report_censys_cve = None
                
                    # Fetch the Shodan CVE report
                
                    report_shodan_cve = search_shodan_cve_country(entry, selected_country, status_output=status_output, progress_bar=progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
            
                    # Debugging the report retrieved from Shodan
                    #print(f"DEBUG: Full Shodan CVE Report: {json.dumps(report_shodan_cve, indent=2)}")
            
                    # Fetch the Censys CVE report
                    report_censys_cve = search_cves_on_censys(censys_api_key, censys_secret, entry, status_output=status_output, progress_bar=progress_bar)
                    if progress_bar:
                        progress_bar.value += 1

                    #print(f"DEBUG: Full Censys CVE Report: {json.dumps(report_censys_cve, indent=2)}")
                                    
                    total_score = 0
                    breakdown_str = ""
                    verdict = "Not Malicious"  # Default verdict in case there's no valid result
                
                    # Calculate verdict and score breakdown
                    total_score, score_breakdown, verdict = calculate_total_malicious_score(
                        {
                            "Shodan": report_shodan_cve,  # Ensure the report is passed correctly
                            "Censys": report_censys_cve,
                            
                        },
                        None,  # Borealis is not used for CVEs, so pass None
                        ioc_type="cve"
                    )
                    combined_report += f"Verdict: {verdict} (Score: {total_score})\n"
                    combined_report += f"Scoring is to be taken with a HUGE grain of salt...Please use judgement.\n\n"
                    
                
                    # Check if the Shodan CVE report is valid and process accordingly
                    if report_shodan_cve and isinstance(report_shodan_cve, dict):
                        facets = report_shodan_cve.get("facets", {})
                        matches = report_shodan_cve.get("matches", [])

                        # Extract total results from the Shodan report
                        total_results = report_shodan_cve.get("total", 0)  # Make sure total_results is defined before it's used
                        
                        # Extract facet information if available
                        if facets:
                            combined_report += f"Shodan Report for {entry}:\n"

                            if total_results:
                                combined_report += f"  - Total Results: {total_results}\n"
                            
                            top_cities = facets.get("city", [])
                            if top_cities:
                                combined_report += "  - Top Cities:\n"
                                for city in top_cities:
                                    combined_report += f"    - {city.get('value', 'N/A')}: {city.get('count', 'N/A')} occurrences\n"
                            
                            top_ports = facets.get("port", [])
                            if top_ports:
                                combined_report += "  - Top Ports:\n"
                                for port in top_ports:
                                    combined_report += f"    - Port {port.get('value', 'N/A')}: {port.get('count', 'N/A')} occurrences\n"
                
                            top_orgs = facets.get("org", [])
                            if top_orgs:
                                combined_report += "  - Top Organizations:\n"
                                for org in top_orgs:
                                    combined_report += f"    - {org.get('value', 'N/A')}: {org.get('count', 'N/A')} occurrences\n"
                            
                            top_products = facets.get("product", [])
                            if top_products:
                                combined_report += "  - Top Products:\n"
                                for product in top_products:
                                    combined_report += f"    - {product.get('value', 'N/A')}: {product.get('count', 'N/A')} occurrences\n"
                            
                            top_os = facets.get("os", [])
                            if top_os:
                                combined_report += "  - Top Operating Systems:\n"
                                for os in top_os:
                                    combined_report += f"    - {os.get('value', 'N/A')}: {os.get('count', 'N/A')} occurrences\n"
                            
                            combined_report += "\n"
                        else:
                            combined_report += f"Shodan Report for {entry}:\nNo facet data found.\n\n"
                        
                        # Extract and display limited matches
                        if matches and isinstance(matches, list):
                            combined_report += "  - Matches:\n"
                            for match in matches[:10]:  # Limit to 2 matches
                                ip_str = match.get("ip_str", "N/A")
                                ports = match.get("port", [])
                                org = match.get("org", "N/A")
                                location = match.get("location", {})
                                city = location.get("city", "N/A")
                                country = location.get("country_name", "N/A")
                                vulns = match.get("vulns", {})
                
                                combined_report += f"    - IP: {sanitize_and_defang(ip_str)}\n      - Organization: {org}\n      - City: {city}\n      - Country: {country}\n"
                                combined_report += f"      - Open Ports: {ports}\n"
                                
                                # Include CVEs from the match
                                if isinstance(vulns, dict):
                                    for cve_id, details in vulns.items():
                                        cvss_score = details.get('cvss', 'N/A')
                                        combined_report += f"       - CVE: {cve_id}\n        - CVSS Score: {cvss_score}\n"
                                combined_report += "\n"
                        else:
                            combined_report += "  - No match data found.\n"
                    else:
                        combined_report += f"Shodan Report for {entry}:\nNo results found or invalid report format.\n\n"

                    # Process the Censys CVE report
                    if report_censys_cve and isinstance(report_censys_cve, list):
                        combined_report += f"Censys Report for {entry}:\n"
                        for result in report_censys_cve:  # Loop through all results
                            ip = result.get("IP", "N/A")
                            asn = result.get("ASN", "N/A")
                            bgp_prefix = result.get("BGP Prefix", "N/A")
                            dns_names = result.get("DNS Names", "N/A")
                            location = result.get("Location", {})
                            city = location.get("City", "N/A")
                            province = location.get("Province", "N/A")
                            country = location.get("Country", "N/A")
                            os_details = result.get("Operating System", {})
                            os_product = os_details.get("Product", "N/A")
                            os_version = os_details.get("Version", "N/A")
                            services = result.get("Services", [])
                            matched_services = result.get("Matched Services", [])
                            cves = result.get("CVEs", [])
                            
                            combined_report += f"  - IP: {sanitize_and_defang(ip)}\n"
                            combined_report += f"    - ASN: {asn}\n"
                            combined_report += f"    - BGP Prefix: {sanitize_and_defang(bgp_prefix)}\n"
                            combined_report += f"    - DNS Names: {dns_names}\n"
                            combined_report += f"    - City: {city}\n      - Province: {province}\n      - Country: {country}\n"
                            combined_report += f"    - OS: {os_product} Version: {os_version}\n"
                            combined_report += "    - Services:\n      - " + "\n      - ".join(services) + "\n"
                            combined_report += f"    - Matched Services: {', '.join(matched_services)}\n"
                    
                            # Include CVEs from the Censys result
                            if cves:
                                for cve in cves:
                                    cve_id = cve.get("CVE ID", "N/A")
                                    cvss = cve.get("CVSS", "N/A")
                                    known_exploited = cve.get("Known Exploited", "N/A")
                    
                                    combined_report += (
                                        f"    - CVE: {cve_id}\n"
                                        f"      - CVSS Score: {cvss}\n"
                                        f"      - Known Exploited: {known_exploited}\n"
                                    )
                            else:
                                combined_report += "    - No CVEs found.\n"
                            #combined_report += "\n"
                    else:
                        combined_report += f"Censys Report for {entry}:\nNo results found or invalid report format.\n\n"

                    # Append score breakdown
                    combined_report += f"-------------------\n| Score Breakdown |\n-------------------\n{score_breakdown}\n\n"

                    # Append to scores list for sorting
                    ioc_scores.append((entry, total_score, combined_report, verdict))
                
                    # Append the final CVE report
                    individual_combined_reports[category].append(combined_report)


                elif category == "orgs":
                    print(f"DEBUG: Found 'orgs' category, proceeding with organization search")
                    report_shodan_org = None
                    report_censys_org = None
                    orgs = selected_category.get("orgs", [])
                    org_name = orgs[0] if orgs else "N/A"
                    
                    
                    report_shodan_org = search_shodan_org(org_name, status_output=status_output, progress_bar=progress_bar)
                    #print(f"DEBUG: search_shodan_org returned: {report_shodan_org}")
                    if progress_bar:
                        progress_bar.value += 1
            
                
                    report_censys_org = search_censys_org(censys_api_key, censys_secret, org_name, status_output=status_output, progress_bar=progress_bar)
                    #print(f"DEBUG: search_censys_org returned: {report_censys_org}")
                    if progress_bar:
                        progress_bar.value += 1
                
                    
                
                    total_score = 0
                    breakdown_str = ""
                    verdict = "Not Malicious"  # Default verdict
                
                    # Calculate verdict and score breakdown
                    total_score, score_breakdown, verdict = calculate_total_malicious_score(
                        {
                            "Shodan": report_shodan_org,  # Ensure the report is passed correctly
                            "Censys": report_censys_org,
                        },
                        None,  # Borealis is not used for Orgs, so pass None
                        ioc_type="org"
                    )
                
                    # Check if the Shodan Org report is valid and process accordingly
                    if report_shodan_org and isinstance(report_shodan_org, dict):
                        facets = report_shodan_org.get("facets", {})
                        matches = report_shodan_org.get("matches", [])
                        
                        # Extract total results from the Shodan report
                        total_results = report_shodan_org.get("total", 0)
                        
                        # Start building the report
                        combined_report += f"Shodan Report for {org_name}:\n"
                        
                        # Total results from Shodan
                        if total_results:
                            combined_report += f"  - Total Results: {total_results}\n"
                        
                        # Top ports facet
                        top_ports = facets.get("port", [])
                        if top_ports:
                            combined_report += "  - Top Ports:\n"
                            for port in top_ports:
                                combined_report += f"    - Port {port.get('value', 'N/A')}: {port.get('count', 'N/A')} occurrences\n"
                    
                        # Top organizations facet (this was missing previously)
                        top_orgs = facets.get("org", [])
                        if top_orgs:
                            combined_report += "  - Top Organizations:\n"
                            for org in top_orgs:
                                combined_report += f"    - {org.get('value', 'N/A')}: {org.get('count', 'N/A')} occurrences\n"
                        
                        # Top products facet
                        top_products = facets.get("product", [])
                        if top_products:
                            combined_report += "  - Top Products:\n"
                            for product in top_products:
                                combined_report += f"    - {product.get('value', 'N/A')}: {product.get('count', 'N/A')} occurrences\n"
                        
                        combined_report += "\n"
                        
                        # Extract and display matches
                        if matches and isinstance(matches, list):
                            combined_report += "  - Matches:\n"
                            for match in matches:
                                ip_str = match.get("ip_str", "N/A")
                                port = match.get("port", "N/A")
                                org = match.get("org", "N/A")
                                location = match.get("location", {})
                                city = location.get("city", "N/A")
                                region_code = location.get("region_code", "N/A")
                                country = location.get("country_name", "N/A")
                                longitude = location.get("longitude", "N/A")
                                latitude = location.get("latitude", "N/A")
                                product = match.get("product", "N/A")
                                asn = match.get("asn", "N/A")
                                isp = match.get("isp", "N/A")
                                os = match.get("os", "N/A")
                                domains = match.get("domains", [])
                                snmp = match.get("snmp", {})
                                ntp = match.get("ntp", {})
                                vulns = match.get("vulns", {})
                                
                                combined_report += f"    - IP: {sanitize_and_defang(ip_str)}\n"
                                combined_report += f"      - Organization: {org}\n"
                                combined_report += f"      - Product: {product}\n"
                                combined_report += f"      - ASN: {asn}\n"
                                combined_report += f"      - ISP: {isp}\n"
                                combined_report += f"      - Operating System: {os}\n"
                                combined_report += f"      - City: {city}\n"
                                combined_report += f"      - Region Code: {region_code}\n"
                                combined_report += f"      - Country: {country}\n"
                                combined_report += f"      - Longitude: {longitude}\n"
                                combined_report += f"      - Latitude: {latitude}\n"
                                combined_report += f"      - Open Ports: {port}\n"
                                combined_report += f"      - Domains: {sanitize_and_defang(domains)}\n"
                                
                                # Vulnerabilities (CVEs)
                                if isinstance(vulns, dict):
                                    combined_report += "      - Vulnerabilities (CVEs):\n"
                                    for cve_id, details in vulns.items():
                                        cvss_score = details.get('cvss', 'N/A')
                                        combined_report += f"        - CVE: {cve_id}\n"
                                        combined_report += f"        - CVSS Score: {cvss_score}\n"
                                
                                combined_report += "\n"
                        else:
                            combined_report += "  - No match data found.\n"
                    else:
                        combined_report += f"Shodan Report for {org_name}:\nNo results found or invalid report format.\n\n"
                
                    # Process Censys results
                    if report_censys_org and isinstance(report_censys_org, list):
                        combined_report += f"Censys Organization Report for {org_name}:\n"
                        for org_entry in report_censys_org:
                            combined_report += f"  - IP: {sanitize_and_defang(org_entry.get('IP', 'N/A'))}\n"
                            combined_report += f"    - ASN: {org_entry.get('ASN', 'N/A')}\n"
                            combined_report += f"    - Autonomous System: {org_entry.get('Autonomous System', 'N/A')}\n"
                            combined_report += f"    - Country: {org_entry.get('Country', 'N/A')}\n"
                            combined_report += f"    - City: {org_entry.get('City', 'N/A')}\n"
                            combined_report += f"    - Province: {org_entry.get('Province', 'N/A')}\n"
                            combined_report += f"    - Postal Code: {org_entry.get('Postal Code', 'N/A')}\n"
                            combined_report += f"    - Latitude: {org_entry.get('Latitude', 'N/A')}\n"
                            combined_report += f"    - Longitude: {org_entry.get('Longitude', 'N/A')}\n"
                            combined_report += f"    - Services: {', '.join(org_entry.get('Services', []))}\n"
                            combined_report += "\n"
                    else:
                        combined_report += f"Censys Organization Report for {org_name}:\nNo results found or invalid report format.\n\n"
                
                    # Add the score breakdown
                    combined_report += f"-------------------\n| Score Breakdown |\n-------------------\n{score_breakdown}\n\n"
                    
                    # Append to scores list for sorting
                    ioc_scores.append((entry, total_score, combined_report, verdict))
                
                    # Append the final CVE report
                    individual_combined_reports[category].append(combined_report)


                elif category == "ports" and not product_port_combination_searched:
                    for port_entry in entries:
                        print(f"DEBUG: Performing standalone port search for port '{port_entry}'")
                        print(f"DEBUG: Found 'ports' category, proceeding with port search")
                        report_shodan_port = None
                        report_censys_port = None
                        report_binaryedge_port = None
                        
                        # Use the selected country from the UI, and don't filter if "All" is selected
                        selected_country = selected_country if selected_country != 'All' else None
    
                        
                        # Perform port search on Shodan, passing the selected country if applicable
                        report_shodan_port = search_shodan_by_port(entry, country=selected_country, status_output=status_output, progress_bar=progress_bar)
                        if progress_bar:
                            progress_bar.value += 1
                    
                
                    
                        # Perform port search on Censys, passing the selected country if applicable
                        report_censys_port = search_censys_by_port(censys_api_key, censys_secret, entry, country=selected_country, status_output=status_output, progress_bar=progress_bar)
                        #print(f"DEBUG: search_censys_by_port returned: {report_censys_port}")
                        if progress_bar:
                            progress_bar.value += 1
    
                        print(f"DEBUG: Calling BinaryEdge for port {entry} in {selected_country}")
                        report_binaryedge_port = search_binaryedge_by_port(entry, country=selected_country, status_output=status_output, progress_bar=progress_bar)
                        if progress_bar:
                            progress_bar.value += 1
                    
                        
                    
                        total_score = 0
                        breakdown_str = ""
                        verdict = "Not Malicious"  # Default verdict in case there's no valid result
                    
                        # Calculate verdict and score breakdown
                        total_score, score_breakdown, verdict = calculate_total_malicious_score(
                            {
                                "Shodan": report_shodan_port,
                                "Censys": report_censys_port,
                                # "BinaryEdge": report_binaryedge_port,
                                
                            },
                            None,  # Borealis is not used for ports, so pass None
                            ioc_type="port"
                        )
                        #combined_report += f"Verdict: {verdict} (Score: {total_score})\n\n"
    
                        # Shodan Report
                        if report_shodan_port and isinstance(report_shodan_port.get('matches', []), list):
                            total_results = report_shodan_port.get('total', 'N/A')
                            top_cities = '\n    - '.join([city.get('value', 'N/A') for city in report_shodan_port.get('facets', {}).get('city', [])])
                            top_orgs = '\n    - '.join([org.get('value', 'N/A') for org in report_shodan_port.get('facets', {}).get('org', [])])
                            top_products = '\n    - '.join([product.get('value', 'N/A') for product in report_shodan_port.get('facets', {}).get('product', [])])
                            if not top_products.strip():
                                top_products = "No product data available"
                            
                            combined_report += f"Shodan Report for Port {entry} in {selected_country if selected_country else 'any country'}:\n"
                            combined_report += f"  - Total Results: {total_results}\n"
                            combined_report += f"  - Top Cities:\n    - {top_cities}\n"
                            combined_report += f"  - Top Organizations:\n    - {top_orgs}\n"
                            combined_report += f"  - Top Products:\n    - {top_products}\n\n"
                    
                            for port_entry in report_shodan_port['matches']:
                                combined_report += f"  - IP: {sanitize_and_defang(port_entry.get('ip_str', 'N/A'))}\n"
                                combined_report += f"    - Organization: {port_entry.get('org', 'N/A')}\n"
                                combined_report += f"    - ASN: {port_entry.get('asn', 'N/A')}\n"
                                combined_report += f"    - ISP: {port_entry.get('isp', 'N/A')}\n"
                                combined_report += f"    - Product: {port_entry.get('product', 'N/A')}\n"
                                combined_report += f"    - OS: {port_entry.get('os', 'N/A')}\n"
                    
                                # Location details
                                location = port_entry.get('location', {})
                                combined_report += f"    - City: {location.get('city', 'N/A')}\n"
                                combined_report += f"    - Region Code: {location.get('region_code', 'N/A')}\n"
                                combined_report += f"    - Country: {location.get('country_name', 'N/A')}\n"
                                combined_report += f"    - Latitude: {location.get('latitude', 'N/A')}\n"
                                combined_report += f"    - Longitude: {location.get('longitude', 'N/A')}\n"
                    
                                # Vulnerabilities (if any)
                                vulns = port_entry.get('vulns', {})
                                if vulns:
                                    combined_report += "    - Vulnerabilities:\n"
                                    for vuln, details in vulns.items():
                                        combined_report += f"      - {vuln}: {details.get('summary', 'N/A')}\n"
                    
                                combined_report += "\n"
                        else:
                            combined_report += f"Shodan Report for Port {entry}:\nNo results found or invalid report format.\n\n"
                    
                    
                        if report_censys_port and isinstance(report_censys_port, list):
                            combined_report += f"Censys Report for Port {entry} in {selected_country if selected_country else 'any country'}:\n"
                        
                            for port_entry in report_censys_port:
                                combined_report += f"  - IP: {sanitize_and_defang(port_entry.get('IP', 'N/A'))}\n"
                                combined_report += f"    - Last Updated: {port_entry.get('Last Updated', 'N/A')}\n"
                                combined_report += f"    - ASN: {port_entry.get('ASN', 'N/A')}\n"
                                combined_report += f"    - Autonomous System: {port_entry.get('Autonomous System', 'N/A')}\n"
                                combined_report += f"    - BGP Prefix: {port_entry.get('BGP Prefix', 'N/A')}\n"
                                combined_report += f"    - ASN Country Code: {port_entry.get('ASN Country Code', 'N/A')}\n"
                                combined_report += f"    - ASN Name: {port_entry.get('ASN Name', 'N/A')}\n"
                        
                                # Location details
                                combined_report += f"    - City: {port_entry.get('City', 'N/A')}\n"
                                combined_report += f"    - Province: {port_entry.get('Province', 'N/A')}\n"
                                combined_report += f"    - Country: {port_entry.get('Country', 'N/A')}\n"
                                combined_report += f"    - Continent: {port_entry.get('Continent', 'N/A')}\n"
                                combined_report += f"    - Postal Code: {port_entry.get('Postal Code', 'N/A')}\n"
                                combined_report += f"    - Latitude: {port_entry.get('Latitude', 'N/A')}\n"
                                combined_report += f"    - Longitude: {port_entry.get('Longitude', 'N/A')}\n"
                                combined_report += f"    - Timezone: {port_entry.get('Timezone', 'N/A')}\n"
                                combined_report += f"    - Country Code: {port_entry.get('Country Code', 'N/A')}\n"
                        
                                # Operating system details
                                combined_report += f"    - Operating System Product: {port_entry.get('Operating System Product', 'N/A')}\n"
                                combined_report += f"    - Operating System Vendor: {port_entry.get('Operating System Vendor', 'N/A')}\n"
                                combined_report += f"    - Operating System CPE: {port_entry.get('Operating System CPE', 'N/A')}\n"
                                combined_report += f"    - Operating System Source: {port_entry.get('Operating System Source', 'N/A')}\n"
                                combined_report += f"    - Operating System Family: {port_entry.get('Operating System Family', 'N/A')}\n"
                                combined_report += f"    - Operating System Device: {port_entry.get('Operating System Device', 'N/A')}\n"
                        
                                # DNS reverse names
                                dns = port_entry.get('DNS Reverse Names', [])
                                if dns:
                                    combined_report += f"    - Reverse DNS: {', '.join(dns)}\n"
                        
                                # Services (if any)
                                services = port_entry.get('Services', [])
                                if services:
                                    combined_report += "    - Services:\n"
                                    for service in services:
                                        combined_report += f"      - Service Name: {service.get('Service Name', 'N/A')}\n"
                                        combined_report += f"        - Transport Protocol: {service.get('Transport Protocol', 'N/A')}\n"
                                        combined_report += f"        - Extended Service Name: {service.get('Extended Service Name', 'N/A')}\n"
                                        combined_report += f"        - Port: {service.get('Port', 'N/A')}\n"
                                        combined_report += f"        - Certificate: {service.get('Certificate', 'N/A')}\n"
                        
                                # Matched services for the specific port
                                matched_services = port_entry.get('Matched Services', [])
                                if matched_services:
                                    combined_report += "    - Matched Services:\n"
                                    for matched_service in matched_services:
                                        combined_report += f"      - Matched Service Name: {matched_service.get('Matched Service Name', 'N/A')}\n"
                                        combined_report += f"        - Transport Protocol: {matched_service.get('Transport Protocol', 'N/A')}\n"
                                        combined_report += f"        - Port: {matched_service.get('Port', 'N/A')}\n"
                        
                                combined_report += "\n"
                        
                        else:
                            combined_report += f"Censys Report for Port {entry}:\nNo results found or invalid report format.\n\n"
    
    
                        
                        if report_binaryedge_port:
                            combined_report += f"BinaryEdge Report for Port {entry}:\n"
                            if 'events' in report_binaryedge_port:
                                for event in report_binaryedge_port['events']:
                                    # Extract target information
                                    ip = event.get('Target IP', 'N/A')
                                    port = event.get('Target Port', 'N/A')
                                    protocol = event.get('Target Protocol', 'N/A')
                                    
                                    # Extract origin information
                                    origin_ip = event.get('Origin IP', 'N/A')
                                    origin_country = event.get('Origin Country', 'N/A')
                                    origin_region = event.get('Origin Region', 'N/A')
                                    
                                    # Use format_date to convert the timestamp
                                    origin_timestamp = format_date(event.get('Origin Timestamp', 'N/A'))
                        
                                    # Add extracted data to the report
                                    combined_report += f"  - Target IP: {sanitize_and_defang(ip)}\n"
                                    combined_report += f"    - Target Port: {port}\n"
                                    combined_report += f"    - Target Protocol: {protocol}\n"
                                    combined_report += f"    - Origin Country: {origin_country}\n"
                                    combined_report += f"    - Origin IP: {sanitize_and_defang(origin_ip)}\n"
                                    combined_report += f"    - Origin Region: {origin_region}\n"
                                    combined_report += f"    - Origin Timestamp: {origin_timestamp}\n"
                        
                                    # Extract result information if available
                                    result_info = event.get('result', {}).get('data', {}).get('response', {})
                                    if result_info:
                                        response_url = result_info.get('url', 'N/A')
                                        status_info = result_info.get('status', {})
                                        status_code = status_info.get('code', 'N/A')
                                        status_message = status_info.get('message', 'N/A')
                        
                                        combined_report += f"    - Response URL: {response_url}\n"
                                        combined_report += f"    - Response Status Code: {status_code}\n"
                                        combined_report += f"    - Response Message: {status_message}\n"
                        
                                        # Extract headers
                                        headers = result_info.get('headers', {}).get('headers', {})
                                        combined_report += f"    - Response Headers:\n"
                                        for header_key, header_value in headers.items():
                                            combined_report += f"        - {header_key}: {header_value}\n"
                                        
                                        # Trim long response body for readability
                                        body = result_info.get('body', {}).get('content', 'N/A')
                                        combined_report += f"    - Response Body: {body[:100]}...\n"
                                    
                                    combined_report += "\n"
                            else:
                                combined_report += "No results found or invalid report format.\n"
                        else:
                            combined_report += "Error querying BinaryEdge.\n\n"
                    
                        # Append score breakdown
                        combined_report += f"-------------------\n| Score Breakdown |\n-------------------\n{score_breakdown}\n\n"
                    
                        # Append to scores list for sorting
                        ioc_scores.append((entry, total_score, combined_report, verdict))
                    
                        # Append the final CVE report
                        individual_combined_reports[category].append(combined_report)


                elif category == "products":
                    #print(f"DEBUG: Found 'products' category, proceeding with product search")
                    
                    # Initialize report and other variables
                    report_shodan_product = None
                    selected_country = selected_country if selected_country != 'All' else None
                
                    
                    # Perform product search on Shodan
                    report_shodan_product = search_shodan_product_country(entry, country=selected_country, status_output=status_output, progress_bar=progress_bar)
                    
                    if progress_bar:
                        progress_bar.value += 1

                    # Perform product search on Censys
                    report_censys_product = search_censys_product_country(censys_api_key, censys_secret, entry, country=selected_country, status_output=status_output, progress_bar=progress_bar)
                    #print(f"DEBUG: Type of report_censys_product: {type(report_censys_product)}")
                    #print(f"DEBUG: Content of report_censys_product: {report_censys_product}")                    
                    if progress_bar:
                        progress_bar.value += 1

                    report_binaryedge_product = search_binaryedge_product(entry, status_output=status_output, progress_bar=progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                    

                    total_score = 0
                    breakdown_str = ""
                    verdict = "Not Malicious"  # Default verdict in case there's no valid result
                
                    # Calculate verdict and score breakdown
                    total_score, score_breakdown, verdict = calculate_total_malicious_score(
                        {
                            "Shodan": report_shodan_product,
                            "Censys": report_censys_product,
                            "BinaryEdge": report_binaryedge_product,
                        },
                        None,  # Borealis is not used for ports, so pass None
                        ioc_type="products"
                    )
                    #combined_report += f"Verdict: {verdict} (Score: {total_score})\n\n"
                
                    # Ensure that the product search is only processed once
                    if report_shodan_product:
                        combined_report += f"Shodan Report for Product {entry} in {selected_country if selected_country else 'any country'}:\n"
                        combined_report += f"  - Total Results: {report_shodan_product.get('total', 'N/A')}\n"
                
                        # Process facets
                        facets = report_shodan_product.get('facets', {})
                        top_cities = '\n    - '.join([f"{city.get('value', 'N/A')} (Count: {city.get('count', 'N/A')})" for city in facets.get('city', [])])
                        top_ports = '\n    - '.join([f"{port.get('value', 'N/A')} (Count: {port.get('count', 'N/A')})" for port in facets.get('port', [])])
                        top_orgs = '\n    - '.join([f"{org.get('value', 'N/A')} (Count: {org.get('count', 'N/A')})" for org in facets.get('org', [])])
                        top_products = '\n    - '.join([f"{product.get('value', 'N/A')} (Count: {product.get('count', 'N/A')})" for product in facets.get('product', [])])
                
                        combined_report += f"  - Top Cities:\n    - {top_cities or 'N/A'}\n"
                        combined_report += f"  - Top Ports:\n    - {top_ports or 'N/A'}\n"
                        combined_report += f"  - Top Organizations:\n    - {top_orgs or 'N/A'}\n"
                        combined_report += f"  - Top Products:\n    - {top_products or 'N/A'}\n\n"
                
                        # Process matches
                        for match in report_shodan_product.get('matches', []):
                            ip_str = match.get('ip_str', 'N/A')
                            port = match.get('port', 'N/A')
                            org = match.get('org', 'N/A')
                            asn = match.get('asn', 'N/A')
                            isp = match.get('isp', 'N/A')
                            product = match.get('product', 'N/A')
                            version = match.get('version', 'N/A')
                            os = match.get('os', 'N/A')
                            domains = ', '.join(match.get('domains', [])) if match.get('domains') else 'N/A'
                            hostnames = ', '.join(match.get('hostnames', [])) if match.get('hostnames') else 'N/A'
                            country_name = match.get('location', {}).get('country_name', 'N/A')
                            city = match.get('location', {}).get('city', 'N/A')
                            region_code = match.get('location', {}).get('region_code', 'N/A')
                            latitude = match.get('location', {}).get('latitude', 'N/A')
                            longitude = match.get('location', {}).get('longitude', 'N/A')
                            timestamp = match.get('timestamp', 'N/A')
                
                            # Extract vulnerabilities if available
                            vulns = match.get('vulns', [])
                            vulns_str = ', '.join(vulns) if vulns else 'None'
                
                            combined_report += (
                                f"  - IP: {sanitize_and_defang(ip_str)}\n"
                                f"    Port: {port}\n"
                                f"    Organization: {org}\n"
                                f"    ASN: {asn}\n"
                                f"    ISP: {isp}\n"
                                f"    OS: {os}\n"
                                f"    Product: {product}\n"
                                f"    Version: {version}\n"
                                f"    Domains: {sanitize_and_defang(domains)}\n"
                                f"    Hostnames: {hostnames}\n"
                                f"    Country: {country_name}\n"
                                f"    City: {city}\n"
                                f"    Region Code: {region_code}\n"
                                f"    Latitude: {latitude}\n"
                                f"    Longitude: {longitude}\n"
                                f"    Timestamp: {timestamp}\n"
                                f"    Vulnerabilities: {vulns_str}\n\n"
                            )
                    else:
                        combined_report += f"No results found for product {entry} in {selected_country if selected_country else 'any country'}.\n"


                    
                    
                    if report_censys_product and isinstance(report_censys_product, list):
                        combined_report += f"Censys Report for Product {entry} in {selected_country if selected_country else 'any country'}:\n"
                    
                        for product_entry in report_censys_product:
                            combined_report += f"  - IP: {sanitize_and_defang(product_entry.get('IP', 'N/A'))}\n"
                            combined_report += f"    - Last Updated: {product_entry.get('Last Updated', 'N/A')}\n"
                            combined_report += f"    - ASN: {product_entry.get('ASN', 'N/A')}\n"
                            combined_report += f"    - Autonomous System: {product_entry.get('Autonomous System Description', 'N/A')}\n"
                            combined_report += f"    - ASN Country Code: {product_entry.get('AS Country Code', 'N/A')}\n"
                            combined_report += f"    - AS Organization: {product_entry.get('AS Organization', 'N/A')}\n"
                            
                            # Location details
                            combined_report += f"    - City: {product_entry.get('City', 'N/A')}\n"
                            combined_report += f"    - Province: {product_entry.get('Province', 'N/A')}\n"  # Updated from Region to Province
                            combined_report += f"    - Postal Code: {product_entry.get('Postal Code', 'N/A')}\n"
                            combined_report += f"    - Country: {product_entry.get('Country', 'N/A')}\n"
                            combined_report += f"    - Latitude: {product_entry.get('Latitude', 'N/A')}\n"
                            combined_report += f"    - Longitude: {product_entry.get('Longitude', 'N/A')}\n"
                            
                            # Service details
                            combined_report += f"    - Protocol: {product_entry.get('Protocol', 'N/A')}\n"
                            combined_report += f"    - Port: {product_entry.get('Port', 'N/A')}\n"
                            combined_report += f"    - Service Name: {product_entry.get('Service Name', 'N/A')}\n"
                    
                            # Operating System details
                            combined_report += f"    - Operating System Vendor: {product_entry.get('Operating System Vendor', 'N/A')}\n"
                            combined_report += f"    - Operating System Family: {product_entry.get('Operating System Family', 'N/A')}\n"
                    
                            # Optional details for matched services
                            services = product_entry.get('Services', [])
                            if services:
                                combined_report += "    - Services:\n"
                                for service in services:
                                    combined_report += f"      - Service Name: {service.get('Service Name', 'N/A')}\n"
                                    combined_report += f"        - Transport Protocol: {service.get('Protocol', 'N/A')}\n"
                                    combined_report += f"        - Port: {service.get('Port', 'N/A')}\n"
                    
                            combined_report += "\n"
                    
                    else:
                        combined_report += f"Censys Report for Product {entry} in {selected_country if selected_country else 'any country'}:\nNo results found or invalid report format.\n\n"


                    # Integrate this into the main reporting function
                    if report_binaryedge_product:
                        # Display the summary directly from the BinaryEdge report
                        combined_report += report_binaryedge_product.get("summary", "No summary available") + "\n\n"
                    
                        # Process events (matches)
                        for event in report_binaryedge_product.get('events', []):
                            # Extract target information
                            target = event.get('target', {})
                            target_ip = target.get('ip', 'N/A')
                            target_port = target.get('port', 'N/A')
                            target_protocol = target.get('protocol', 'N/A')
                    
                            # Extract origin information
                            origin = event.get('origin', {})
                            origin_ip = origin.get('ip', 'N/A')
                            origin_country = origin.get('country', 'N/A')
                            origin_region = origin.get('region', 'N/A')
                            origin_timestamp = format_date(origin.get('ts', 'N/A'))
                            origin_port = origin.get('port', 'N/A')
                    
                            # Add extracted data to the report
                            combined_report += (
                                f"  - Target IP: {sanitize_and_defang(target_ip)}\n"
                                f"    - Target Port: {target_port}\n"
                                f"    - Target Protocol: {target_protocol}\n"
                                f"    - Origin Country: {origin_country}\n"
                                f"    - Origin IP: {sanitize_and_defang(origin_ip)}\n"
                                f"    - Origin Region: {origin_region}\n"
                                f"    - Origin Timestamp: {origin_timestamp}\n"
                                f"    - Origin Port: {origin_port}\n"
                            )
                    
                            # Extract service information
                            service = event.get('result', {}).get('data', {}).get('service', {})
                            service_name = service.get('name', 'N/A')
                            service_product = service.get('product', 'N/A')
                            service_version = service.get('version', 'N/A')
                            service_extrainfo = service.get('extrainfo', 'N/A')
                            service_banner = service.get('banner', 'N/A')
                            service_state = event.get('result', {}).get('data', {}).get('state', {}).get('state', 'N/A')
                    
                            # Add service information to the report
                            combined_report += (
                                f"    - Service Name: {service_name}\n"
                                f"    - Service Product: {service_product}\n"
                                f"    - Service Version: {service_version}\n"
                                f"    - Service Extra Info: {service_extrainfo}\n"
                                f"    - Service Banner: {service_banner}\n"
                                f"    - Service State: {service_state}\n"
                                + "\n"
                            )
                    else:
                        combined_report += f"No results found for product {entry} on BinaryEdge.\n"
                    
                    
                    # Append the score breakdown
                    combined_report += f"-------------------\n| Score Breakdown |\n-------------------\n{score_breakdown}\n\n"
                        
                    # Append to scores list for sorting
                    ioc_scores.append((entry, total_score, combined_report, verdict))
                
                    # Append the final CVE report
                    individual_combined_reports[category].append(combined_report)

                elif category == "product_port_combinations":
                    for entry in entries:
                        product = entry[0]
                        port = entry[1]
                        selected_country = selected_country if selected_country != 'All' else None
                        
                        # Initialize variables for the reports
                        report_shodan_product_port = None
                        report_censys_product_port = None
                        report_binaryedge_product_port = None
                
                        print(f"DEBUG: Processing product-port combination search for '{product}' with port '{port}' in country '{selected_country}'")
                
                        # Perform product-port-country search on Shodan
                        report_shodan_product_port = search_shodan_product_port_country(
                            product, port=port, country=selected_country,
                            status_output=status_output, progress_bar=progress_bar
                        )
                        if progress_bar:
                            progress_bar.value += 1
                
                        # Perform product-port-country search on Censys
                        report_censys_product_port = search_censys_product_port_country(
                            censys_api_key, censys_secret, product, port=port,
                            country=selected_country, status_output=status_output, progress_bar=progress_bar
                        )
                        if progress_bar:
                            progress_bar.value += 1
                
                        # Perform product-port search on BinaryEdge (if applicable)
                        report_binaryedge_product_port = search_binaryedge_product_port_country(
                            product, port=port, country=selected_country,
                            status_output=status_output, progress_bar=progress_bar
                        )
                        if progress_bar:
                            progress_bar.value += 1
                
                        # Calculate verdict and score breakdown
                        total_score, score_breakdown, verdict = calculate_total_malicious_score(
                            {
                                "Shodan": report_shodan_product_port,
                                "Censys": report_censys_product_port,
                                "BinaryEdge": report_binaryedge_product_port,
                            },
                            None,  # Borealis is not used for ports, so pass None
                            ioc_type="product_port"
                        ) or (0, "No data", "Not Malicious")  # Provide defaults if None is returned

                        # Start building the combined report
                        combined_report += f"Product-Port Combination Report for '{product}' on Port {port} in {selected_country or 'any country'}:\n\n"
                
                        # Process Shodan report
                        if report_shodan_product_port:
                            combined_report += f"Shodan Report for Product '{product}' on Port {port} in {selected_country if selected_country else 'any country'}:\n"
                            combined_report += f"  - Total Results: {report_shodan_product_port.get('total', 'N/A')}\n"
                
                            # Only include top organizations for facet data
                            facets = report_shodan_product_port.get('facets', {})
                            top_orgs = '\n    - '.join([f"{org.get('value', 'N/A')} (Count: {org.get('count', 'N/A')})" for org in facets.get('org', [])])
                            
                            combined_report += f"  - Top Organizations:\n    - {top_orgs or 'N/A'}\n\n"
                
                            # Include individual match details
                            for match in report_shodan_product_port.get('matches', []):
                                combined_report += (
                                    f"  - IP: {sanitize_and_defang(match.get('ip_str', 'N/A'))}\n"
                                    f"    - Port: {match.get('port', 'N/A')}\n"
                                    f"    - Organization: {match.get('org', 'N/A')}\n"
                                    f"    - ASN: {match.get('asn', 'N/A')}\n"
                                    f"    - ISP: {match.get('isp', 'N/A')}\n"
                                    f"    - Product: {match.get('product', 'N/A')}\n"
                                    f"    - Country: {match.get('location', {}).get('country_name', 'N/A')}\n\n"
                                )
                
                        # Process Censys report if available
                        if report_censys_product_port:
                            # Check for the 'result' key and then for 'hits' within it
                            result = report_censys_product_port.get('result', {})
                            hits = result.get('hits', [])
                            
                            if hits:
                                combined_report += f"Censys Report for Product '{product}' on Port {port} in {selected_country if selected_country else 'any country'}:\n"
                                
                                for product_entry in hits:
                                    # Extracting details from each hit entry
                                    ip_address = product_entry.get('ip', 'N/A')
                                    last_updated = product_entry.get('last_updated_at', 'N/A')
                                    location = product_entry.get('location', {})
                                    as_info = product_entry.get('autonomous_system', {})
                        
                                    combined_report += (
                                        f"  - IP: {sanitize_and_defang(ip_address)}\n"
                                        f"    - Last Updated: {last_updated}\n"
                                        f"    - ASN: {as_info.get('asn', 'N/A')}\n"
                                        f"    - Autonomous System: {as_info.get('description', 'N/A')}\n"
                                        f"    - Country: {location.get('country', 'N/A')}\n"
                                        f"    - Province: {location.get('province', 'N/A')}\n"
                                        f"    - City: {location.get('city', 'N/A')}\n"
                                        f"    - Latitude: {location.get('coordinates', {}).get('latitude', 'N/A')}\n"
                                        f"    - Longitude: {location.get('coordinates', {}).get('longitude', 'N/A')}\n"
                                    )
                        
                                    # Parsing operating system details if present
                                    os_info = product_entry.get('operating_system', {})
                                    combined_report += (
                                        f"    - Operating System: {os_info.get('product', 'N/A')}\n"
                                        f"    - OS Version: {os_info.get('version', 'N/A')}\n"
                                        f"    - OS Vendor: {os_info.get('vendor', 'N/A')}\n"
                                        f"    - OS CPE: {os_info.get('cpe', 'N/A')}\n"
                                    )
                        
                                    # Parsing services details
                                    services = product_entry.get('services', [])
                                    combined_report += "    - Services:\n"
                                    for service in services:
                                        combined_report += (
                                            f"      - Service Name: {service.get('service_name', 'N/A')}\n"
                                            f"        - Port: {service.get('port', 'N/A')}\n"
                                            f"        - Protocol: {service.get('transport_protocol', 'N/A')}\n"
                                            f"        - Extended Service Name: {service.get('extended_service_name', 'N/A')}\n"
                                        )
                                    combined_report += "\n"
                            else:
                                # Detailed message when `hits` is empty or None
                                combined_report += f"No Censys 'hits' data found for product '{product}' on port {port} in {selected_country or 'any country'}.\n"
                        else:
                            # More detailed message for missing or incomplete report structure
                            combined_report += f"Unexpected response structure: No 'result' field found in Censys data for product '{product}' on port {port}.\n"
                
                        # Process BinaryEdge report if available
                        if report_binaryedge_product_port:
                            combined_report += f"BinaryEdge Report for Product '{product}' on Port {port}:\n"
                            for event in report_binaryedge_product_port.get('events', []):
                                combined_report += (
                                    f"  - Target IP: {sanitize_and_defang(event.get('target', {}).get('ip', 'N/A'))}\n"
                                    f"    - Target Port: {event.get('target', {}).get('port', 'N/A')}\n"
                                    f"    - Origin Country: {event.get('origin', {}).get('country', 'N/A')}\n"
                                )
                        
                        # Score breakdown
                        combined_report += f"-------------------\n| Score Breakdown |\n-------------------\n{score_breakdown}\n\n"
                        product_port_combination_searched = True
                        
                        ioc_scores.append((product, total_score, combined_report, verdict))
                        individual_combined_reports["product_port_combinations"].append(combined_report)

            print(f"Completed Processing {category.upper()}\n")

    # Prepare the aggregated report for all IOCs
    aggregated_report = "\n".join([
        f"{'.' * 150}\n\nUNCLASSIFIED//OUO\n\nIOC: {sanitize_and_defang(ioc[0])}" +
        (f" ({ioc[4]})" if len(ioc) == 5 and ioc[4] else "") +  # Add country code if available and if it is an IP
        f"\n\n{ioc[2]}" for ioc in ioc_scores
    ])
    
    # Debugging print statements to understand what's inside ioc_scores
    for ioc in ioc_scores:
        if len(ioc) == 5 and ioc[1] == 'ips':  # Check if it is an IP and if country code exists
            print(f"DEBUG: IOC: {ioc[0]}, Score: {ioc[1]}, Verdict: {ioc[3]}, Country Code: {ioc[4]}")
        else:
            print(f"DEBUG: IOC: {ioc[0]}, Score: {ioc[1]}, Verdict: {ioc[3]}")
    
    # First, filter the ioc_scores to only include IOCs with verdict "Malicious"
    malicious_ioc_scores = [ioc for ioc in ioc_scores if ioc[3] in ['Malicious', 'Probably Malicious']]
    
    # Only display top malicious IOCs if 2 or more malicious IOCs are scanned
    if len(malicious_ioc_scores) >= 2:
        # Sort the malicious IOCs by total_score in descending order (higher malicious score first)
        malicious_ioc_scores.sort(key=lambda x: x[1], reverse=True)
        
        # Display the top 5 malicious IOCs at the top of the report
        print("DEBUG: Top Malicious IOCs:")
        top_malicious_iocs_list = malicious_ioc_scores[:5]  # Get top 5 malicious IOCs
        top_malicious_iocs = "\n".join([
            f"IOC: {sanitize_and_defang(ioc[0])}" +
            (f" ({ioc[4]})" if len(ioc) == 5 and ioc[4] else "") +
            f" (Score: {ioc[1]})" for ioc in top_malicious_iocs_list
        ])
        final_report = f"Top Malicious IOCs:\n{'='*50}\n{top_malicious_iocs}\n{'='*50}\n{aggregated_report}"
    else:
        # Skip the Top Malicious IOCs section if fewer than 2 malicious IOCs are scanned
        final_report = aggregated_report

    if output_file_path:
        with open(output_file_path, "w") as outfile:
            outfile.write(final_report)

    return final_report