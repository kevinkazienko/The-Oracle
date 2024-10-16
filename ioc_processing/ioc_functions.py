import os
import re
import time
import json
import textwrap
import logging
import ast
from datetime import datetime, timedelta, timezone
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
    is_domain
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
from api_interactions.shodan import get_shodan_report
from api_interactions.alienvault import get_alienvault_report
from api_interactions.ipqualityscore import get_ipqualityscore_report, parse_ipqualityscore_report
from api_interactions.greynoise import get_greynoise_report
from api_interactions.urlscan import (
    submit_url_to_urlscan,
    get_urlscan_report
)
from api_interactions.censys import get_censys_data
from api.api_keys import censys_api_key, censys_secret, metadefender_api_key
from api_interactions.borealis import request_borealis, format_borealis_report
from api_interactions.binaryedge import get_binaryedge_report
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
        

def start_validation(output_to_file, raw_input=None, file_input=None, file_name_input=None, progress_bar=None, status_output=None):
    output_file_path = None

    # Determine if output should be saved to a file
    if output_to_file:
        output_file_path = "output_files/output.txt"  # Define the output file location or modify based on input

    # Initialize an empty list for IOCs
    iocs = []

    # Handling raw input (comma-separated or single)
    if raw_input:
        print(f"DEBUG: Raw input before refanging:\n{raw_input}")
        cleaned_input = sanitize_and_defang(raw_input, defang=False)
        print(f"DEBUG: Input after refanging:\n{cleaned_input}")
        iocs = [ioc.strip() for ioc in cleaned_input.split(',') if ioc.strip()]  # Split on commas for comma-separated values

    # Handling file input (uploaded or dropdown selected file content)
    if file_input:
        print(f"DEBUG: File content provided:\n{file_input}")
        iocs = [ioc.strip() for ioc in file_input.splitlines() if ioc.strip()]  # Split into individual IOCs

    # Proceed only if IOCs are found
    if not iocs:
        print("Error: No valid IOCs found.")
        return "Error: No valid IOCs found."


    # Function to classify the IOC based on the detected pattern
def classify_ioc(ioc):
    ioc = ioc.strip()  # Clean up whitespace
    if is_ip(ioc):
        return 'ip'
    elif is_url(ioc):
        return 'url'
    elif is_domain(ioc):
        return 'domain'
    elif is_hash(ioc):
        return 'hash'
    else:
        return 'unknown'

    # Classify IOCs using classify_ioc function
    ioc_dict = {'ips': [], 'urls': [], 'domains': [], 'hashes': []}
    for ioc in iocs:
        ioc_type = classify_ioc(ioc)  # Use the classify_ioc function
        if ioc_type != 'unknown':
            # Handle the plural case for "hash"
            if ioc_type == "hash":
                ioc_dict['hashes'].append(ioc)
            else:
                ioc_dict[f'{ioc_type}s'].append(ioc)

    # Filter out empty categories
    ioc_dict = {k: v for k, v in ioc_dict.items() if v}

    if not ioc_dict:
        print("Error: No valid IOCs found.")
        return "Error: No valid IOCs found."

    print(f"DEBUG: Starting analysis with IOCs = {ioc_dict}")

    # Display progress bar before starting analysis
    if progress_bar and status_output:
        with status_output:
            clear_output()
            display(HTML('<b>Performing analysis...</b>'))
            display(progress_bar)

    # Proceed with analysis, passing ioc_dict as selected_category
    aggregated_report = analysis(ioc_dict, output_file_path=output_file_path, progress_bar=progress_bar, status_output=status_output)

    # Save output to file if specified
    if output_to_file:
        with open(output_file_path, "a") as outfile:
            outfile.write(aggregated_report)

    return aggregated_report

def auto_detect_ioc_type(iocs):
    if iocs['ips']:
        return 'ip'
    elif iocs['urls']:
        return 'url'
    elif iocs['hashes']:
        return 'hash'
    else:
        return 'unknown'


def parse_bulk_iocs(content):
    iocs = {'ips': [], 'urls': [], 'domains': [], 'hashes': []}
    if not content:
        return iocs
    for line in content.splitlines():
        line = line.strip()
        if line:
            if is_ip(line):
                iocs['ips'].append(line)
            elif is_url(line):
                iocs['urls'].append(line)
            elif is_domain(line):
                iocs['domains'].append(line)
            elif is_hash(line):
                iocs['hashes'].append(line)
            else:
                print(f"Sorry, we were unable to recognize IOC format: {line}")
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



def calculate_total_malicious_score(reports, borealis_report, ioc_type, status_output=None):
    total_score = 0
    score_breakdown = []
    malicious_count = 0
    total_sources = 0
    trusted_provider_found = None
    breakdown_str = ""
    signature_info = {}
    malicious_sources = 0
     # Ensure status_output is passed if needed for VirusTotal
    if status_output is None:
        status_output = []  # Default to an empty list or appropriate default object

    # Define maximum possible scores per validation source
    max_scores = {
        "VirusTotal": 65,  # Sum of malicious, suspicious, YARA, IDS, sandbox, and crowdsourced context
        "AbuseIPDB": 10,  # Confidence score maxes out at 100
        "AlienVault": 5,  # Arbitrary max for pulses + malware families
        "GreyNoise": 5,  # Arbitrary weight for malicious classification
        "IPQualityScore": 5,  # Fraud score maxes out at 100
        "MalwareBazaar": 25,  # Based on downloads, origin country, and intelligence
        "URLScan": 10,  # Malicious score maxes out at 100
        "Shodan": 0,  # Shodan does not contribute to score, only used for trusted provider detection
        "BinaryEdge": 5,
        "MetaDefender": 5,
        "AUWL": 5,
        "TOP1MILLION": 5,
        "ALPHABETSOUP": 5,
        "STONEWALL": 5,
        "Hybrid-Analysis":5
        
    }


    # Adjust the max possible score based on IOC type
    if ioc_type == "ip":
        max_possible_score = max_scores["VirusTotal"] + max_scores["AbuseIPDB"] + max_scores["AlienVault"] + max_scores["GreyNoise"] + max_scores["IPQualityScore"] + max_scores["BinaryEdge"] + max_scores["MetaDefender"] + max_scores["STONEWALL"]
    elif ioc_type in ["url", "domain"]:
        max_possible_score = max_scores["VirusTotal"] + max_scores["AlienVault"] + max_scores["IPQualityScore"] + max_scores["URLScan"] + max_scores["AUWL"] + max_scores["BinaryEdge"] + max_scores["MetaDefender"] + max_scores["ALPHABETSOUP"] + max_scores["TOP1MILLION"] + max_scores["STONEWALL"]
    elif ioc_type == "hash":
        max_possible_score = max_scores["VirusTotal"] + max_scores["AlienVault"] + max_scores["MalwareBazaar"] + max_scores["MetaDefender"] + max_scores["Hybrid-Analysis"]
    else:
        max_possible_score = 0  # If the IOC type is unknown, max score is set to 0

    #vendor_contributions = {} # Track score contributions from each vendor

    # Threshold to consider high risk from a single source
    high_malicious_count_threshold = 3  # Adjust as necessary
    malicious_score_threshold = 50  # Adjust as needed
    probably_malicious_score_threshold = 30  # Adjust as needed

    # Make current_date timezone-aware (UTC)
    current_date = datetime.now(timezone.utc)
    days_threshold = 14  # The 14-day threshold for analysis dates

    # Add a flag to determine if the analysis date is recent for each vendor
    recent_analysis = False

    # Extract Borealis report details
    borealis_breakdown = ""
    if borealis_report:
        borealis_breakdown, borealis_score = extract_borealis_info(borealis_report)
        total_score += borealis_score  # Add Borealis score to the total score
        #vendor_contributions["Borealis"] = borealis_score

    # Adjusted weight thresholds for malicious and suspicious counts
    malicious_weight = 1  # Weight per malicious detection
    suspicious_weight = 0.5  # Weight per suspicious detection

    try:
        # IP-based IOC
        if ioc_type == "ip":
            # VirusTotal parsing
            if 'VirusTotal' in reports:
                vt_report = reports['VirusTotal']
                malicious_count, suspicious_count, last_analysis_date_formatted, crowdsourced_context, tags, registrar, creation_date = extract_vt_analysis(vt_report)
            
                # Adjusting VirusTotal score
                vt_score = (malicious_count * malicious_weight) + (suspicious_count * suspicious_weight)
                total_score += min(vt_score, max_scores["VirusTotal"])  # Cap VirusTotal score
                #vendor_contributions["VirusTotal"] = min(vt_score, vt_max_score)

            
                # Check if last analysis date is within the last 14 days
                last_analysis_date = extract_last_analysis_date(vt_report)
                if last_analysis_date:
                    last_analysis_date_formatted = last_analysis_date.strftime('%Y-%m-%d %H:%M:%S')
                    if isinstance(last_analysis_date, datetime) and (current_date - last_analysis_date <= timedelta(days=days_threshold)):
                        recent_analysis = True
            
                # Ensure tags, registrar, and creation date are handled safely with defaults
                tags = ', '.join(vt_report['data']['attributes'].get('tags', [])) if vt_report['data']['attributes'].get('tags') else 'N/A'
                registrar = vt_report['data']['attributes'].get('registrar', 'N/A')
                creation_date = vt_report['data']['attributes'].get('creation_date', 'N/A')
            
                if creation_date != 'N/A':
                    creation_date = format_date(creation_date)
            
                categories = vt_report.get('data', {}).get('attributes', {}).get('categories', {})
                categories_str = process_dynamic_field(categories)
            
                popularity_ranks = vt_report.get('data', {}).get('attributes', {}).get('popularity_ranks', {})
                popularity_str = process_dynamic_field(popularity_ranks)
            
                # Update breakdown with the extracted information
                score_breakdown.append(f"VirusTotal:\n  Malicious={malicious_count}\n  Suspicious={suspicious_count}")
                score_breakdown.append(f"  Tags: {tags}")
                score_breakdown.append(f"  Categories: {categories_str}")
                score_breakdown.append(f"  Popularity Ranks: {popularity_str}")
                score_breakdown.append(f"  Registrar: {registrar}")
                score_breakdown.append(f"  Creation Date: {creation_date}")
                score_breakdown.append(f"  Last Analysis Date: {last_analysis_date_formatted}")
            
                # Crowdsourced context
                if crowdsourced_context != 'N/A':
                    crowdsourced_context_formatted = format_crowdsourced_context(crowdsourced_context)
                    total_score += 1  # Weight for crowdsourced context indicating malicious activity
                    #vendor_contributions["VirusTotal"] += 15
                    score_breakdown.append(f"  Crowdsourced Context:\n  {crowdsourced_context_formatted}")
            
            # YARA Rules (Livehunt) parsing
            if 'Livehunt YARA Rules' in reports:
                yara_rules = reports['Livehunt YARA Rules']
                if yara_rules:
                    total_score += len(yara_rules) * 1  # Weight for each matching YARA rule
                   # vendor_contributions["VirusTotal"] += 10
                    score_breakdown.append(f"  Livehunt YARA Rules: {', '.join(yara_rules)}")
            
            # Crowdsourced IDS rules parsing
            if 'Crowdsourced IDS Rules' in reports:
                ids_rules = reports['Crowdsourced IDS Rules']
                if ids_rules:
                    formatted_ids_rules = "\n".join(
                        [f"    - {rule.get('rule_msg', 'N/A')} (Severity: {rule.get('alert_severity', 'N/A')}, Source: {rule.get('rule_source', 'N/A')}, URL: {rule.get('rule_url', 'N/A')})"
                         for rule in ids_rules]
                    )
                    total_score += len(ids_rules) * 1  # Weight for each IDS rule
                    #vendor_contributions["VirusTotal"] += 5
                    score_breakdown.append(f"  Crowdsourced IDS Rules:\n  {formatted_ids_rules}")
            
            # Dynamic Analysis Sandbox Detections
            if 'Dynamic Analysis Sandbox Detections' in reports:
                sandbox_detections = reports['Dynamic Analysis Sandbox Detections']
                if sandbox_detections:
                    total_score += len(sandbox_detections) * 1  # Weight for each sandbox detection
                    #vendor_contributions["VirusTotal"] += 8
                    score_breakdown.append(f"  Dynamic Analysis Sandbox Detections: {', '.join(sandbox_detections)}")
            
            # Signature information
            if 'Signature Information' in reports:
                signature_info = reports['Signature Information']
                if signature_info.get('valid_signature', False):
                    score_breakdown.append("  Signature Information: Valid Signature found")
                else:
                    total_score += 1  # If signature is not valid, increase the score
                    #vendor_contributions["VirusTotal"] += 20
                    score_breakdown.append("  Signature Information: Invalid or no signature")

            # AbuseIPDB parsing
            abuseipdb_report = reports.get("AbuseIPDB", {})
            if isinstance(abuseipdb_report, dict):
                confidence_score = int(abuseipdb_report.get('abuseConfidenceScore', 0))

                # Handle the last_seen field (timestamp or ISO 8601)
                last_seen = abuseipdb_report.get('lastSeen', None)
                if last_seen:
                    if isinstance(last_seen, str):
                        try:
                            last_analysis_date = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                        except ValueError as e:
                            last_analysis_date = None
                    elif isinstance(last_seen, int):
                        last_analysis_date = datetime.utcfromtimestamp(last_seen).replace(tzinfo=timezone.utc)

                    # Compare datetime with current date
                    if last_analysis_date and (current_date - last_analysis_date <= timedelta(days=days_threshold)):
                        recent_analysis = True

                total_reports = int(abuseipdb_report.get('totalReports', 0))
                is_tor = abuseipdb_report.get('isTor', False)

                if confidence_score > 0:
                    total_sources += 1
                    malicious_count += 1
                    total_score += confidence_score
                    #vendor_contributions["AbuseIPDB"] += confidence_score

                score_breakdown.append(f"AbuseIPDB:\n  Confidence Score={confidence_score}\n  Total Reports={total_reports}\n  Is Tor={is_tor}")

            # IPQualityScore parsing
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
                suspicious = ipqs_report.get("suspicious", False)
                # Weights for each component
                fraud_weight = 1      # Weight for fraud score
                vpn_weight = 10       # VPN increases score by 10 if True
                tor_weight = 15       # TOR increases score by 15 if True
                proxy_weight = 5      # Proxy increases score by 5 if True
                phishing_weight = 20  # Phishing increases score by 20 if True
                malware_weight = 30   # Malware increases score by 30 if True
                suspicious_weight = 40
            
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
            
                # Update the total score and add to breakdown
                total_score += total_ipqs_score
                malicious_count += 1  # If any of these conditions exist, consider it malicious
                #vendor_contributions["IPQualityScore"] += total_ipqs_score
            
                score_breakdown.append(
                    f"IPQualityScore:\n  Fraud Score={score_ipqs}\n  VPN={vpn}\n"
                    f"  Tor={tor}\n  Proxy={proxy}\n  Phishing={phishing}\n"
                    f"  Malware={malware}\n  Suspicious={suspicious}"
                )
            else:
                score_breakdown.append("IPQualityScore: No data available")

            if isinstance(ipqs_report, dict):
                asn = str(ipqs_report.get("asn", ""))
                isp = ipqs_report.get("isp", "")
                organization = ipqs_report.get("organization", "")
                
                # Apply trusted provider detection as done in URLScan section
                provider = check_trusted_provider("", organization, isp)
                if provider:
                    trusted_provider_found = provider
                    score_breakdown.append(f"  IP belongs to trusted provider ({trusted_provider_found})...Proceed with caution")
                else:
                    score_breakdown.append("  No Trusted Provider Detected in IPQualityScore")

            # GreyNoise parsing
            greynoise_report = reports.get("GreyNoise", {})
            if isinstance(greynoise_report, dict):
                classification = greynoise_report.get("classification", "unknown")
                total_sources += 1
                if classification != "benign":
                    malicious_count += 1
                    #vendor_contributions["GreyNoise"] += 1
                score_breakdown.append(f"GreyNoise:\n  Classification={classification}")

            # AlienVault parsing
            alienvault_report = reports.get("AlienVault", {})
            if isinstance(alienvault_report, dict):
                pulses = alienvault_report.get("pulse_count", 0)
                malware_families = alienvault_report.get("malware_families", 0)
                
                # Get ASN (try both 'asn' and 'ASN')
                asn = alienvault_report.get("asn", "").split()[0]  # Split and take the first part, which is the number

                organization = alienvault_report.get("organization", "")
                isp = alienvault_report.get("isp", "") or ""
                indicator = alienvault_report.get("indicator", "")
                
                # Debug: Check what AlienVault returned for these fields
                print(f"DEBUG: ASN = {asn}, Organization = {organization}, ISP = {isp}, Indicator = {indicator}")
                
                # Include ASN in the breakdown
                score_breakdown.append(f"AlienVault:\n  Pulses={pulses}\n  Malware Families={malware_families}\n  ASN={alienvault_report.get('asn', 'N/A')}")
                
                # Check for trusted provider
                provider = check_trusted_provider(asn, organization, isp)
                print(f"DEBUG: Trusted Provider detected from AlienVault: {provider}")
                
                # Add provider information to the breakdown and verdict
                if provider:
                    trusted_provider_found = provider
                    score_breakdown.append(f"  Trusted Provider Detected in AlienVault: {trusted_provider_found}...Proceed with caution")
                else:
                    score_breakdown.append("  No Trusted Provider Detected in AlienVault")
            
                

            # Shodan parsing
            shodan_report = reports.get("Shodan", {})
            if isinstance(shodan_report, dict):
                asn = str(shodan_report.get("asn", ""))
                organization = shodan_report.get("organization", "")
                provider = check_trusted_provider(asn, organization, "")
                if provider:
                    trusted_provider_found = provider
                    score_breakdown.append(f"  Trusted Provider Detected in Shodan: {trusted_provider_found}...Proceed with caution")

            # BinaryEdge parsing
            binaryedge_report = reports.get("BinaryEdge", {})
            if isinstance(binaryedge_report, dict):
                # Get total events and calculate score
                events = binaryedge_report.get('total', 0)
                
                # Increment score based on events
                total_score += events  # Adjust the score contribution to be based solely on event count
                
                # Append event count to the breakdown
                score_breakdown.append(f"BinaryEdge:\n  Total Events = {events}")

            # Metadefender parsing
            metadefender_report = reports.get("Metadefender", {})
            if isinstance(metadefender_report, dict):
                detected_by = metadefender_report.get('detected_by', 0)
                total_score += detected_by * 3  # Adjust score based on detection engines
                #vendor_contributions["Metadefender"] += detected_by * 3
                score_breakdown.append(f"Metadefender:\n  Detected By={detected_by}")

            # Append Borealis info if present
            if borealis_breakdown:
                score_breakdown.append(f"Borealis Report:\n{borealis_breakdown}")

            # Stonewall parsing (approval for blocking)
            if "Stonewall" in borealis_report:
                stonewall_report = borealis_report["Stonewall"]
                approved_for_blocking = stonewall_report.get("approved", False)
                if approved_for_blocking:
                    total_score += max_scores["Stonewall"]
                    malicious_count += 1
                    score_breakdown.append(f"Stonewall: Approved for blocking (malicious)")
                else:
                    score_breakdown.append("Stonewall: Not approved for blocking")

        # URL and Domain-based IOC
        elif ioc_type in ["url", "domain"]:
            if 'VirusTotal' in reports:
                crowdsourced_context_formatted = "N/A"
                vt_report = reports['VirusTotal']
                malicious_count, suspicious_count, last_analysis_date_formatted, crowdsourced_context, tags, registrar, creation_date = extract_vt_analysis(vt_report)
            
                vt_score = (malicious_count * 1) + (suspicious_count * 0.5)  # Weight for malicious and suspicious
                total_score += min(vt_score, max_scores["VirusTotal"])
            
                tags = ', '.join(vt_report['data']['attributes'].get('tags', [])) if vt_report['data']['attributes'].get('tags') else 'N/A'
                registrar = vt_report['data']['attributes'].get('registrar', 'N/A')
                creation_date = vt_report['data']['attributes'].get('creation_date', 'N/A')
            
                if creation_date != 'N/A':
                    creation_date = format_date(creation_date)
            
                categories = vt_report.get('data', {}).get('attributes', {}).get('categories', {})
                categories_str = process_dynamic_field(categories)
            
                popularity_ranks = vt_report.get('data', {}).get('attributes', {}).get('popularity_ranks', {})
                popularity_str = process_dynamic_field(popularity_ranks)
            
                # Append VirusTotal details to the score breakdown
                score_breakdown.append(f"VirusTotal:\n  Malicious={malicious_count}\n  Suspicious={suspicious_count}")
                score_breakdown.append(f"  Tags: {tags}")
                score_breakdown.append(f"  Categories: {categories_str}")
                score_breakdown.append(f"  Popularity Ranks: {popularity_str}")
                score_breakdown.append(f"  Registrar: {registrar}")
                score_breakdown.append(f"  Creation Date: {creation_date}")
                score_breakdown.append(f"  Last Analysis Date: {last_analysis_date_formatted}")
            
                # Last downloaded file from VirusTotal
                last_downloaded_file_hash = vt_report['data']['attributes'].get('last_http_response_content_sha256', None)
                last_downloaded_file_info = "No last downloaded file found"
                
                if last_downloaded_file_hash:
                    # Pass progress_bar if available
                    file_report = get_hash_report(last_downloaded_file_hash, status_output=status_output, progress_bar=progress_bar if 'progress_bar' in locals() else None)
                    
                    if file_report:
                        # Extract the file's basic properties
                        file_name = file_report['basic_properties'].get('file_name', 'N/A')
                        file_type = file_report['basic_properties'].get('file_type', 'N/A')
                        detection_count = len(file_report.get('malicious_vendors', []))
                        total_vendors = file_report.get('basic_properties', {}).get('total_av_engines', 63)
                        last_analysis_date = file_report['basic_properties'].get('last_analysis_date', 'N/A')
                        
                        # Format the detection information
                        detection_info = f"{detection_count}/{total_vendors} security vendors detected this file"
                        
                        # Format the last downloaded file info
                        last_downloaded_file_info = (
                            f"  {file_name} of type {file_type}\n"
                            f"  with sha256 {last_downloaded_file_hash}\n  which was detected by {detection_info}\n"
                            f"  on {last_analysis_date} UTC"
                        )
                    else:
                        last_downloaded_file_info = f"Last downloaded file SHA256: {last_downloaded_file_hash} (No additional details found)"
            
                # Add last downloaded file info to the end of the VirusTotal section
                score_breakdown.append(f"  Last Downloaded File:{last_downloaded_file_info}")
            
                if crowdsourced_context != 'N/A':
                    total_score += 15
                    score_breakdown.append(f"  Crowdsourced Context:\n  {crowdsourced_context_formatted}")

            # URLScan parsing
            urlscan_report = reports.get("URLScan", {})
            if isinstance(urlscan_report, dict):
                # Check if the domain is resolving
                if not urlscan_report.get('Resolving', True):
                    score_breakdown.append("URLScan:\n  The domain isn't resolving. No malicious score.")
                else:
                    malicious_urls = urlscan_report.get('Malicious Score', 0)
                    tls_issuer = urlscan_report.get('TLS Issuer', 'N/A')
                    tls_age = urlscan_report.get('TLS Age (days)', 'N/A')
                    redirected = urlscan_report.get('Redirected', 'N/A')
                    asn = str(urlscan_report.get("ASN", ""))
                    organization = urlscan_report.get("Organization", "")
                    domain = urlscan_report.get("Domain", "") or ""
                    isp = urlscan_report.get("ISP", "") or ""
                    last_analysis_date = urlscan_report.get("Last Analysis Date", "") or ""

                    score_urlscan = malicious_urls
                    total_sources += 1
                    if score_urlscan > 0:
                        malicious_count += 1
                    total_score += score_urlscan

                    score_breakdown.append(f"URLScan:\n  Malicious Score= {malicious_urls}\n  ISP= {isp}\n  TLS Issuer= {tls_issuer}\n  TLS Age= {tls_age} days\n  Redirected= {redirected}\n  Last Analysis Date= {last_analysis_date}")

                    # Check for a trusted provider
                    provider = check_trusted_provider(asn, organization, isp)
                    if provider:
                        trusted_provider_found = provider
                        score_breakdown.append(f"  Domain is hosted on a trusted provider (ISP: {trusted_provider_found})...Proceed with caution")

            # IPQualityScore parsing for URLs/Domains
            ipqs_report = reports.get("IPQualityScore", {})
            if isinstance(ipqs_report, str):
                ipqs_report = parse_ipqualityscore_report(ipqs_report)
            
            if isinstance(ipqs_report, dict) and ipqs_report:
                # Extract relevant fields from IPQualityScore report
                score_ipqs = int(ipqs_report.get("risk_score", 0))  # Risk score
                vpn = ipqs_report.get("vpn", False)                 # VPN flag
                tor = ipqs_report.get("tor", False)                 # TOR flag
                proxy = ipqs_report.get("proxy", False)             # Proxy flag
                phishing = ipqs_report.get("phishing", False)       # Phishing flag
                malware = ipqs_report.get("malware", False)         # Malware flag
                server = ipqs_report.get("server", False)
                suspicious = ipqs_report.get("suspicious", False)
                # Weights for each component
                risk_weight = 1        # Weight for risk score
                vpn_weight = 10        # VPN increases score by 10 if True
                tor_weight = 15        # TOR increases score by 15 if True
                proxy_weight = 5       # Proxy increases score by 5 if True
                phishing_weight = 20   # Phishing increases score by 20 if True
                malware_weight = 30    # Malware increases score by 30 if True
                suspicious_weight = 40
            
                # Calculate total score for IPQualityScore by applying the weights
                total_ipqs_score = (
                    score_ipqs * risk_weight +
                    (vpn_weight if vpn else 0) +
                    (tor_weight if tor else 0) +
                    (proxy_weight if proxy else 0) +
                    (phishing_weight if phishing else 0) +
                    (malware_weight if malware else 0) +
                    (suspicious_weight if suspicious else 0)
                )
            
                # Update the total score and add to breakdown
                total_score += total_ipqs_score
                malicious_count += 1  # If any of these conditions exist, consider it malicious
            
                score_breakdown.append(
                    f"IPQualityScore:\n  Risk Score={score_ipqs}\n  VPN={vpn}\n"
                    f"  Tor={tor}\n  Proxy={proxy}\n  Phishing={phishing}\n"
                    f"  Malware={malware}\n  Server={server}\n  Suspicious={suspicious}\n  IPQS Score Contribution: {total_ipqs_score} / {max_scores['IPQualityScore']}"
                )
                # Check for a trusted provider
                provider = check_trusted_provider("", "", server)
                if provider:
                    trusted_provider_found = provider
                    score_breakdown.append(f"  Domain is hosted on a trusted provider (ISP: {trusted_provider_found})...Proceed with caution")
            else:
                score_breakdown.append("IPQualityScore: No data available")

            # AlienVault parsing for URLs/Domains
            alienvault_report = reports.get("AlienVault", {})
            if isinstance(alienvault_report, dict):
                pulses = alienvault_report.get("pulse_count", 0)
                malware_families = alienvault_report.get("malware_families", 0)
                total_sources += 1
                if pulses + malware_families > 0:
                    malicious_count += 1
                score_breakdown.append(f"AlienVault:\n  Pulses={pulses}\n  Malware Families={malware_families}")

                asn = str(alienvault_report.get("asn", ""))
                organization = alienvault_report.get("organization", "")
                domain = alienvault_report.get("domain", "") or ""
                isp = alienvault_report.get("isp", "") or ""
                indicator = alienvault_report.get("indicator", "")
                provider = check_trusted_provider(asn, organization, isp)
                if provider:
                    trusted_provider_found = provider
                    score_breakdown.append(f"  Domain is hosted on a trusted provider: {trusted_provider_found}...Proceed with caution")

            # BinaryEdge parsing for URLs/Domains
            binaryedge_report = reports.get("BinaryEdge", {})
            if isinstance(binaryedge_report, dict):
                events = binaryedge_report.get('total', 0)
                total_score += events * 2  # Adjust score increment based on events
                score_breakdown.append(f"BinaryEdge:\n  Total Events={events}")
                parsed_binaryedge_info = parse_binaryedge_report(binaryedge_report, ioc_type)
                score_breakdown.append(f"  Details:\n{parsed_binaryedge_info}")

            # Metadefender parsing for URLs/Domains
            metadefender_report = reports.get("Metadefender", {})
            if isinstance(metadefender_report, dict):
                detected_by = metadefender_report.get('detected_by', 0)
                total_score += detected_by * 3  # Adjust score based on detection engines
                score_breakdown.append(f"Metadefender:\n  Detected By={detected_by}")

            # Append Borealis info if present
            if borealis_breakdown:
                score_breakdown.append(f"Borealis Report:\n{borealis_breakdown}")


            # AUWL Section
            auwl_report = borealis_report.get("AUWL", [])
            if isinstance(auwl_report, list) and auwl_report:
                phishing_count = 0
                total_auwl_clusters = len(auwl_report)
            
                # Iterate over the AUWL clusters and check for malicious categories
                for cluster in auwl_report:
                    cluster_name = cluster.get('clusterName', 'N/A')
                    cluster_category = cluster.get('clusterCategory', 'N/A')
                    cluster_url = cluster.get('url', 'N/A')
            
                    # If the category is 'phishing' or other malicious types, count it as malicious
                    if cluster_category.lower() == "phishing":
                        phishing_count += 1
            
                    # Add cluster information to the breakdown
                    score_breakdown.append(f"  AUWL Cluster: {cluster_name}\n    Category: {cluster_category}\n    URL: {cluster_url}")
            
                # Cap the score contribution from AUWL at 200, distribute proportionally
                max_auwl_score = 200
                if total_auwl_clusters > 0:
                    # Calculate score per phishing cluster
                    score_per_cluster = max_auwl_score / total_auwl_clusters  
                    auwl_score = phishing_count * score_per_cluster
                    auwl_score = min(auwl_score, max_auwl_score)  # Ensure AUWL score does not exceed the max score of 200
            
                    total_sources += 1
                    if phishing_count > 0:
                        malicious_count += phishing_count
                        total_score += int(auwl_score)
                        
            
                score_breakdown.append(f"  AUWL Total Clusters: {total_auwl_clusters}\n  Phishing Clusters Detected: {phishing_count}\n  AUWL Score: {int(auwl_score)}")
            else:
                score_breakdown.append("AUWL: No relevant data found.")


            # AlphabetSoup parsing (DGA detection)
            if "ALPHABETSOUP" in borealis_report:
                alphabet_soup_report = borealis_report["AlphabetSoup"]
                dga_detected = alphabet_soup_report.get("dga_detected", False)
                if dga_detected:
                    total_score += max_scores["AlphabetSoup"]
                    malicious_count += 1
                    score_breakdown.append(f"AlphabetSoup: DGA Detected (malicious)")
                else:
                    score_breakdown.append(f"AlphabetSoup: No DGA detected")
        
            # Top1M parsing (Majestic, Tranco, Cisco block detection)
            if "TOP1MILLION" in borealis_report:
                top1m_report = borealis_report["TOP1MILLION"]
                blocked_by = top1m_report.get("blocked_by", [])
                if blocked_by:
                    top1m_score = min(len(blocked_by) * 20, max_scores["TOP1MILLION"])
                    total_score += top1m_score
                    malicious_count += 1
                    score_breakdown.append(f"Top1M: Blocked by {', '.join(blocked_by)} (score: {top1m_score})")
                else:
                    score_breakdown.append("Top1M: Not blocked by Majestic, Tranco, or Cisco")
        
            # Stonewall parsing (approval for blocking)
            if "STONEWALL" in borealis_report:
                stonewall_report = borealis_report["STONEWALL"]
                approved_for_blocking = stonewall_report.get("approved", False)
                if approved_for_blocking:
                    total_score += max_scores["STONEWALL"]
                    malicious_count += 1
                    score_breakdown.append(f"Stonewall: Approved for blocking (malicious)")
                else:
                    score_breakdown.append("Stonewall: Not approved for blocking")

        # Hash-based IOC
        elif ioc_type == "hash":
            # VirusTotal parsing
            if 'VirusTotal' in reports:
                vt_report = reports['VirusTotal']
                malicious_count, suspicious_count, last_analysis_date_formatted, crowdsourced_context, tags, registrar, creation_date = extract_vt_analysis(vt_report)

                #print(f"DEBUG: Malicious Count: {malicious_count}, Suspicious Count: {suspicious_count}")

                malicious_count = malicious_count or 0
                suspicious_count = suspicious_count or 0

                vt_score = (malicious_count * 1) + (suspicious_count * 0.5)  # Weight for malicious and suspicious
                #print(f"DEBUG: VirusTotal Score: {vt_score}")
                total_score += min(vt_score, max_scores.get("VirusTotal", 100))
                #print(f"DEBUG: Total Score after VirusTotal: {total_score}")
                

                # Extract categories, popularity ranks, and other information
                categories = vt_report.get('data', {}).get('attributes', {}).get('categories', None)
                categories_str = process_dynamic_field(categories)
                popularity_ranks = vt_report.get('data', {}).get('attributes', {}).get('popularity_ranks', {})
                popularity_str = process_dynamic_field(popularity_ranks)

                score_breakdown.append(f"VirusTotal:\n  Malicious={malicious_count}\n  Suspicious={suspicious_count}")
                score_breakdown.append(f"  Categories: {categories_str}")
                score_breakdown.append(f"  Popularity Ranks: {popularity_str}")
                score_breakdown.append(f"  Tags: {tags}")
                score_breakdown.append(f"  Last Analysis Date: {last_analysis_date_formatted}")

                # Process signature information
                signature_info = vt_report.get('data', {}).get('attributes', {}).get('signature_info', {})

                if isinstance(signature_info, dict):
                    verified = signature_info.get('verified', 'Invalid')
                    signers = signature_info.get('signers', 'Unknown')
                    
                    signers_str = ', '.join(signers) if isinstance(signers, list) else str(signers)
                
                    if verified == 'Signed':
                        score_breakdown.append(f"  Signature: Valid (Signed by: {signers_str})")
                        total_score -= 2  # Reduce score for valid signature
                    else:
                        score_breakdown.append("  Signature: Invalid or not present")
                        total_score += 20  # Increase score if invalid or not found
                else:
                    score_breakdown.append("  Signature: No signature information available")

                # Handle crowdsourced context
                if isinstance(crowdsourced_context, str):
                    # If it's a string, just use it as is
                    crowdsourced_context_formatted = crowdsourced_context
                elif isinstance(crowdsourced_context, dict):
                    # Format it if it's a dictionary (if needed)
                    crowdsourced_context_formatted = format_crowdsourced_context(crowdsourced_context)
                else:
                    crowdsourced_context_formatted = 'N/A'  # Default if it's not found

                # Process threat severity
                threat_severity = vt_report.get('data', {}).get('attributes', {}).get('threat_severity', {})

                if isinstance(threat_severity, dict):
                    severity_level = threat_severity.get('level_description', 'N/A')
                    threat_category = threat_severity.get('threat_severity_data', {}).get('popular_threat_category', 'N/A')
                    num_gav_detections = threat_severity.get('threat_severity_data', {}).get('num_gav_detections', 0)
                else:
                    severity_level = 'N/A'
                    threat_category = 'N/A'
                    num_gav_detections = 0

                    #print(f"DEBUG: Threat Severity Level: {severity_level}, GAV Detections: {num_gav_detections}")
                    num_gav_detections = num_gav_detections or 0  # Ensure it's not None
            
                    score_breakdown.append(f"  Threat Severity: {severity_level}, Category: {threat_category}, GAV Detections: {num_gav_detections}")
                    total_score += 10  # Adjust score based on threat severity

                # Process Sigma rules
                sigma_rules = vt_report.get('data', {}).get('attributes', {}).get('sigma_analysis_results', [])
                if sigma_rules:
                    sigma_rule_names = [rule.get('rule_title', 'Unknown Sigma Rule') for rule in sigma_rules]
                    
                    score_breakdown.append(f"  Sigma Rules: {', '.join(sigma_rule_names)}")
                    total_score += len(sigma_rules) * 5  # Add 5 points per Sigma rule
            else:
                score_breakdown.append("VirusTotal: No data available")

            # YARA Rules (Livehunt) parsing
            livehunt_yara_rules = vt_report.get('livehunt_yara_rules', [])
            if livehunt_yara_rules:
                total_score += len(livehunt_yara_rules) * 10  # Add weight for each matching YARA rule
                
                score_breakdown.append(f"  Livehunt YARA Rules: {', '.join([rule['rule_name'] for rule in livehunt_yara_rules])}")


            # Crowdsourced YARA rules parsing
            crowdsourced_yara_rules = vt_report.get('crowdsourced_yara_rules', [])
            if crowdsourced_yara_rules:
                total_score += len(crowdsourced_yara_rules) * 5  # Add a smaller weight for community YARA rules
                
                score_breakdown.append(f"  Crowdsourced YARA Rules: {', '.join([rule['rule_name'] for rule in crowdsourced_yara_rules])}")


            # Dynamic Analysis Sandbox Detections parsing
            sandbox_detections = vt_report.get('sandbox_verdicts', [])
            if sandbox_detections:
                total_score += len(sandbox_detections) * 8  # Add weight for each sandbox detection
                
                score_breakdown.append(f"  Dynamic Analysis Sandbox Detections: {', '.join([d['verdict'] for d in sandbox_detections])}")


            # MalwareBazaar parsing
            malwarebazaar_report = reports.get("MalwareBazaar", {})
            if isinstance(malwarebazaar_report, dict):
                country = malwarebazaar_report.get("origin_country", "N/A")
                intelligence = malwarebazaar_report.get("intelligence", {})
                downloads = intelligence.get("downloads", 0)
                uploads = intelligence.get("uploads", "0")
                delivery_method = malwarebazaar_report.get("delivery_method", "N/A")

                #print(f"DEBUG: MalwareBazaar Downloads: {downloads}, Uploads: {uploads}")
                
                tags = ', '.join(malwarebazaar_report.get('tags', [])) if malwarebazaar_report.get('tags') else 'N/A'
                filename = malwarebazaar_report.get("file_name", "N/A")

                # Ensure downloads and uploads are integers
                try:
                    downloads = int(downloads)
                    uploads = int(uploads)
                except ValueError:
                    downloads = 0
                    uploads = 0

                if country != "N/A" or downloads > 0:
                    malicious_count += 1
                score_breakdown.append(f"MalwareBazaar:\n  Country={country}\n  Downloads={downloads}\n  Filename={filename}\n  Uploads={uploads}\n  Delivery Method={delivery_method}\n  Tags={tags}")
                total_sources += 1
                total_score += downloads  # Add downloads to score
            else:
                score_breakdown.append("MalwareBazaar: No data available")

            # AlienVault parsing for hashes
            alienvault_report = reports.get("AlienVault", {})
            if isinstance(alienvault_report, dict):
                pulses = alienvault_report.get("pulse_count", 0)
                malware_families = alienvault_report.get("malware_families", 0)
                total_sources += 1
                if pulses + malware_families > 0:
                    malicious_count += 1
                score_breakdown.append(f"AlienVault:\n  Pulses={pulses}\n  Malware Families={malware_families}")

                asn = str(alienvault_report.get("asn", ""))
                organization = alienvault_report.get("organization", "")
                domain = alienvault_report.get("domain", "") or ""
                isp = alienvault_report.get("isp", "") or ""
                indicator = alienvault_report.get("indicator", "")
            else:
                score_breakdown.append("AlienVault: No data available")

            # Metadefender parsing for hashes
            metadefender_report = reports.get("MetaDefender", {})
            if isinstance(metadefender_report, dict):
                detected_by = metadefender_report.get('detected_by', 0)

                #print(f"DEBUG: Metadefender Detected By: {detected_by}")

                if detected_by is None:
                    detected_by = 0
                    
                total_score += detected_by * 3  # Adjust score based on detection engines
                score_breakdown.append(f"Metadefender:\n  Detected By={detected_by}")
            else:
                score_breakdown.append("Metadefender: No data available")


            # Hybrid Analysis parsing
            hybrid_analysis_report = reports.get("Hybrid-Analysis", {})
            if isinstance(hybrid_analysis_report, dict):  # Ensure it's a dictionary
                report_hybrid_analysis = hybrid_analysis_report
                if report_hybrid_analysis:
                    # Extract necessary fields directly from the report_hybrid_analysis
                    file_name = report_hybrid_analysis.get("submit_name", report_hybrid_analysis.get("file_name", "N/A"))
                    threat_score = report_hybrid_analysis.get("threat_score", 0)
                    if threat_score is None:
                        threat_score = 0  # Default to 0 if no threat score is available
                        
                    verdict = report_hybrid_analysis.get("verdict", "N/A")
                    classification_tags = ''.join(report_hybrid_analysis.get("classification_tags", [])) if report_hybrid_analysis.get("classification_tags") else "None"
                    vx_family = report_hybrid_analysis.get("vx_family", "N/A")
                    total_processes = report_hybrid_analysis.get("total_processes", 0)
                    total_network_connections = report_hybrid_analysis.get("total_network_connections", 0)
                    
                    # Process MITRE ATT&CK data
                    mitre_attcks = report_hybrid_analysis.get("mitre_attcks", [])

                    if isinstance(mitre_attcks, list):
                        mitre_attcks_str = ', '.join(
                            [f"{attack.get('tactic', 'N/A')} - {attack.get('technique', 'N/A')} (ID: {attack.get('attck_id', 'N/A')})"
                             for attack in mitre_attcks]
                        )
                    elif isinstance(mitre_attcks, str):
                        mitre_attcks_str = mitre_attcks  # If it's already a string, use it directly
                    else:
                        mitre_attcks_str = "None"
                    
                    # Scale threat score and add to total score
                    ha_score = threat_score * 0.7  # Scale to a maximum of 70
                    total_score += min(ha_score, max_scores.get("Hybrid-Analysis", 70))
            
                    # Append Hybrid-Analysis details to the score breakdown
                    score_breakdown.append(f"Hybrid Analysis:\n"
                                           f"  Verdict: {verdict}\n"
                                           f"  Threat Score: {threat_score}\n"
                                           f"  File Name: {file_name}\n"
                                           f"  Classification Tags: {classification_tags}\n"
                                           f"  Family: {vx_family}\n"
                                           f"  Total Processes: {total_processes}\n"
                                           f"  Total Network Connections: {total_network_connections}\n"
                                           f"  MITRE ATT&CK Tactics: {mitre_attcks_str}\n")
            else:
                score_breakdown.append("Hybrid Analysis: No data available")



        # Final score scaling: Scale total score to 100
        scaled_total_score = (total_score / max_possible_score) * 100 if max_possible_score > 0 else 0
        
        # Final score and verdict calculation
        verdict = "Not Malicious"  # Default verdict

        if ioc_type == "ip":
            # If IP belongs to a trusted provider, mark as Not Malicious
            if trusted_provider_found:
                verdict = "Not Malicious"
                score_breakdown.append(f"Note: IP belongs to trusted provider ({trusted_provider_found}). Verdict set to 'Not Malicious'.")
            else:
                # Adjust the verdict calculation based on scaled total score
                if scaled_total_score == 0:
                    verdict = "Not Malicious"
                elif 1 <= scaled_total_score <= 15:
                    verdict = "Suspicious"
                elif 31 <= scaled_total_score <= 50:
                    verdict = "Probably Malicious"
                else:
                    verdict = "Malicious"
        
        elif ioc_type in ["url", "domain"]:
            # For URLs/domains, adjust verdict based on malicious count and analysis date
            if scaled_total_score > 0:
                if malicious_count >= high_malicious_count_threshold:
                    if recent_analysis:
                        verdict = "Malicious"
                    else:
                        verdict = "Probably Malicious"
                elif malicious_count > 0:
                    if malicious_count > (total_sources / 2):
                        verdict = "Probably Malicious"
                    else:
                        verdict = "Suspicious"
                else:
                    verdict = "Not Malicious"
            else:
                verdict = "Not Malicious"
        
        elif ioc_type == "hash":
            # For hashes, base verdict primarily on the scaled score
            if scaled_total_score == 0:
                verdict = "Not Malicious"
            elif 1 <= scaled_total_score <= 15:
                verdict = "Suspicious"
            elif 31 <= scaled_total_score <= 50:
                verdict = "Probably Malicious"
            else:
                verdict = "Malicious"
        
        else:
            # If IOC type is unknown or not handled, default to Not Malicious
            verdict = "Not Malicious"
        
        # Add trusted provider warning if detected, but do not affect verdict or score
        if trusted_provider_found:
            score_breakdown.append(f"  Warning: Hosted on a trusted provider (Provider: {trusted_provider_found}). Proceed with caution...")
        
        # Display the final score and verdict at the top of the breakdown
        verdict_str = f"Verdict: {verdict}"
        total_score_str = f"Total Score: {total_score} out of {max_possible_score} ({scaled_total_score:.2f}%)\n"
        
        # Debugging
        print(f"DEBUG: Total Score = {total_score}, Verdict = {verdict}, Breakdown = {score_breakdown}")
        
        # Append the score and verdict to the top of the breakdown
        score_breakdown.insert(0, total_score_str)
        score_breakdown.insert(0, verdict_str)
        
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



def analysis(selected_category, output_file_path=None, progress_bar=None, status_output=None):
    print(f"DEBUG: analysis function started with selected_category = {selected_category}")
    individual_combined_reports = {}
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
    # if 'ips' not in selected_category:
    #     print("DEBUG: 'ips' not found in selected_category, initializing empty list for 'ips'")
    #     selected_category['ips'] = []
    # if 'urls' not in selected_category:
    #     print("DEBUG: 'urls' not found in selected_category, initializing empty list for 'urls'")
    #     selected_category['urls'] = []
    # if 'hashes' not in selected_category:
    #     print("DEBUG: 'hashes' not found in selected_category, initializing empty list for 'hashes'")
    #     selected_category['hashes'] = []

    # Handle category-specific processing and ensure all IOC types are present
    selected_category.setdefault('ips', [])
    selected_category.setdefault('urls', [])
    selected_category.setdefault('domains', [])  # Add this line to handle domains
    selected_category.setdefault('hashes', [])

    print(f"DEBUG: Updated selected_category = {selected_category}")

    # Calculate total API calls based on the number of IOCs in each category
    total_api_calls = (
        len(selected_category['ips']) * 10  # 10 API calls per IP
        + len(selected_category['urls']) * 9  # 9 API calls per URL
        + len(selected_category['domains']) * 9  # 9 API calls per domain (if treated separately from URLs)
        + len(selected_category['hashes']) * 4  # 4 API calls per hash
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

                combined_report = f"Analysis for {sanitize_and_defang(entry)} ({category.upper()}):\n\n"

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
                    report_binaryedge_ip = get_binaryedge_report(entry, ioc_type="ip", status_output=status_output, progress_bar=progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                    report_metadefender_ip = analyze_with_metadefender(entry, ioc_type="ip", metadefender_api_key=metadefender_api_key, status_output=status_output, progress_bar=progress_bar)
                    if progress_bar:
                        progress_bar.value += 1
                    # Borealis Report
                    borealis_report = request_borealis(entry, ioc_type="ip", status_output=status_output, progress_bar=progress_bar)
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
                        combined_report += f"Verdict: {verdict} (Score: {total_score}) (Belongs to {trusted_provider_found})\n\n"
                    else:
                        combined_report += f"Verdict: {verdict} (Score: {total_score})\n\n"
                 
                                        
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

                    # # Calculate verdict and score breakdown
                    # total_score, breakdown, verdict = calculate_total_malicious_score(
                    #     {
                    #         "VirusTotal": report_vt_ip,
                    #         "AbuseIPDB": report_abuseipdb,
                    #         "IPQualityScore": report_ipqualityscore,
                    #         "GreyNoise": report_greynoise,
                    #         "AlienVault": report_alienvault,
                    #     },
                    #     borealis_report,
                    #     ioc_type="ip"
                    # )
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
                        ioc_type="url"
                    )

                    if trusted_provider_found:
                        provider_list = ', '.join(trusted_provider_found)
                        combined_report += f"Verdict: {verdict} (Score: {total_score}) (Hosted on: {provider_list})\n\n"
                    else:
                        combined_report += f"Verdict: {verdict} (Score: {total_score})\n\n"
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
                        combined_report += "AlienVault OTX Report:\nN/A or Error\n\n"
                
                    # URLScan Report
                    if report_urlscan and isinstance(report_urlscan, dict):
                        last_analysis_date = report_urlscan.get('task', {}).get('time', 'N/A')
                        combined_report += f"URLScan Report:\n"
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
                    combined_report += f"Verdict: {verdict} (Score: {total_score})\n\n"
                
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
                
                    individual_combined_reports[category].append(combined_report)

            print(f"Completed Processing {category.upper()}\n")

    # Prepare the aggregated report for all IOCs
    aggregated_report = "\n".join([
        f"{'.' * 150}\nIOC: {sanitize_and_defang(ioc[0])}" +
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