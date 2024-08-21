import os
import time
import json
import ast
from datetime import datetime, timedelta
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
    get_domain_report
)
from api_interactions.shodan import get_shodan_report
from api_interactions.alienvault import get_alienvault_report
from api_interactions.ipqualityscore import get_ipqualityscore_report
from api_interactions.greynoise import get_greynoise_report
from api_interactions.urlscan import (
    submit_url_to_urlscan,
    get_urlscan_report
)
from api_interactions.censys import get_censys_data
from api.api_keys import censys_api_key, censys_secret
from api_interactions.borealis import request_borealis, format_borealis_report


def start_validation(choice, output_to_file, raw_input=None, file_input=None, file_name_input=None, progress_bar=None, status_output=None):
    output_file_path = None

    # Determine if output should be saved to a file
    if output_to_file:
        output_file_path = file_name_input

    # Parsing user input
    iocs = None
    if raw_input:
        iocs = parse_bulk_iocs(raw_input)
    elif file_input:
        iocs = parse_bulk_iocs(file_input)

    # Validate IOCs based on the selected category (choice)
    if choice == "1":  # IPs selected
        if any(not is_ip(ioc) for ioc in iocs['ips']):
            raise ValueError("Error: You selected 'IP' but entered a URL or hash. Please reset and enter a valid IP address.")
    elif choice == "2":  # URLs/Domains selected
        if any(not is_url(ioc) for ioc in iocs['urls']):
            raise ValueError("Error: You selected 'URL/Domain' but entered an IP or hash. Please reset and enter a valid URL or domain.")
    elif choice == "3":  # Hashes selected
        if any(not is_hash(ioc) for ioc in iocs['hashes']):
            raise ValueError("Error: You selected 'Hash' but entered an IP or domain. Please reset and enter a valid hash.")

    # If no validation errors, proceed with the analysis
    print(f"DEBUG: Starting analysis with ioc_type = {choice} and IOCs = {iocs}")

    # Display progress
    if progress_bar:
        clear_output()
        display(progress_bar, HTML('<b>Performing analysis...</b>'))

    # Proceed with analysis if input is valid
    aggregated_report = analysis(choice, iocs, output_file_path, progress_bar, status_output)

    if output_to_file:
        with open(output_file_path, "a") as outfile:
            outfile.write(aggregated_report)

    return aggregated_report


def validate_iocs():
    while True:
        print("Welcome to the IOC validation Python script.")
        print("Hopefully, with this script, it will be easier to validate IOCs and check if they are malicious or not.")
        print("\nWhich of the following IOCs do you want to validate:")
        print("[1] IPs")
        print("[2] URLs/Domains")
        print("[3] Hashes")
        print("[4] Bulk IOCs")
        print("[5] Exit script")
        print("[-h]/[--help] Help")
        choice = input("Choose an option 1, 2, 3, 4, 5 for validation, as well you can choose -h or --help for more information.\nYour choice: ")

        if choice.lower() in ['-h', '--help']:
            print_help()
            continue 
        elif choice in ['1', '2', '3', '4', '5']:
            return choice 
        else:
            print("\nInvalid option, please select again.")


def parse_bulk_iocs(content):
    iocs = {'ips': [], 'urls': [], 'hashes': []}
    if not content:
        return iocs
    for line in content.splitlines():
        line = line.strip()
        if line:
            if is_ip(line):
                iocs['ips'].append(line)
            elif is_url(line):
                iocs['urls'].append(line)
            elif is_hash(line):
                iocs['hashes'].append(line)
            else:
                print(f"Sorry, we were unable to recognize IOC format: {line}")
    return iocs


def extract_last_analysis_date(vt_report):
    if vt_report and 'data' in vt_report and 'attributes' in vt_report['data']:
        return vt_report['data']['attributes'].get('last_analysis_date')
    return None


def format_date(timestamp):
    if timestamp:
        return datetime.utcfromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
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
    else:
        formatted_context = crowdsourced_context
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


# Malwarebazaar
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


trusted_asn_list = {
    "Google": 15169,
    "Cloudflare": 13335,
    "Amazon": 16509,
    "Microsoft": 8075,
    "Akamai": 20940,
    "Shodan": 20473,  # Shodan is trusted but does not count towards malicious score.
}


def check_trusted_provider(asn, organization, domain, isp, ioc=None, indicator=None):
    """
    Check if the ASN, organization, domain, ISP, IOC (from VirusTotal), or Indicator (from AlienVault) 
    matches a trusted provider.
    Handles cases where organization, domain, or ISP might be a list.
    """
    # Default empty strings for None values
    asn = asn or ""
    organization = organization or ""
    domain = domain or ""
    isp = isp or ""
    ioc = ioc or ""
    indicator = indicator or ""

    # If organization, domain, isp, or other fields are lists, convert them to a comma-separated string
    if isinstance(organization, list):
        organization = ', '.join(organization)
    if isinstance(domain, list):
        domain = ', '.join(domain)
    if isinstance(isp, list):
        isp = ', '.join(isp)

    # List of trusted providers with variations
    trusted_variations = {
        "Amazon": ["Amazon", "amazonaws.com", "amazon.com", "amazon"],
        "Google": ["Google", "GOOGLE", "google.com", "google.ca", "GOOGLE-CLOUD-PLATFORM", "google"],
        "Cloudflare": ["Cloudflare", "CLOUDFLARENET", "AS13335 cloudflare", "cloudflare"],
        "Microsoft": ["Microsoft", "MICROSOFT-CORP"],
        # Add other trusted providers as needed
    }

    # Normalize all values to lowercase for case-insensitive matching
    asn = asn.lower()
    organization = organization.lower()
    domain = domain.lower()
    isp = isp.lower()
    ioc = ioc.lower()
    indicator = indicator.lower()

    # Check each provider and its variations
    for provider, variations in trusted_variations.items():
        if (asn == str(trusted_asn_list.get(provider, "")).lower()) or \
           any(var.lower() in organization for var in variations) or \
           any(var.lower() in domain for var in variations) or \
           any(var.lower() in isp for var in variations) or \
           any(var.lower() in ioc for var in variations) or \
           any(var.lower() in indicator for var in variations):
            return provider

    return None


def calculate_total_malicious_score(reports, borealis_report, ioc_type):
    total_score = 0
    breakdown = []
    malicious_count = 0
    total_sources = 0
    trusted_provider_found = None

    try:
        # IP-based IOC
        if ioc_type == "ip":
            # VirusTotal parsing for malicious and suspicious detections
            if 'VirusTotal' in reports:
                vt_report = reports['VirusTotal']
                malicious = vt_report.get('malicious', 0)
                suspicious = vt_report.get('suspicious', 0)
                total_score += malicious * 10  # Weight for malicious detections
                total_score += suspicious * 5  # Weight for suspicious detections
                breakdown.append(f"VirusTotal:\n  Malicious={malicious}\n  Suspicious={suspicious}")
        
                # Crowdsourced context
                if 'crowdsourced_context' in vt_report:
                    crowdsourced_context = vt_report.get('crowdsourced_context', 'N/A')
                    if crowdsourced_context != 'N/A':
                        total_score += 15  # Weight for crowdsourced context indicating malicious activity
                        breakdown.append(f"  Crowdsourced Context: {crowdsourced_context}")
        
            # YARA Rules (Livehunt) parsing
            if 'Livehunt YARA Rules' in reports:
                yara_rules = reports['Livehunt YARA Rules']
                if yara_rules:
                    total_score += len(yara_rules) * 10  # Weight for each matching YARA rule
                    breakdown.append(f"  Livehunt YARA Rules: {', '.join(yara_rules)}")
        
            # Crowdsourced IDS rules parsing
            if 'Crowdsourced IDS Rules' in reports:
                ids_rules = reports['Crowdsourced IDS Rules']
                if ids_rules:
                    total_score += len(ids_rules) * 5  # Weight for each IDS rule
                    breakdown.append(f"  Crowdsourced IDS Rules: {', '.join(ids_rules)}")
        
            # Dynamic Analysis Sandbox Detections
            if 'Dynamic Analysis Sandbox Detections' in reports:
                sandbox_detections = reports['Dynamic Analysis Sandbox Detections']
                if sandbox_detections:
                    total_score += len(sandbox_detections) * 8  # Weight for each sandbox detection
                    breakdown.append(f"  Dynamic Analysis Sandbox Detections: {', '.join(sandbox_detections)}")
        
            # Signature information
            if 'Signature Information' in reports:
                signature_info = reports['Signature Information']
                if signature_info.get('valid_signature', False):
                    breakdown.append("  Signature Information: Valid Signature found")
                else:
                    total_score += 20  # If signature is not valid, increase the score
                    breakdown.append("  Signature Information: Invalid or no signature")

            # AbuseIPDB
            abuseipdb_report = reports.get("AbuseIPDB", {})
            if isinstance(abuseipdb_report, dict):
                confidence_score = int(abuseipdb_report.get('abuseConfidenceScore', 0))
                total_reports = int(abuseipdb_report.get('totalReports', 0))
                is_tor = abuseipdb_report.get('isTor', False)
                
                if confidence_score > 0:
                    total_sources += 1
                    malicious_count += 1
                    total_score += confidence_score
                
                breakdown.append(f"\nAbuseIPDB:\n  Confidence Score={confidence_score}\n  Total Reports={total_reports}\n  Is Tor={is_tor}")

            # IPQualityScore
            ipqs_report = reports.get("IPQualityScore", {})
            if isinstance(ipqs_report, str):
                ipqs_report = parse_ipqualityscore_report(ipqs_report)
            
            if isinstance(ipqs_report, dict) and ipqs_report:
                score_ipqs = ipqs_report.get("fraud_score", 0)
                total_sources += 1
                if int(score_ipqs) > 0:
                    malicious_count += 1
                total_score += int(score_ipqs)
                breakdown.append(
    f"IPQualityScore:\n  Fraud Score={score_ipqs}\n  VPN={ipqs_report.get('vpn', False)}\n"
    f"  Tor={ipqs_report.get('tor', False)}\n  Proxy={ipqs_report.get('proxy', False)}"
)

                asn = str(ipqs_report.get("asn", ""))
                organization = ipqs_report.get("organization", "")
                domain = ipqs_report.get("host", "") or ""
                isp = ipqs_report.get("isp", "") or ""
                provider = check_trusted_provider(asn, organization, domain, isp)
                if provider:
                    trusted_provider_found = provider
            else:
                breakdown.append("IPQualityScore: No data available")

            # GreyNoise
            greynoise_report = reports.get("GreyNoise", {})
            if isinstance(greynoise_report, dict):
                classification = greynoise_report.get("classification", "unknown")
                total_sources += 1
                if classification != "benign":
                    malicious_count += 1
                breakdown.append(f"GreyNoise:\n  Classification={classification}")

            # AlienVault
            alienvault_report = reports.get("AlienVault", {})
            if isinstance(alienvault_report, dict):
                pulses = alienvault_report.get("pulse_count", 0)
                malware_families = alienvault_report.get("malware_families", 0)
                asn = alienvault_report.get("asn", 0)
                total_sources += 1
                if pulses + malware_families > 0:
                    malicious_count += 1
                breakdown.append(f"AlienVault:\n  Pulses={pulses}\n  Malware Families={malware_families}\n  ASN={asn}")

                asn = str(alienvault_report.get("asn", ""))
                organization = alienvault_report.get("organization", "")
                domain = ""  # Default to empty string
                isp = alienvault_report.get("isp", "") or ""
                indicator = alienvault_report.get("indicator", "")  # Extract Indicator field from AlienVault
                provider = check_trusted_provider(asn, organization, domain, isp, indicator=indicator)
                if provider:
                    trusted_provider_found = provider
                    breakdown.append(f"  Trusted Provider Detected in AlienVault: {trusted_provider_found}")

            # Censys
            censys_report = reports.get("Censys", {})
            if isinstance(censys_report, dict):
                total_sources += 1
                breakdown.append(f"Censys:\n  Organization={censys_report.get('organization', 'N/A')}")
                
                asn = str(censys_report.get("asn", ""))
                organization = censys_report.get("organization", "")
                provider = check_trusted_provider(asn, organization, "", "")
                if provider:
                    trusted_provider_found = provider
                    
            # Shodan
            shodan_report = reports.get("Shodan", {})
            if isinstance(shodan_report, dict):
                asn = str(shodan_report.get("asn", ""))
                organization = shodan_report.get("organization", "")
                provider = check_trusted_provider(asn, organization, "", "")
                if provider:
                    trusted_provider_found = provider
                    breakdown.append(f"  Trusted Provider Detected in Shodan: {trusted_provider_found}...Proceed with caution")

            # Borealis info
            breakdown.append("Borealis Report:")
            borealis_info = extract_borealis_info(borealis_report)
            breakdown.append(f"  {borealis_info}")

        # URL and Domain-based IOC
        elif ioc_type in ["url", "domain"]:
            # VirusTotal
            if 'VirusTotal' in reports:
                vt_report = reports['VirusTotal']
                
                malicious_count = vt_report.get('malicious', 0)
                suspicious_count = vt_report.get('suspicious', 0)
                total_score += malicious_count
                total_score += suspicious_count // 2  # Half weight for suspicious
                
                breakdown.append(f"VirusTotal:\n  Malicious={malicious_count}\n  Suspicious={suspicious_count}")
        
                # Crowdsourced Context
                crowdsourced_context = vt_report.get('crowdsourced_context', 'N/A')
                if crowdsourced_context != 'N/A':
                    total_score += 2  # Arbitrary weight for crowdsourced context
                    breakdown.append(f"  Crowdsourced Context: {crowdsourced_context}")
                
                # YARA Rules
                yara_rules = vt_report.get('yara_rules', [])
                if yara_rules:
                    total_score += len(yara_rules)  # Add weight per YARA rule
                    breakdown.append(f"  Livehunt YARA Rules: {', '.join(yara_rules)}")
                
                # Crowdsourced IDS Rules
                ids_rules = vt_report.get('crowdsourced_ids_rules', [])
                if ids_rules:
                    total_score += len(ids_rules)  # Add weight per IDS rule
                    breakdown.append(f"  Crowdsourced IDS Rules: {', '.join(ids_rules)}")
                
                # Dynamic Analysis Sandbox Detections
                sandbox_detections = vt_report.get('dynamic_analysis_detections', [])
                if sandbox_detections:
                    total_score += len(sandbox_detections)  # Add weight per sandbox detection
                    breakdown.append(f"  Dynamic Analysis Sandbox Detections: {', '.join(sandbox_detections)}")
                
                # Signature Information
                signature_info = vt_report.get('signature_information', {})
                if signature_info.get('valid_signature', False):
                    breakdown.append(f"  Signature Information: Valid signature from {signature_info.get('signature_name', 'N/A')}")
                    total_score -= 2  # Reduce score for valid signatures

            # URLScan
            urlscan_report = reports.get("URLScan", {})
            if isinstance(urlscan_report, dict):
                malicious_urls = urlscan_report.get('Malicious Score', 0)
                tls_issuer = urlscan_report.get('TLS Issuer', 'N/A')
                tls_age = urlscan_report.get('TLS Age (days)', 'N/A')
                redirected = urlscan_report.get('Redirected', 'N/A')
                asn = str(urlscan_report.get("ASN", ""))
                organization = urlscan_report.get("Organization", "")
                domain = urlscan_report.get("Domain", "") or ""
                isp = urlscan_report.get("ISP", "") or ""  # Make sure ISP is retrieved correctly here
                
                score_urlscan = malicious_urls
                total_sources += 1
                if score_urlscan > 0:
                    malicious_count += 1
                total_score += score_urlscan
            
                # Ensure ISP is included in the breakdown
                breakdown.append(f"URLScan:\n  Malicious Score={malicious_urls}\n  ISP={isp}\n  TLS Issuer={tls_issuer}\n  TLS Age={tls_age} days\n  Redirected={redirected}")
            
                # Check for a trusted provider
                provider = check_trusted_provider(asn, organization, domain, isp)
                if provider:
                    breakdown.append(f"  Domain is hosted on a trusted provider (ISP: {provider})")

            # AlienVault
            alienvault_report = reports.get("AlienVault", {})
            if isinstance(alienvault_report, dict):
                pulses = alienvault_report.get("pulse_count", 0)
                malware_families = alienvault_report.get("malware_families", 0)
                total_sources += 1
                if pulses + malware_families > 0:
                    malicious_count += 1
                breakdown.append(f"AlienVault:\n  Pulses={pulses}\n  Malware Families={malware_families}")

                asn = str(alienvault_report.get("asn", ""))
                organization = alienvault_report.get("organization", "")
                domain = alienvault_report.get("domain", "") or ""
                isp = alienvault_report.get("isp", "") or ""
                indicator = alienvault_report.get("indicator", "")  # Extract Indicator field from AlienVault
                provider = check_trusted_provider(asn, organization, domain, isp, indicator=indicator)
                if provider:
                    trusted_provider_found = provider
                    breakdown.append(f"  Trusted Provider Detected in AlienVault: {trusted_provider_found}")

            # Extract Borealis information and append to the breakdown
            breakdown.append("Borealis Report:")
            borealis_info = extract_borealis_info(borealis_report)
            breakdown.append(f"{borealis_info}")
                    
        # Hash-based IOC
        elif ioc_type == "hash":
            # VirusTotal
            if 'VirusTotal' in reports:
                vt_report = reports['VirusTotal']
                
                # Extract malicious and suspicious counts from the nested 'last_analysis_stats' field
                last_analysis_stats = vt_report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious_count = last_analysis_stats.get('malicious', 0)
                suspicious_count = last_analysis_stats.get('suspicious', 0)
                
                # Debugging: Ensure we're extracting the right values from the report
                print(f"DEBUG: Extracted Malicious count: {malicious_count}")
                print(f"DEBUG: Extracted Suspicious count: {suspicious_count}")
                
                total_score += int(malicious_count)  # Ensure it's converted to an integer
                total_score += int(suspicious_count) // 2  # Half weight for suspicious detections
                
                # Update breakdown with correct counts
                breakdown.append(f"VirusTotal:\n  Malicious={malicious_count}\n  Suspicious={suspicious_count}")
                
                # Signature Information
                signature_info = vt_report.get('signature_information', {})
                if signature_info.get('valid_signature', False):
                    breakdown.append(f"  Signature: Valid signature from {signature_info.get('signature_name', 'N/A')}")
                    total_score -= 2  # Reduce score for valid signatures
                else:
                    breakdown.append("Signature: Invalid or no signature found\n")
                
                # Crowdsourced Context
                crowdsourced_context = vt_report.get('crowdsourced_context', 'N/A')
                if crowdsourced_context != 'N/A':
                    total_score += 2  # Arbitrary weight for crowdsourced context
                    breakdown.append(f"  Crowdsourced Context: {crowdsourced_context}")
                
                # YARA Rules
                yara_rules = vt_report.get('yara_rules', [])
                if yara_rules:
                    total_score += len(yara_rules)  # Add weight per YARA rule
                    breakdown.append(f"  Livehunt YARA Rules: {', '.join(yara_rules)}")
                
                # Crowdsourced IDS Rules
                ids_rules = vt_report.get('crowdsourced_ids_rules', [])
                if ids_rules:
                    total_score += len(ids_rules)  # Add weight per IDS rule
                    breakdown.append(f"  Crowdsourced IDS Rules: {', '.join(ids_rules)}")
                
                # Dynamic Analysis Sandbox Detections
                sandbox_detections = vt_report.get('dynamic_analysis_detections', [])
                if sandbox_detections:
                    total_score += len(sandbox_detections)  # Add weight per sandbox detection
                    breakdown.append(f"  Dynamic Analysis Sandbox Detections: {', '.join(sandbox_detections)}")
        
            # MalwareBazaar
            malwarebazaar_report = reports.get("MalwareBazaar", {})
            if isinstance(malwarebazaar_report, dict):
                country = malwarebazaar_report.get("origin_country", "N/A")
                intelligence = malwarebazaar_report.get("intelligence", {})
                downloads = intelligence.get("downloads", "0")
                uploads = intelligence.get("uploads", "0")
                delivery_method = malwarebazaar_report.get("delivery_method", "N/A")  # Add Delivery Method
                tags = ', '.join(malwarebazaar_report.get('tags', [])) if malwarebazaar_report.get('tags') else 'N/A'  # Add Tags
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
                breakdown.append(f"MalwareBazaar:\n  Country={country}\n  Downloads={downloads}\n  Filename={filename}\n  Uploads={uploads}\n  Delivery Method={delivery_method}\n  Tags={tags}")
                total_sources += 1
                total_score += downloads  # Add downloads to score
            
            # AlienVault
            alienvault_report = reports.get("AlienVault", {})
            if isinstance(alienvault_report, dict):
                pulses = alienvault_report.get("pulse_count", 0)
                malware_families = alienvault_report.get("malware_families", 0)
                total_sources += 1
                if pulses + malware_families > 0:
                    malicious_count += 1
                breakdown.append(f"AlienVault:\n  Pulses={pulses}\n  Malware Families={malware_families}")
        
                asn = str(alienvault_report.get("asn", ""))
                organization = alienvault_report.get("organization", "")
                domain = alienvault_report.get("domain", "") or ""
                isp = alienvault_report.get("isp", "") or ""
                indicator = alienvault_report.get("indicator", "")  # Extract Indicator field from AlienVault
                provider = check_trusted_provider(asn, organization, domain, isp, indicator=indicator)
                if provider:
                    trusted_provider_found = provider
                    breakdown.append(f"  Trusted Provider Detected in AlienVault: {trusted_provider_found}")
        
        # Final score and verdict calculation
        if malicious_count > (total_sources / 2):
            if trusted_provider_found:
                verdict = f"  Not Malicious (Trusted Provider: {trusted_provider_found})"
            else:
                verdict = "Malicious"
        elif trusted_provider_found:
            verdict = "Not Malicious"
            breakdown.append(f"  Trusted Provider Detected: {trusted_provider_found}...Proceed with caution")
        else:
            verdict = "Not Malicious"
        
        return total_score, "\n".join(breakdown), verdict

    except Exception as e:
        return 0, f"Error during score calculation: {str(e)}", "Unknown"


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
    # Calculate total score and breakdown
    total_score, breakdown, verdict = calculate_total_malicious_score(report_data, ioc_type)

    # Define a threshold for determining if something is malicious
    threshold_value = 200  # Adjust this based on your sensitivity needs

    # Return True if the total score meets or exceeds the threshold
    return total_score >= threshold_value, breakdown


def format_alienvault_report(alienvault_report):
    formatted_report = "AlienVault Report:\n"  # Initialize the formatted_report variable

    if isinstance(alienvault_report, dict):

        def add_field_to_report(field_name, field_value):
            nonlocal formatted_report  # Ensure that the inner function uses the outer scope variable
            if field_value or field_value == 0:  # Include even if the value is 0
                formatted_report += f"  - {field_name}: {field_value}\n"

        # Direct fields
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

        # False Positive Information
        false_positive = alienvault_report.get('false_positive', {})
        if isinstance(false_positive, dict):
            add_field_to_report("False Positive Assessment", false_positive.get('assessment', 'N/A'))
            add_field_to_report("False Positive Assessment Date", false_positive.get('assessment_date', 'N/A'))
            add_field_to_report("False Positive Report Date", false_positive.get('report_date', 'N/A'))

        # Malware Families
        malware_families = alienvault_report.get('malware_families', [])
        if malware_families:
            add_field_to_report("Malware Families", ', '.join(malware_families))

        # Sections
        sections = alienvault_report.get('sections', [])
        if sections:
            add_field_to_report("Sections", ', '.join(sections))

        # Pulse Information
        pulse_info = alienvault_report.get('pulse_info', {})
        if pulse_info:
            add_field_to_report("Pulse Count", pulse_info.get('count', 'N/A'))
            if 'pulses' in pulse_info:
                add_field_to_report("Top 3 Pulses", "")
                for i, pulse in enumerate(pulse_info['pulses'][:3], start=1):
                    add_field_to_report(f"  Name", pulse.get('name', 'N/A'))
                    # add_field_to_report(f"  - Author Name", pulse.get('author_name', 'N/A'))
                    # add_field_to_report(f"  - Tags", ', '.join(pulse.get('tags', [])))
                    # add_field_to_report(f"  - TLP", pulse.get('tlp', 'N/A'))
                    # add_field_to_report(f"  - Modified", pulse.get('modified', 'N/A'))
                    # add_field_to_report(f"  - Created", pulse.get('created', 'N/A'))
                    # add_field_to_report(f"  - Description", pulse.get('description', 'N/A'))

        # Related Information
        related_info = alienvault_report.get('related', {})
        if related_info:
            add_field_to_report("Related Adversary", related_info.get('adversary', 'N/A'))
            add_field_to_report("Related Malware Families", ', '.join(related_info.get('malware_families', [])))
            add_field_to_report("Related Industries", ', '.join(related_info.get('industries', [])))

        return formatted_report.strip()  # Remove any trailing newline
    else:
        return "Invalid format for AlienVault report"


def process_individual_ioc_file(file_path, category):
    content = read_file(file_path)
    cleaned_content = clean_input(content)
    iocs = {category: cleaned_content.splitlines()}
    return iocs

    
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

    return "\n".join(breakdown)


def analysis(selected_category, iocs, output_file_path=None, progress_bar=None, status_output=None):
    print(f"DEBUG: analysis function started with selected_category = {selected_category}, iocs = {iocs}")
    
    individual_combined_reports = {}
    ioc_scores = []

    if iocs is None:
        print("DEBUG: IOCs is None")
        return "Error: IOCs are None"

    # Handle category-specific processing and ensure all IOC types are present
    if 'ips' not in iocs:
        print("DEBUG: 'ips' not found in IOCs, initializing empty list for 'ips'")
        iocs['ips'] = []
    if 'urls' not in iocs:
        print("DEBUG: 'urls' not found in IOCs, initializing empty list for 'urls'")
        iocs['urls'] = []
    if 'hashes' not in iocs:
        print("DEBUG: 'hashes' not found in IOCs, initializing empty list for 'hashes'")
        iocs['hashes'] = []

    print(f"DEBUG: Updated IOCs = {iocs}")

    for category, entries in iocs.items():
        if entries:  # Only process if there are entries in the category
            print(f"Processing {category.upper()}...")
            individual_combined_reports[category] = []
        
            total_reports = len(iocs['ips']) * 7 + len(iocs['urls']) * 6 + len(iocs['hashes']) * 4
            progress_step = 100 / total_reports if total_reports > 0 else 1
    
            for count, entry in enumerate(entries, start=1):
                if status_output:
                    clear_output(wait=True)
                    display(HTML(f'<b>Scanning {category.capitalize()} [{count}/{len(entries)}]: {sanitize_and_defang(entry)}</b>'))
                    display(progress_bar)
    
                print(f"\nScanning {category.capitalize()} [{count}/{len(entries)}]: {sanitize_and_defang(entry)}")

                combined_report = f"Analysis for {sanitize_and_defang(entry)} ({category.upper()}):\n\n"

                if category == "ips":
                    report_vt_ip = None
                    report_abuseipdb = None
                    report_shodan = None
                    report_alienvault = None
                    report_ipqualityscore = None
                    report_greynoise = None
                    report_censys = None
                    report_vt_ip = get_ip_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += progress_step
                    report_abuseipdb = get_abuseipdb_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += progress_step
                    report_shodan = get_shodan_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += progress_step
                    report_alienvault = get_alienvault_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += progress_step
                    report_ipqualityscore = get_ipqualityscore_report(entry, full_report=True, status_output=status_output, progress_bar=progress_bar)
                    if progress_bar:
                        progress_bar.value += progress_step
                    report_greynoise = get_greynoise_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += progress_step
                    report_censys = get_censys_data(censys_api_key, censys_secret, entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += progress_step
                    # Borealis Report
                    borealis_report = request_borealis(entry, ioc_type="ip", status_output=status_output, progress_bar=progress_bar)
                    if progress_bar:
                        progress_bar.value += progress_step


                    # Calculate verdict and score breakdown
                    total_score, breakdown, verdict = calculate_total_malicious_score(
                        {
                            "VirusTotal": report_vt_ip,
                            "AbuseIPDB": report_abuseipdb,
                            "IPQualityScore": report_ipqualityscore,
                            "GreyNoise": report_greynoise,
                            "AlienVault": report_alienvault,
                        },
                        borealis_report,
                        ioc_type="ip"
                    )
                    combined_report += f"Verdict: {verdict} (Score: {total_score})\n\n"
                 
                                        
                        # VirusTotal Report
                    if report_vt_ip and report_vt_ip != f"Failed to fetch VirusTotal IP report for {entry}.":
                        malicious_score = report_vt_ip['data']['attributes']['last_analysis_stats']['malicious']
                        suspicious_score = report_vt_ip['data']['attributes']['last_analysis_stats']['suspicious']
                        last_analysis_date = format_date(extract_last_analysis_date(report_vt_ip))
                        av_vendors = extract_av_vendors(report_vt_ip)
                        crowdsourced_context = report_vt_ip['data']['attributes'].get('crowdsourced_context', 'N/A')
                        crowdsourced_context_formatted = format_crowdsourced_context(crowdsourced_context)
                    
                        vt_result = (
                            f"  - IOC: {sanitize_and_defang(entry)} Malicious {malicious_score} Vendor Score\n"
                            f"  - Malicious Detections: {malicious_score}\n"
                            f"  - Suspicious Detections: {suspicious_score}\n"
                            f"  - Malicious Vendors: {', '.join(av_vendors['malicious'])}\n"
                            f"  - Suspicious Vendors: {', '.join(av_vendors['suspicious'])}\n"
                            f"  - Last Analysis Date: {last_analysis_date}\n"
                            f"  - Crowdsourced Context:\n    {crowdsourced_context_formatted}\n"
                        )
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
                    if isinstance(report_ipqualityscore, dict):
                        if not report_ipqualityscore.get("error"):
                            ipqualityscore_str = json.dumps(report_ipqualityscore, indent=2)
                            combined_report += f"IPQualityScore Report:\n{ipqualityscore_str}\n\n"
                        else:
                            combined_report += "IPQualityScore Report:\nN/A\n\n"
                    elif isinstance(report_ipqualityscore, str):
                        if not report_ipqualityscore.startswith("IPQualityScore Report:"):
                            combined_report += f"IPQualityScore Report:\n{sanitize_and_defang(report_ipqualityscore)}\n\n"
                        else:
                            combined_report += f"{sanitize_and_defang(report_ipqualityscore)}\n\n"
    
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
                        combined_report += f"  - Last Seen: {last_analysis_date}\n"
                        combined_report += f"  - First Seen: {report_greynoise.get('first_seen', 'N/A')}\n\n"
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

                    # Format and append the Borealis report to the combined report
                    if borealis_report:
                        formatted_borealis_report = format_borealis_report(borealis_report, ioc_type="ip", request=entry)
                        combined_report += f"{formatted_borealis_report}\n\n"
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
                    combined_report += f"ScoreBreakdown\n{breakdown}\n\n"


                    # Append to scores list for sorting
                    ioc_scores.append((entry, total_score, combined_report))
    
                    individual_combined_reports[category].append(combined_report)
    
                elif category == "urls" or category == "domains":
                    report_vt_url = None
                    report_urlscan = None
                    report_alienvault = None
                    
                    urlscan_uuid = submit_url_to_urlscan(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += progress_step
                    url_id = submit_url_for_analysis(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += progress_step
                    report_alienvault = get_alienvault_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += progress_step
                    if url_id:
                        time.sleep(16)
                        report_vt_url = get_url_report(url_id, status_output, progress_bar)
                        if progress_bar:
                            progress_bar.value += progress_step
                        
                        if urlscan_uuid:
                            report_urlscan = get_urlscan_report(urlscan_uuid, status_output=status_output, progress_bar=progress_bar)
                            if progress_bar:
                                progress_bar.value += progress_step
                        else:
                            report_urlscan = None
                    borealis_report = request_borealis(entry, status_output=status_output, ioc_type="url", progress_bar=progress_bar)
                    if progress_bar:
                        progress_bar.value += progress_step


                        # Calculate verdict and score breakdown
                        total_score, breakdown, verdict = calculate_total_malicious_score(
                            {
                                "VirusTotal": report_vt_url,
                                "URLScan": report_urlscan,
                                "AlienVault": report_alienvault,
                            },
                            borealis_report,
                            ioc_type="url"
                        )
                        combined_report += f"Verdict: {verdict} (Score: {total_score})\n\n"

                
                        # VirusTotal Report
                        if report_vt_url:
                            last_analysis_stats = report_vt_url['data']['attributes']['last_analysis_stats']
                            harmless = last_analysis_stats['harmless']
                            malicious = last_analysis_stats['malicious']
                            suspicious = last_analysis_stats['suspicious']
                            timeout = last_analysis_stats['timeout']
                            undetected = last_analysis_stats['undetected']
                            last_analysis_date = format_date(extract_last_analysis_date(report_vt_url))
                            av_vendors = extract_av_vendors(report_vt_url)
                            vt_result = (
                                f"  - IOC: {sanitize_and_defang(entry)} - Harmless: {harmless}, Malicious: {malicious}, Suspicious: {suspicious}, Timeout: {timeout}, Undetected: {undetected}\n"
                                f"  - Malicious Vendors: {', '.join(av_vendors['malicious'])}\n"
                                f"  - Suspicious Vendors: {', '.join(av_vendors['suspicious'])}\n"
                                f"  - Last Analysis Date: {last_analysis_date}"
                            )
                            combined_report += f"VirusTotal Report:\n{vt_result}\n"
                
                            crowdsourced_context = report_vt_url.get("crowdsourced_context", "N/A")
                            combined_report += f"  - Crowdsourced Context:\n    {crowdsourced_context}\n"
                        else:
                            combined_report += "VirusTotal Report:\nN/A\n\n"
                
                        # AlienVault Report
                        if isinstance(report_alienvault, dict):
                            # Assuming that if there's an error, it will be a specific key in the dictionary.
                            if 'error' not in report_alienvault:
                                combined_report += f"\n{format_alienvault_report(report_alienvault)}\n\n"
                            else:
                                combined_report += "AlienVault OTX Report:\nError reported in AlienVault response\n\n"
                        else:
                            combined_report += "AlienVault OTX Report:\nN/A\n\n"
                
                        # URLScan Report
                        if report_urlscan and "error" in report_urlscan and report_urlscan["error"] == "The domain isn't resolving":
                            combined_report += "URLScan Report:\n  - The domain isn't resolving\n\n"
                        elif report_urlscan:
                            last_analysis_date = report_urlscan.get('task', {}).get('time', 'N/A')
                            combined_report += f"URLScan Report (Task Time: {last_analysis_date}):\n"
                            for key, value in report_urlscan.items():
                                if key == "IP":
                                    value = sanitize_and_defang(value)
                                combined_report += f"  - {key}: {sanitize_and_defang(value)}\n"
                            combined_report += "\n"
                        else:
                            combined_report += "URLScan Report:\nN/A\n\n"

                        if borealis_report:
                            formatted_borealis_report = format_borealis_report(borealis_report, category, entry)
                            combined_report += f"{formatted_borealis_report}\n\n"
                        else:
                            combined_report += "Borealis Report:\nN/A\n\n"

                    # Calculate verdict and score breakdown
                        # total_score, breakdown, verdict = calculate_total_malicious_score(
                        #     {
                        #         "VirusTotal": report_vt_url,
                        #         "URLScan": report_urlscan,
                        #         "AlienVault": report_alienvault,
                        #     },
                        #     borealis_report,
                        #     ioc_type="url"
                        # )
                        # combined_report += f"Verdict: {verdict} (Score: {total_score})\n\nScore Breakdown\n{breakdown}\n\n"

                        combined_report += f"Score Breakdown\n{breakdown}\n\n"
                        
                    # Append to scores list for sorting
                    ioc_scores.append((entry, total_score, combined_report))
            
                    individual_combined_reports[category].append(combined_report)
    
                elif category == "hashes":
                    report_vt_hash = None
                    report_alienvault = None
                    report_malwarebazaar = None
                    
                    report_vt_hash = get_hash_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += progress_step
                    
                    report_malwarebazaar = get_malwarebazaar_hash_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += progress_step
                
                    report_alienvault = get_alienvault_report(entry, status_output, progress_bar)
                    if progress_bar:
                        progress_bar.value += progress_step

                    breakdown = []
                    verdict = "Not Malicious"
                    total_score = 0

                    # Calculate verdict and score breakdown
                    total_score, breakdown_str, verdict = calculate_total_malicious_score(
                        {
                            "VirusTotal": report_vt_hash,
                            "MalwareBazaar": report_malwarebazaar,
                            "AlienVault": report_alienvault,
                        },
                        None,  # Borealis is not used for hashes, so pass None
                        ioc_type="hash"
                    )
                    combined_report += f"Verdict: {verdict} (Score: {total_score})\n\n"

                    # VirusTotal Hash Report
                    if report_vt_hash and report_vt_hash != f"Failed to fetch VirusTotal hash report for {entry}.":
                        basic_properties = report_vt_hash.get("basic_properties", {})
                        av_vendors = report_vt_hash.get("malicious_vendors", [])
                        
                        vt_result = (
                            f"  - Hash: {sanitize_and_defang(entry)} \n"
                            f"  - File Name: {basic_properties.get('file_name', 'N/A')}\n"
                            f"  - File Type: {basic_properties.get('file_type', 'N/A')}\n"
                            f"  - File Size: {basic_properties.get('file_size', 'N/A')}\n"
                        )
                        
                        # Move signature information here, right after file size
                        # Extract the signature information
                        # Extract the signature information
                        # Extract the signature information
                        signatures = report_vt_hash.get('data', {}).get('attributes', {}).get('signature_info', {})
                        
                        # Debugging: Print the type and content of signature_info to investigate
                        print(f"DEBUG: signature_info type: {type(signatures)} - content: {signatures}")
                        
                        # Check if signature_info is a dictionary and contains the 'verified' field
                        verified = signatures.get('verified', 'Invalid')
                        sig_issuer = signatures.get('signers', 'Unknown')  # Extract the signer information
                        
                        if verified == 'Signed':
                            vt_result += f"  - Signature: Valid (Signed by: {sig_issuer})\n"
                            breakdown.append(f"Valid signature by {sig_issuer}, deemed non-malicious")
                            verdict = "Not Malicious (Valid Signature)"
                        else:
                            vt_result += "  - Signature: Invalid\n"
                    
                        # Continue with the remaining fields
                        vt_result += (
                            f"  - Malicious Detection Count: {len(av_vendors)}\n"
                            f"  - Malicious Vendors: {', '.join(av_vendors)}\n"
                            f"  - First Submission Date: {format_date(basic_properties.get('first_submission_date'))}\n"
                            f"  - Last Submission Date: {format_date(basic_properties.get('last_submission_date'))}\n"
                            f"  - Last Analysis Date: {format_date(basic_properties.get('last_analysis_date'))}\n"
                        )
                        
                        combined_report += f"VirusTotal Report:\n{vt_result}\n"
                    
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

                    # Calculate verdict and score breakdown
                    # total_score, breakdown_str, verdict = calculate_total_malicious_score(
                    #     {
                    #         "VirusTotal": report_vt_hash,
                    #         "MalwareBazaar": report_malwarebazaar,
                    #         "AlienVault": report_alienvault,
                    #     },
                    #     ioc_type="hash"
                    # )
                    # combined_report += f"Verdict: {verdict} (Score: {total_score})\n\n"
                    # combined_report += f"Score Breakdown\n{breakdown_str}\n\n"
                    combined_report += f"Score Breakdown\n{breakdown_str}\n\n"

                    # Append to scores list for sorting
                    ioc_scores.append((entry, total_score, combined_report))
                
                    individual_combined_reports[category].append(combined_report)

            print(f"Completed Processing {category.upper()}\n")

    # Sort the IOCs by total_score in descending order (higher malicious score first)
    ioc_scores.sort(key=lambda x: x[1], reverse=True)

    # Separate each report with a dotted line and prepare the final aggregated report
    aggregated_report = "\n".join([f"{'.' * 50}\nIOC: {sanitize_and_defang(ioc[0])}\n\n{ioc[2]}" for ioc in ioc_scores])

    # Check if there are multiple IOCs being processed before printing the top malicious IOCs
    if len(ioc_scores) > 1:
        # Display the top 5 malicious IOCs at the top of the report
        top_malicious_iocs = "\n".join([f"IOC: {sanitize_and_defang(ioc)[0]} (Score: {ioc[1]})" for ioc in ioc_scores[:5]])
        final_report = f"Top Malicious IOCs:\n{'='*50}\n{sanitize_and_defang(top_malicious_iocs)}\n{'='*50}\n{aggregated_report}"
    else:
        # Only one IOC is being processed, no need for top malicious section
        final_report = aggregated_report

    if output_file_path:
        with open(output_file_path, "w") as outfile:
            outfile.write(final_report)

    return final_report
