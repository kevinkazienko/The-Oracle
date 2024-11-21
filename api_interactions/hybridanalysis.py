import requests
import json
import re
from datetime import datetime
import time
from urllib.parse import urlencode
from IPython.display import clear_output, HTML, display
from api.api_keys import hybridanalysis_api_key
from file_operations.file_utils import is_ip, is_domain, is_hash, is_url

# Base URL for Hybrid Analysis
HYBRID_ANALYSIS_BASE_URL = "https://www.hybrid-analysis.com/api/v2"

def detect_ioc_type(ioc):
    """
    Detects the type of IOC (Indicator of Compromise) provided.
    """
    if is_ip(ioc):
        return "ip"
    elif is_url(ioc):
        return "url"
    elif is_hash(ioc):
        return "hash"
    elif is_domain(ioc):
        return "domain"
    else:
        return "unknown"


def handle_hybrid_analysis_ioc(ioc, status_output=None, progress_bar=None):
    """
    Handles IOC analysis using the appropriate Hybrid Analysis API endpoint.
    """
    ioc_type = detect_ioc_type(ioc)

    if ioc_type == "url":
        print(f"Detected URL. Submitting {ioc} for quick-scan.")
        return analyze_url_with_hybrid_analysis(ioc, ioc_type, status_output, progress_bar)

    elif ioc_type in ["ip", "domain"]:
        print(f"Detected {ioc_type}. Searching {ioc} using the /search/terms endpoint.")
        return search_hybrid_analysis_by_term(ioc, ioc_type, status_output, progress_bar)

    elif ioc_type == "hash":
        print(f"Detected hash. Fetching report for {ioc}.")
        return get_hybrid_analysis_hash_report(ioc, status_output, progress_bar)

    else:
        print(f"Unknown IOC type for {ioc}. Unable to process.")
        return None


def search_hybrid_analysis_by_term(search_term, ioc_type, status_output=None, progress_bar=None):
    """
    Searches the Hybrid Analysis API for a given term (e.g., IP address, domain, file hash).
    """
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Searching Hybrid Analysis for {search_term}...</b>'))
            display(progress_bar)

    print(f"Searching Hybrid Analysis for term: {search_term} (Type: {ioc_type})")
    search_url = f"{HYBRID_ANALYSIS_BASE_URL}/search/terms"
    headers = {
        "accept": "application/json",
        "api-key": hybridanalysis_api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    # Determine the correct search term key and format the data
    search_key = "host" if ioc_type == "ip" else "domain"
    data = f"{search_key}={search_term}"  # Format the data as a URL-encoded string

    print(f"DEBUG: Request Data: {data}")
    
    response = requests.post(search_url, headers=headers, data=data)

    try:
        response_json = response.json()  # Attempt to parse JSON from response
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse JSON response: {e}")
        print(f"Response Text: {response.text}")  # Debugging
        return None

    if response.status_code == 200:
        print(f"Search completed successfully for term: {search_term}")
        #print(f"DEBUG: Raw JSON Response: {response.json()}")
        return response_json
    else:
        print(f"Search failed for term: {search_term}. HTTP {response.status_code}: {response.text}")
        return None

def parse_hybrid_analysis_ip_response(response_json, debug=False):
    """
    Parses the Hybrid Analysis response for IPs and extracts relevant details into plaintext.
    """
    if not isinstance(response_json, dict):
        raise ValueError(f"Expected dictionary with 'result' key, got {type(response_json)}")

    results = response_json.get("result", [])
    if debug:
        print(f"DEBUG: Number of results found: {len(results)}")

    report_lines = []
    for idx, result in enumerate(results, start=1):
        report_lines.append(f"   - Result {idx}:")
        report_lines.append(f"    - Verdict: {result.get('verdict', 'N/A')}")
        report_lines.append(f"    - AV Detect: {result.get('av_detect', 'N/A')}")
        report_lines.append(f"    - Threat Score: {result.get('threat_score', 'N/A')}")
        report_lines.append(f"    - VX Family: {result.get('vx_family', 'N/A')}")
        report_lines.append(f"    - SHA256: {result.get('sha256', 'N/A')}")
        report_lines.append(f"    - Job ID: {result.get('job_id', 'N/A')}")
        report_lines.append(f"    - Submit Name: {result.get('submit_name', 'N/A')}")
        report_lines.append(f"    - Environment: {result.get('environment_description', 'N/A')}")
        report_lines.append(f"    - Analysis Start Time: {result.get('analysis_start_time', 'N/A')}")
        report_lines.append(f"    - Size: {result.get('size', 'N/A')} bytes")
        report_lines.append(f"    - Type: {result.get('type_short', 'N/A')}")
        #report_lines.append("")  # Blank line for readability

    parsed_report = "\n".join(report_lines)
    if debug:
        print(f"DEBUG: Parsed Report for IP:\n{parsed_report}")
    return parsed_report


def generate_hybrid_analysis_domain_report(response_json):
    """
    Generate a structured report based on the Hybrid-Analysis API JSON response for domain searches.
    """
    report = []

    if not response_json or "result" not in response_json:
        report.append("No data available for the domain.")
        return "\n".join(report)

    results = response_json.get("result", [])
    if not results:
        report.append("No results found for the domain.")
        return "\n".join(report)

    # report.append("Hybrid-Analysis Domain Report:")
    # report.append("=" * 50)

    for idx, result in enumerate(results, start=1):
        report.append(f"  - Entry {idx}:")
        report.append(f"   - Verdict: {result.get('verdict', 'N/A')}")
        report.append(f"   - AV Detect: {result.get('av_detect', 'N/A')}")
        report.append(f"  - Threat Score: {result.get('threat_score', 'N/A')}")
        report.append(f"  - VX Family: {result.get('vx_family', 'N/A')}")
        report.append(f"  - Job ID: {result.get('job_id', 'N/A')}")
        report.append(f"  - SHA256: {result.get('sha256', 'N/A')}")
        report.append(f"  - Environment ID: {result.get('environment_id', 'N/A')}")
        report.append(f"  - Analysis Start Time: {result.get('analysis_start_time', 'N/A')}")
        report.append(f"  - Submit Name: {result.get('submit_name', 'N/A')}")
        report.append(f"  - Environment Description: {result.get('environment_description', 'N/A')}")
        report.append(f"  - Size: {result.get('size', 'N/A')}")
        report.append(f"  - Type: {result.get('type', 'N/A')}")
        report.append(f"  - Type Short: {result.get('type_short', 'N/A')}")
        # report.append("-" * 50)

    return "\n".join(report)


def process_hybrid_analysis_report(json_response):
    # Identify the report that contains MITRE ATT&CK data
    mitre_report = next((r for r in json_response if r.get('mitre_attcks')), None)
    
    # Fallback: if no MITRE ATT&CK data found, use the longest report based on non-empty fields
    longest_report = mitre_report if mitre_report else max(json_response, key=lambda x: len([v for v in x.values() if v]))

    # Print the relevant report
    print_hybrid_analysis_report(longest_report)

def parse_hybrid_analysis_report(report):
    if isinstance(report, list) and report:  # Handle non-empty list
        primary_report = report[0]  # Use the first report if it's a list
        return extract_report_data(primary_report)
    elif isinstance(report, list) and not report:  # Handle empty list
        return None  # Return None or a suitable default value
    elif isinstance(report, dict):  # Handle single dict report
        return extract_report_data(report)
    else:
        raise ValueError(f"Unexpected report format: {type(report)}")

def extract_report_data(report):
    if not isinstance(report, dict):  # Ensure the report is a dictionary
        raise ValueError(f"Invalid report format: Expected dict, got {type(report)}")

    # Extract fields
    file_type = report.get('type', 'N/A')  # Only assign 'N/A' if the key is completely missing
    file_size = report.get('size', 'N/A') if isinstance(report.get('size'), (int, float)) else 'N/A'
    classification_tags = ', '.join(report.get('classification_tags', [])) if isinstance(report.get('classification_tags'), list) else 'N/A'

    # Debugging: Verify extracted values
    #print(f"DEBUG: Extracted values - file_type: {file_type}, file_size: {file_size}, classification_tags: {classification_tags}")

    return {
        'hash': report.get('sha256', 'N/A'),
        'file_name': report.get('submit_name', report.get('file_name', 'N/A')),
        'file_type': file_type,
        'file_size': file_size,
        'verdict': report.get('verdict', 'N/A'),
        'md5': report.get('md5', 'N/A'),
        'sha1': report.get('sha1', 'N/A'),
        'sha256': report.get('sha256', 'N/A'),
        'sha512': report.get('sha512', 'N/A'),
        'threat_score': report.get('threat_score', 'N/A'),
        'classification_tags': classification_tags,
        'vx_family': report.get('vx_family', 'N/A'),
        'total_network_connections': report.get('total_network_connections', 0),
        'total_processes': report.get('total_processes', 0),
        'mitre_attcks': report.get('mitre_attcks', []),
        'signatures': report.get('signatures', []),
        'signature_info': report.get('signature_info', 'N/A')
    }

# Function to check if the analysis date is older than 14 days
def needs_hybridrescan(last_analysis_date):
    if last_analysis_date is None:
        return True
    last_analysis_datetime = datetime.strptime(last_analysis_date, '%Y-%m-%d')
    return (datetime.utcnow() - last_analysis_datetime).days > 14

# Function to get hash report with real-time status and progress
def get_hybrid_analysis_hash_report(file_hash, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching Hybrid Analysis report for {file_hash}...</b>'))
            display(progress_bar)

    print(f"Fetching Hybrid Analysis report for {file_hash}.")
    url = f"{HYBRID_ANALYSIS_BASE_URL}/search/hashes"
    headers = {
        "accept": "application/json",
        "api-key": hybridanalysis_api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "hashes[]": file_hash  # Proper encoding of hash array
    }

    response = requests.post(url, headers=headers, data=data)

    if response.status_code == 200:
        report = response.json()
        #print(f"DEBUG: Raw API response type: {type(report)}")

        # Pass raw response to the parser
        return report
    else:
        print(f"Failed to fetch report. Status Code: {response.status_code}")
        return None

def print_hybrid_analysis_report(report_data):
    # Debug: Ensure data is consistent before formatting
    #print("DEBUG: Printing report data:", report_data)

    file_type = report_data.get('file_type', 'N/A')
    file_size = report_data.get('file_size', 'N/A')
    classification_tags = report_data.get('classification_tags', 'N/A')

    #print(f"DEBUG: Fields - file_type: {file_type}, file_size: {file_size}, classification_tags: {classification_tags}")

    # MITRE ATT&CK Tactics
    mitre_attcks = report_data.get("mitre_attcks", [])
    mitre_attcks_str = "None" if not mitre_attcks else '\n'.join(
        [f"    - Tactic: {attack.get('tactic', 'N/A')}\n      - Technique: {attack.get('technique', 'N/A')} ({attack.get('attck_id', 'N/A')})"
         for attack in mitre_attcks]
    )

    # Signatures
    signatures = report_data.get("signatures", [])
    signatures_str = "None" if not signatures else '\n'.join(
        [f"    - Threat Level: {signature.get('threat_level_human', 'N/A')}\n      - Name: {signature.get('name', 'N/A')}"
         for signature in signatures]
    )

    # Signature Info
    signature_info = report_data.get("signature_info", "N/A")

    # Certificates
    certificates = report_data.get("certificates", [])
    certificates_str = "None" if not certificates else '\n'.join(
        [f"  - Owner: {cert.get('owner', 'N/A')}\n    Issuer: {cert.get('issuer', 'N/A')}\n    Valid From: {cert.get('valid_from', 'N/A')} to {cert.get('valid_until', 'N/A')}"
         for cert in certificates]
    )

    # Format the report
    report = (
        f"Hybrid-Analysis Report:\n"
        f"  - Hash: {report_data['hash']}\n"
        f"  - File Name: {report_data['file_name']}\n"
        f"  - File Type: {file_type}\n"
        f"  - File Size: {file_size} bytes\n"
        f"  - Verdict: {report_data['verdict']}\n"
        f"  - md5: {report_data['md5']}\n"
        f"  - sha1: {report_data['sha1']}\n"
        f"  - sha256: {report_data['sha256']}\n"
        f"  - sha512: {report_data['sha512']}\n"
        f"  - Threat Score: {report_data['threat_score']}\n"
        f"  - Classification Tags: {classification_tags}\n"
        f"  - Family: {report_data['vx_family']}\n"
        f"  - Total Processes: {report_data['total_processes']}\n"
        f"  - Total Network Connections: {report_data['total_network_connections']}\n"
        f"  - MITRE ATT&CK Tactics:\n{mitre_attcks_str}\n"
        f"  - Signature Info:\n    - Status: {signature_info}\n"
        f"  - Signatures:\n{signatures_str}\n"
        f"  - Certificates:\n    {certificates_str}\n\n"
    )

    return report

# Function to submit hash for rescan with real-time status and progress
def submit_hybridhash_for_rescan(file_hash, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Submitting {file_hash} for rescan...</b>'))
            display(progress_bar)

    print(f"Submitting {file_hash} for rescan.")
    url = f"{HYBRID_ANALYSIS_BASE_URL}/submit/rescan"
    headers = {
        "accept": "application/json",
        "api-key": hybridanalysis_api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {"hash": file_hash}

    response = requests.post(url, headers=headers, data=data)

    if response.status_code == 200:
        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f'<b>{file_hash} rescan submitted successfully.</b>'))
                display(progress_bar)
        print(f"{file_hash} submitted for rescan.")
        return response.json()
    else:
        print(f"Failed to submit {file_hash} for rescan. Status Code: {response.status_code}")
        return None


def submit_url_to_hybrid_analysis(url, status_output=None, progress_bar=None):
    """
    Submits a URL for quick-scan analysis to Hybrid Analysis.
    """
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Submitting {url} for quick-scan...</b>'))
            display(progress_bar)

    print(f"Submitting {url} for quick-scan.")
    quick_scan_url = f"{HYBRID_ANALYSIS_BASE_URL}/quick-scan/url"
    headers = {
        "accept": "application/json",
        "api-key": hybridanalysis_api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "url": url,
        "scan_type": "all"  # Specify the scan type
    }
    
    response = requests.post(quick_scan_url, headers=headers, data=data)

    if response.status_code == 200:  # Quick-scan submission successful
        response_json = response.json()
        scan_id = response_json.get("id")
        finished = response_json.get("finished", False)
        print(f"Quick-scan submitted successfully. Scan ID: {scan_id}, Finished: {finished}")
        return scan_id, finished
    else:
        print(f"Failed to submit quick-scan. HTTP {response.status_code}: {response.text}")
        return None, None


def fetch_hybrid_analysis_report(submission_id, status_output=None, progress_bar=None, timeout=600, poll_interval=15):
    """
    Polls the /quick-scan/{id} endpoint or fetches the final quick-scan results immediately if completed.
    """
    if not submission_id:
        print("Invalid submission ID. Cannot fetch results.")
        return None

    elapsed_time = 0
    while elapsed_time < timeout:
        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f'<b>Checking results for Submission ID: {submission_id}...</b>'))
                display(progress_bar)

        print(f"Fetching results for Submission ID: {submission_id}...")
        results_url = f"{HYBRID_ANALYSIS_BASE_URL}/quick-scan/{submission_id}"
        headers = {
            "accept": "application/json",
            "api-key": hybridanalysis_api_key
        }
        response = requests.get(results_url, headers=headers)

        if response.status_code == 200:
            results_json = response.json()
            finished = results_json.get("finished", False)
            if finished:
                print("Quick-scan analysis completed successfully.")
                return results_json  # Return the final report immediately
            else:
                print("Quick-scan analysis still in progress.")
        else:
            print(f"Failed to fetch quick-scan results. HTTP {response.status_code}: {response.text}")
            return None

        time.sleep(poll_interval)
        elapsed_time += poll_interval

    print("Timeout reached while waiting for quick-scan analysis to complete.")
    return None



def parse_hybrid_analysis_url_report(report):
    """
    Parses the Hybrid-Analysis URL report and formats it for readability.
    """
    if not isinstance(report, dict):
        print(f"Error: Expected report to be a dict, got {type(report)}")
        return "Hybrid-Analysis Report:\nNo data available or analysis failed.\n\n"

    # Extract general information
    report_id = report.get("id", "N/A")
    sha256 = report.get("sha256", "N/A")
    finished = report.get("finished", False)
    whitelist = report.get("whitelist", [])
    detailed_reports = report.get("reports", [])

    # Parse the "scanners" section
    scanners_info = []
    for scanner in report.get("scanners", []):
        scanner_info = {
            "name": scanner.get("name", "N/A"),
            "status": scanner.get("status", "N/A"),
            "progress": f"{scanner.get('progress', 'N/A')}%",
            "positives": scanner.get("positives", "N/A"),
            "percent": f"{scanner.get('percent', 'N/A')}%"
        }
        scanners_info.append(scanner_info)

    # Parse the "scanners_v2" section
    scanners_v2_info = []
    for scanner_key, scanner in report.get("scanners_v2", {}).items():
        if scanner:  # Ensure the scanner data is not None
            scanner_info = {
                "name": scanner.get("name", scanner_key),
                "status": scanner.get("status", "N/A"),
                "progress": f"{scanner.get('progress', 'N/A')}%",
                "percent": f"{scanner.get('percent', 'N/A')}%",
                "error_message": scanner.get("error_message", "None")
            }
            scanners_v2_info.append(scanner_info)

    # Format the report output for readability
    report_output = (
        # f"Hybrid-Analysis Report:\n"
        f"  - Report ID: {report_id}\n"
        f"  - SHA256: {sha256}\n"
        f"  - Finished: {'Yes' if finished else 'No'}\n"
        f"  - Scanners:\n"
    )

    # Add formatted information from "scanners"
    for scanner_info in scanners_info:
        report_output += (
            f"    - {scanner_info['name']}:\n"
            f"        - Status: {scanner_info['status']}\n"
            f"        - Progress: {scanner_info['progress']}\n"
            f"        - Positives: {scanner_info['positives']}\n"
            f"        - Percent: {scanner_info['percent']}\n"
        )

    # Add formatted information from "scanners_v2"
    report_output += "  - Scanners v2:\n"
    for scanner_info in scanners_v2_info:
        report_output += (
            f"    - {scanner_info['name']}:\n"
            f"        - Status: {scanner_info['status']}\n"
            f"        - Progress: {scanner_info['progress']}\n"
            f"        - Percent: {scanner_info['percent']}\n"
            f"        - Error Message: {scanner_info['error_message']}\n"
        )

    # Add whitelist information
    if whitelist:
        report_output += "  - Whitelist:\n"
        for item in whitelist:
            report_output += f"    - {item}\n"
    else:
        report_output += "  - Whitelist: None\n"

    # Add detailed reports information
    if detailed_reports:
        report_output += "  - Detailed Reports:\n"
        for detailed_report in detailed_reports:
            report_output += f"    - {json.dumps(detailed_report, indent=4)}\n"
    else:
        report_output += "  - Detailed Reports: None\n"

    return report_output


def analyze_url_with_hybrid_analysis(url, status_output=None, progress_bar=None):
    """
    Submits a URL for quick-scan analysis, waits for completion if necessary, and fetches the final results.
    """
    submission_id, finished = submit_url_to_hybrid_analysis(url, status_output, progress_bar)
    if not submission_id:
        print("Submission failed. No submission ID returned.")
        return None

    if finished:
        print("Quick-scan analysis is already completed. Fetching results...")
        report = fetch_hybrid_analysis_report(submission_id, status_output=status_output, progress_bar=progress_bar, timeout=0, poll_interval=0)
        return report

    # If not finished, poll for completion
    print("Quick-scan analysis is in progress. Polling for results...")
    report = fetch_hybrid_analysis_report(submission_id, status_output=status_output, progress_bar=progress_bar)
    if report:
        return report
    else:
        print("Failed to fetch the quick-scan report.")
        return None