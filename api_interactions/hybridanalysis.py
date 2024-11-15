import requests
import json
from datetime import datetime
import time
from IPython.display import clear_output, HTML, display
from api.api_keys import hybridanalysis_api_key

# Base URL for Hybrid Analysis
HYBRID_ANALYSIS_BASE_URL = "https://www.hybrid-analysis.com/api/v2"


def process_hybrid_analysis_report(json_response):
    # Identify the report that contains MITRE ATT&CK data
    mitre_report = next((r for r in json_response if r.get('mitre_attcks')), None)
    
    # Fallback: if no MITRE ATT&CK data found, use the longest report based on non-empty fields
    longest_report = mitre_report if mitre_report else max(json_response, key=lambda x: len([v for v in x.values() if v]))

    # Print the relevant report
    print_hybrid_analysis_report(longest_report)

def parse_hybrid_analysis_report(report):
    if isinstance(report, list) and report:  # Handle list report
        primary_report = report[0]  # Use the first report if it's a list
        return extract_report_data(primary_report)
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
    print(f"Submitting URL to Hybrid Analysis (quick-scan): {url}")
    submission_url = f"{HYBRID_ANALYSIS_BASE_URL}/quick-scan/url"
    headers = {
        "accept": "application/json",
        "api-key": hybridanalysis_api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    data = {"url": url, "scan_type": "all"}
    response = requests.post(submission_url, headers=headers, data=data)

    if response.status_code == 200:
        try:
            response_json = response.json()
            #print(f"DEBUG: Received quick-scan report response: {json.dumps(response_json, indent=2)}")
            # Check if the response contains the report directly
            if "id" in response_json or "submission_type" in response_json:
                print("Quick-scan returned a completed report directly.")
                return response_json  # Return the completed report directly
            else:
                print("Error: Expected report fields not found in the response.")
                return None
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON response: {e}")
            return None
    else:
        print(f"Failed to submit URL to Hybrid Analysis. Status Code: {response.status_code}")
        return None



def parse_hybrid_analysis_url_report(report):
    if not isinstance(report, dict):
        print(f"Error: Expected report to be a dict, got {type(report)}")
        return "Hybrid-Analysis Report:\nNo data available or analysis failed.\n\n"

    # Extract general information
    report_id = report.get("id", "N/A")
    submission_type = report.get("submission_type", "N/A")
    sha256 = report.get("sha256", "N/A")
    finished = report.get("finished", False)

    # Parse the "scanners" section
    scanners_info = []
    for scanner in report.get("scanners", []):
        scanner_info = {
            "name": scanner.get("name", "N/A"),
            "status": scanner.get("status", "N/A"),
            "progress": scanner.get("progress", "N/A"),
            "positives": scanner.get("positives", "N/A"),
            "percent": scanner.get("percent", "N/A")
        }
        scanners_info.append(scanner_info)

    # Parse the "scanners_v2" section
    scanners_v2_info = []
    for scanner_key, scanner in report.get("scanners_v2", {}).items():
        if scanner:  # Ensure the scanner data is not None
            scanner_info = {
                "name": scanner.get("name", "N/A"),
                "status": scanner.get("status", "N/A"),
                "progress": scanner.get("progress", "N/A"),
                "percent": scanner.get("percent", "N/A"),
                "error_message": scanner.get("error_message", None)
            }
            scanners_v2_info.append(scanner_info)

    # Format the report output for readability
    report_output = (
        f"Hybrid-Analysis Report:\n"
        f"  - Report ID: {report_id}\n"
        f"  - Submission Type: {submission_type}\n"
        f"  - SHA256: {sha256}\n"
        f"  - Finished: {'Yes' if finished else 'No'}\n"
        f"  - Scanners:\n"
    )

    # Add formatted information from "scanners"
    for scanner_info in scanners_info:
        report_output += (
            f"    - {scanner_info['name']}:\n"
            f"        - Status: {scanner_info['status']}\n"
            f"        - Progress: {scanner_info['progress']}%\n"
            f"        - Positives: {scanner_info['positives']}\n"
            f"        - Percent: {scanner_info['percent']}%\n"
        )

    # Add formatted information from "scanners_v2"
    report_output += "  - Scanners v2:\n"
    for scanner_info in scanners_v2_info:
        report_output += (
            f"    - {scanner_info['name']}:\n"
            f"        - Status: {scanner_info['status']}\n"
            f"        - Progress: {scanner_info['progress']}%\n"
            f"        - Percent: {scanner_info['percent']}%\n"
            f"        - Error Message: {scanner_info['error_message']}\n"
        )

    return report_output