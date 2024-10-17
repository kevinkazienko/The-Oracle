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
    if isinstance(report, list):
        # Filter the report for those containing MITRE ATT&CK data or non-empty sha256
        relevant_reports = [r for r in report if r.get('mitre_attcks') or r.get('hash')]
        
        # Use the first relevant report that has MITRE ATT&CK data, fallback to sha256
        for r in relevant_reports:
            if r.get('mitre_attcks'):
                return extract_report_data(r)
        
        # Fallback to a report with sha256 if no MITRE data found
        return extract_report_data(relevant_reports[0]) if relevant_reports else None
    
    elif isinstance(report, dict):
        # Directly parse if it's a dictionary and contains relevant fields
        if report.get('verdict') or report.get('hash'):
            return extract_report_data(report)
        else:
            return None
    else:
        raise TypeError(f"Expected dict or list, got {type(report)}")

def extract_report_data(report):
    # Debugging before extracting to ensure we capture all fields correctly
    # print(f"DEBUG: Extracting report data from: {report}")

    # Extract the filename from 'submit_name' first, then fall back to other possible keys
    file_name = report.get('submit_name') or report.get('file_name', 'N/A')

    parsed_report = {
        'hash': report.get('sha256', 'N/A'),
        'file_name': file_name,  # Use the prioritized file_name extraction
        'file_type': report.get('type', report.get('file_type', 'N/A')),  # Extracting file type correctly
        'file_size': report.get('size', report.get('file_size', 'N/A')),  # Extracting file size correctly
        'verdict': report.get('verdict', 'N/A'),
        'md5': report.get('md5', 'N/A'),
        'sha1': report.get('sha1', 'N/A'),
        'sha256': report.get('sha256', 'N/A'),
        'sha512': report.get('sha512', 'N/A'),
        'threat_score': report.get('threat_score', 'N/A'),
        'classification_tags': ''.join(report.get('classification_tags', [])) if report.get('classification_tags') else 'None',
        'vx_family': report.get('vx_family', 'N/A'),
        'total_processes': report.get('total_processes', 0),
        'total_network_connections': report.get('total_network_connections', 0),
        'mitre_attcks': report.get('mitre_attcks', []),
        'signatures': report.get('signatures', []),
        'signature_info': report.get('signature_info', 'N/A')
    }

    # Debugging after extraction to ensure the fields are parsed correctly
    # print(f"DEBUG: Parsed report data - {parsed_report}")

    return parsed_report

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
        # print("DEBUG: Full Hybrid Analysis JSON response:")
        # print(json.dumps(report, indent=4))
        
        if report:
            parsed_report = parse_hybrid_analysis_report(report)  # Single parse
            return parsed_report if parsed_report else None
        else:
            print(f"No report found for hash: {file_hash}")
            return None

def print_hybrid_analysis_report(report_data):
    # MITRE ATT&CK Tactics
    mitre_attcks = report_data.get("mitre_attcks", [])
    mitre_attcks_str = "None"
    if mitre_attcks:
        mitre_attcks_str = '\n'.join(
            [f"    - Tactic: {attack.get('tactic', 'N/A')}\n      - Technique: {attack.get('technique', 'N/A')} ({attack.get('attck_id', 'N/A')})"
             for attack in mitre_attcks]
        )

    # Signatures
    signatures = report_data.get("signatures", [])
    signatures_str = "None"
    if signatures:
        signatures_str = '\n'.join(
            [f"    - Threat Level: {signature.get('threat_level_human', 'N/A')}\n      - Name: {signature.get('name', 'N/A')}"
             for signature in signatures]
        )

    # Signature Info
    signature_info = report_data.get("signature_info", "N/A")

    # Certificates
    certificates = report_data.get("certificates", [])
    certificates_str = "None"
    if certificates:
        certificates_str = '\n'.join(
            [f"  - Owner: {cert.get('owner', 'N/A')}\n    Issuer: {cert.get('issuer', 'N/A')}\n    Valid From: {cert.get('valid_from', 'N/A')} to {cert.get('valid_until', 'N/A')}"
             for cert in certificates]
        )

    # Format the report
    report = (
        f"Hybrid-Analysis Report:\n"
        f"  - Hash: {report_data['hash']}\n"
        f"  - File Name: {report_data['file_name']}\n"
        f"  - File Type: {report_data['file_type']}\n"
        f"  - File Size: {report_data['file_size']} bytes\n"
        f"  - Verdict: {report_data['verdict']}\n"
        f"  - md5: {report_data['md5']}\n"
        f"  - sha1: {report_data['sha1']}\n"
        f"  - sha256: {report_data['sha256']}\n"
        f"  - sha512: {report_data['sha512']}\n"
        f"  - Threat Score: {report_data['threat_score']}\n"
        f"  - Classification Tags: {report_data['classification_tags']}\n"
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