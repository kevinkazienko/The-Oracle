import requests
import json
from datetime import datetime
import time
from IPython.display import clear_output, HTML, display
from api.api_keys import hybridanalysis_api_key
from file_operations.file_utils import sanitize_and_defang

# Base URL for Hybrid Analysis
HYBRID_ANALYSIS_BASE_URL = "https://www.hybrid-analysis.com/api/v2"


def parse_hybrid_analysis_report(report):
    """
    This function parses the raw Hybrid Analysis report and returns structured data to be used in the analysis function.
    """

    # Default values for cases where data is not present
    file_name = report.get("file_name", "N/A")
    file_type = report.get("type", "N/A")
    file_size = report.get("size", "N/A")
    verdict = report.get("verdict", "N/A")
    threat_score = report.get("threat_score", "N/A")

    # Extracting nested fields
    classification_tags = ', '.join(report.get("classification_tags", []))
    vx_family = report.get("vx_family", "N/A")
    mitre_attcks = report.get("mitre_attcks", [])
    total_processes = report.get("total_processes", 0)
    total_network_connections = report.get("total_network_connections", 0)
    certificates = report.get("certificates", [])

    # Extract signature info
    signature_info = report.get("signature_info", {})
    signature_status = signature_info.get("status", "N/A")
    signature_signer = signature_info.get("signer", "N/A")
    signature_valid = signature_info.get("valid", "N/A")

    # Formatting MITRE ATT&CK data
    mitre_attcks_str = '\n'.join(
        [
            f"   - Tactic: {attack.get('tactic', 'N/A')}\n"
            f"     Technique: {attack.get('technique', 'N/A')} (ID: {attack.get('attck_id', 'N/A')})\n"
            f"     ATT&CK Wiki: {attack.get('attck_id_wiki', 'N/A')}\n"
            f"     Malicious Identifiers Count: {attack.get('malicious_identifiers_count', 0)}\n"
            f"     Suspicious Identifiers Count: {attack.get('suspicious_identifiers_count', 0)}\n"
            f"     Informative Identifiers Count: {attack.get('informative_identifiers_count', 0)}\n"
            f"     Parent Technique: {attack.get('parent', {}).get('technique', 'None')} (ID: {attack.get('parent', {}).get('attck_id', 'None')})"
            for attack in mitre_attcks if isinstance(attack, dict)
        ]
    ) if mitre_attcks else 'None'

    # Formatting Certificates
    certificates_str = '\n'.join(
        [f"  - Owner: {cert['owner']}\n    Issuer: {cert['issuer']}\n    Valid From: {cert['valid_from']} to {cert['valid_until']}" 
         for cert in certificates]
    ) if certificates else 'None'

    # Returning structured data
    return {
        "file_name": file_name,
        "file_type": file_type,
        "file_size": file_size,
        "verdict": verdict,
        "threat_score": threat_score,
        "classification_tags": classification_tags,
        "vx_family": vx_family,
        "mitre_attcks_str": mitre_attcks_str,
        "total_processes": total_processes,
        "total_network_connections": total_network_connections,
        "certificates_str": certificates_str,
        "signature_status": signature_status,
        "signature_signer": signature_signer,
        "signature_valid": signature_valid
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

    # Pass the hash in the correct form-encoded format
    data = {
        "hashes[]": file_hash  # Proper encoding of hash array
    }

    response = requests.post(url, headers=headers, data=data)

    if response.status_code == 200:
        report = response.json()
        print("DEBUG: Full Hybrid Analysis JSON response:")
        print(json.dumps(report, indent=4))
        
        if report and len(report) > 0:
            report_data = report[0]  # Extract the first result
            # Extract relevant fields from the report
            file_name = report_data.get("submit_name", "N/A")
            file_type = report_data.get("type", "N/A")
            file_size = report_data.get("size", "N/A")
            threat_score = report_data.get("threat_score", "N/A")  # Check if it's populated
            verdict = report_data.get("verdict", "N/A")
            analysis_start_time = report_data.get("analysis_start_time", "N/A")
            vx_family = report_data.get("vx_family", "N/A")
            av_detect = report_data.get("av_detect", "N/A")
            threat_level = report_data.get("threat_level", "N/A")
            total_processes = report_data.get("total_processes", "N/A")
            total_network_connections = report_data.get("total_network_connections", "N/A")
            mitre_attcks = ', '.join([f"{attack.get('tactic', 'N/A')} - {attack.get('technique', 'N/A')}" 
                                      for attack in report_data.get("mitre_attcks", [])])
            
            # Return a structured report for further processing
            return parse_hybrid_analysis_report(report_data)
            
        else:
            print("No report found for the provided hash.")
            return None
    else:
        print(f"Failed to fetch Hybrid Analysis report for {file_hash}. Status Code: {response.status_code}, {response.text}")
        return None

def print_hybrid_analysis_report(entry, report_data):
    """
    Function to print the Hybrid Analysis report based on parsed data.
    """

    # Constructing the final report string
    report = (
        f"Hybrid-Analysis Report:\n"
        f"  - Hash: {sanitize_and_defang(entry)}\n"
        f"  - File Name: {report_data['file_name']}\n"
        f"  - File Type: {report_data['file_type']}\n"
        f"  - File Size: {report_data['file_size']} bytes\n"
        f"  - Verdict: {report_data['verdict']}\n"
        f"  - Threat Score: {report_data['threat_score']}\n"
        f"  - Classification Tags: {report_data['classification_tags']}\n"
        f"  - Family: {report_data['vx_family']}\n"
        f"  - Total Processes: {report_data['total_processes']}\n"
        f"  - Total Network Connections: {report_data['total_network_connections']}\n"
        f"  - MITRE ATT&CK Tactics:\n {report_data['mitre_attcks_str']}\n"
        f"  - Certificates:\n    {report_data['certificates_str']}\n\n"
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