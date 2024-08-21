import requests
import json
import base64
from api.api_keys import virus_total_api_key
from IPython.display import clear_output, HTML, display

def get_ip_report(ip, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching VirusTotal IP report for {ip}...</b>'))
            display(progress_bar)
    print(f"Fetching VirusTotal IP report for {ip}.")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        report = response.json()

        # Fetch Crowdsourced context if available
        crowdsourced_context = report.get("data", {}).get("attributes", {}).get("crowdsourced_context", [])
        crowdsourced_context_plaintext = "\n".join([f"{ctx.get('title', 'N/A')}: {ctx.get('details', 'N/A')}" for ctx in crowdsourced_context]) if crowdsourced_context else "N/A"

        report["crowdsourced_context"] = crowdsourced_context_plaintext

        return report
    else:
        print(f"Failed to fetch VirusTotal IP report for {ip}. Status Code: {response.status_code}")
        return None

def submit_url_for_analysis(url, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Submitting URL {url} to VirusTotal for analysis...</b>'))
            display(progress_bar)
    print(f"Submitting URL {url} to VirusTotal for analysis.")
    
    url_endpoint = "https://www.virustotal.com/api/v3/urls"
    url_encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")  # Encode the URL in base64
    payload = f"url={url}"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key,
        "content-type": "application/x-www-form-urlencoded"
    }
    response = requests.post(url_endpoint, data=payload, headers=headers)
    
    if response.status_code == 200:
        return url_encoded  # Return the base64 encoded URL
    else:
        print(f"Failed to submit URL to VirusTotal analysis. Status Code: {response.status_code}")
        return None

def get_url_report(url_id, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching VirusTotal URL report for ID: {url_id}...</b>'))
            display(progress_bar)
    print(f"Fetching VirusTotal URL report for ID: {url_id}")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        report = response.json()

        # Fetch Crowdsourced context if available
        crowdsourced_context = report.get("data", {}).get("attributes", {}).get("crowdsourced_context", [])
        crowdsourced_context_plaintext = "\n".join([f"{ctx.get('title', 'N/A')}: {ctx.get('details', 'N/A')}" for ctx in crowdsourced_context]) if crowdsourced_context else "N/A"

        report["crowdsourced_context"] = crowdsourced_context_plaintext

        return report
    else:
        print(f"Failed to fetch VirusTotal URL report for ID: {url_id}. Status Code: {response.status_code}, Response: {response.text}")
        return None

def submit_domain_for_analysis(domain, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Submitting Domain {domain} to VirusTotal for analysis...</b>'))
            display(progress_bar)
    print(f"Submitting Domain {domain} to VirusTotal for analysis.")
    url_endpoint = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url_endpoint, headers=headers)
    if response.status_code == 200:
        return domain  # Return the domain as the ID
    else:
        print(f"Failed to submit Domain to VirusTotal analysis. Status Code: {response.status_code}")
        return None

def get_domain_report(domain, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching VirusTotal Domain report for: {domain}...</b>'))
            display(progress_bar)
    print(f"Fetching VirusTotal Domain report for: {domain}")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        report = response.json()

        # Fetch Crowdsourced context if available
        crowdsourced_context = report.get("data", {}).get("attributes", {}).get("crowdsourced_context", [])
        crowdsourced_context_plaintext = "\n".join([f"{ctx.get('title', 'N/A')}: {ctx.get('details', 'N/A')}" for ctx in crowdsourced_context]) if crowdsourced_context else "N/A"

        report["crowdsourced_context"] = crowdsourced_context_plaintext

        return report
    else:
        print(f"Failed to fetch VirusTotal Domain report for: {domain}. Status Code: {response.status_code}, Response: {response.text}")
        return None

def get_hash_report(hash_id, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching VirusTotal hash report for {hash_id}...</b>'))
            display(progress_bar)
    print(f"Fetching VirusTotal hash report for {hash_id}.")
    url = f"https://www.virustotal.com/api/v3/files/{hash_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        report = response.json()
        attributes = report.get("data", {}).get("attributes", {})

        # Extract basic properties
        basic_properties = {
            "file_name": attributes.get("meaningful_name", "N/A"),
            "file_type": attributes.get("type_description", "N/A"),
            "file_size": attributes.get("size", "N/A"),
            "last_analysis_date": attributes.get("last_analysis_date", "N/A"),
            "first_submission_date": attributes.get("first_submission_date", "N/A"),
            "last_submission_date": attributes.get("last_submission_date", "N/A"),
        }
        report["basic_properties"] = basic_properties

        # Extract malicious, suspicious, harmless vendors
        last_analysis_results = attributes.get("last_analysis_results", {})
        malicious_vendors = [
            vendor for vendor, details in last_analysis_results.items()
            if details.get("category") == "malicious"
        ]
        report["malicious_vendors"] = malicious_vendors

        # Extract Livehunt YARA rules
        livehunt_yara_rules = attributes.get("crowdsourced_yara_results", [])
        report["livehunt_yara_rules"] = [
            {
                "rule_name": yara.get("rule_name", "N/A"),
                "author": yara.get("author", "N/A"),
                "source": yara.get("source", "N/A")
            }
            for yara in livehunt_yara_rules
        ]

        # Extract Crowdsourced IDS rules
        crowdsourced_ids_rules = attributes.get("crowdsourced_ids_results", [])
        report["crowdsourced_ids_rules"] = [
            {
                "rule_msg": ids.get("rule_msg", "N/A"),
                "alert_severity": ids.get("alert_severity", "N/A"),
                "rule_source": ids.get("rule_source", "N/A"),
                "rule_url": ids.get("rule_url", "N/A")
            }
            for ids in crowdsourced_ids_rules
        ]

        # Extract Dynamic Analysis Sandbox Detections
        sandbox_verdicts = attributes.get("sandbox_verdicts", {})
        report["sandbox_verdicts"] = [
            {
                "sandbox_name": sandbox_verdicts.get(sandbox).get("sandbox_name", "N/A"),
                "verdict": sandbox_verdicts.get(sandbox).get("category", "N/A"),
                "malware_names": sandbox_verdicts.get(sandbox).get("malware_names", [])
            }
            for sandbox in sandbox_verdicts
        ]

        # NEW: Extract Signature Information
        signature_info = attributes.get("signature_info", {})
        if signature_info:
            valid = signature_info.get("valid", False)
            signer = signature_info.get("signer", "Unknown")

            # Check if signed by Microsoft
            if valid and "Microsoft" in signer:
                report["signature_info"] = {
                    "status": "Valid",
                    "signer": "Microsoft",
                    "safe": True  # Deemed safe
                }
            else:
                report["signature_info"] = {
                    "status": "Valid" if valid else "Invalid",
                    "signer": signer,
                    "safe": False  # Not deemed safe
                }
        else:
            report["signature_info"] = {
                "status": "No Signature",
                "signer": "N/A",
                "safe": False
            }

        return report
    else:
        print(f"Failed to fetch VirusTotal hash report for {hash_id}. Status Code: {response.status_code}")
        return None