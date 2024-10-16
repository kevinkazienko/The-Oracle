import requests
import json
import base64
from datetime import datetime, timedelta, timezone
import time
from api.api_keys import virus_total_api_key
from IPython.display import clear_output, HTML, display

# Helper function to check if the analysis date is older than 14 days
def needs_rescan(last_analysis_epoch):
    """
    Check if the last analysis date is older than 14 days.
    :param last_analysis_epoch: The last analysis date in Unix timestamp format.
    :return: True if the last analysis is older than 14 days, False otherwise.
    """
    if last_analysis_epoch is None:
        return True  # If no analysis has been done, we need a rescan
    
    # Convert the last analysis time from epoch to a datetime object (UTC)
    last_analysis_date = datetime.utcfromtimestamp(last_analysis_epoch)
    
    # Get the current UTC time
    current_date = datetime.utcnow()

    # Compare to see if the last analysis is more than 14 days old
    return (current_date - last_analysis_date) > timedelta(days=14)

def get_ip_report(ip, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching VirusTotal report for {ip}...</b>'))
            display(progress_bar)
    print(f"Fetching VirusTotal report for {ip}.")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        report = response.json()


        # Debug: Print full raw JSON response for troubleshooting
        # print("Raw JSON response from VirusTotal:", json.dumps(report, indent=4))

        attributes = report.get("data", {}).get("attributes", {})
        
        # Convert last_analysis_date from epoch to readable date
        last_analysis_epoch = attributes.get("last_analysis_date", None)
        last_analysis_date = datetime.utcfromtimestamp(last_analysis_epoch).strftime('%Y-%m-%d %H:%M:%S') if last_analysis_epoch else "N/A"

        # Check if the last analysis is older than 14 days, and submit for rescan if needed
        if needs_rescan(last_analysis_epoch):
            print(f"Analysis for {ip} is older than 14 days. Submitting for rescan.")
            submit_ip_for_rescan(ip, status_output, progress_bar)
            # Fetch the updated report after rescan
            time.sleep(30)  # Allow time for the rescan to complete
            response = requests.get(url, headers=headers)  # Fetch the updated report

        report["last_analysis_date"] = last_analysis_date
        
        # Convert first_submission_date from epoch to readable date
        first_submission_epoch = attributes.get("first_submission_date", None)
        first_submission_date = datetime.utcfromtimestamp(first_submission_epoch).strftime('%Y-%m-%d %H:%M:%S') if first_submission_epoch else "N/A"
        
        # Add to report
        report["last_analysis_date"] = last_analysis_date
        report["first_submission_date"] = first_submission_date

        # Fetch Crowdsourced context if available
        crowdsourced_context = report.get("data", {}).get("attributes", {}).get("crowdsourced_context", [])
        crowdsourced_context_plaintext = "\n".join([f"{ctx.get('title', 'N/A')}: {ctx.get('details', 'N/A')}" for ctx in crowdsourced_context]) if crowdsourced_context else "N/A"

        report["crowdsourced_context"] = crowdsourced_context_plaintext

        return report
    else:
        print(f"Failed to fetch VirusTotal report for {ip}. Status Code: {response.status_code}")
        return None

def submit_ip_for_rescan(ip, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Submitting {ip} for rescan...</b>'))
            display(progress_bar)
    print(f"Submitting {ip} for rescan.")
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/analyse"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.post(url, headers=headers)
    
    if response.status_code == 200:
        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f'<b>{ip} rescan submitted successfully.</b>'))
                display(progress_bar)
        print(f"{ip} submitted for rescan.")
        return response.json()
    else:
        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f'<b>Failed to submit{ip} for rescan. Status Code: {response.status_code}</b>'))
                display(progress_bar)
        print(f"Failed to submit {ip} for rescan. Status Code: {response.status_code}")
        return None

def submit_url_for_analysis(url, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Submitting {url} to VirusTotal for analysis...</b>'))
            display(progress_bar)
    print(f"Submitting {url} to VirusTotal for analysis.")
    
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
        print(f"Failed to submit to VirusTotal analysis. Status Code: {response.status_code}")
        return None

def get_url_report(url_id, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching VirusTotal report for ID: {url_id}...</b>'))
            display(progress_bar)
    print(f"Fetching VirusTotal report for ID: {url_id}")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        report = response.json()

        # Extract attributes from the report
        attributes = report.get("data", {}).get("attributes", {})
        
        # Convert last_analysis_date from epoch to readable date
        last_analysis_epoch = attributes.get("last_analysis_date", None)
        last_analysis_date = datetime.utcfromtimestamp(last_analysis_epoch).strftime('%Y-%m-%d %H:%M:%S') if last_analysis_epoch else "N/A"

        # Check if a rescan is needed
        if needs_rescan(last_analysis_epoch):
            print(f"Analysis for {url_id} is older than 14 days. Submitting for rescan.")
            submit_url_for_rescan(url_id, status_output, progress_bar)
            # Fetch the updated report after rescan
            time.sleep(30)  # Allow some time for the rescan to complete
            response = requests.get(url, headers=headers)  # Fetch the updated report
            report = response.json()

        report["last_analysis_date"] = last_analysis_date
        
        # Extract first_submission_date
        first_submission_epoch = attributes.get("first_submission_date", None)
        first_submission_date = datetime.utcfromtimestamp(first_submission_epoch).strftime('%Y-%m-%d %H:%M:%S') if first_submission_epoch else "N/A"
        report["first_submission_date"] = first_submission_date

        # Fetch Crowdsourced context if available
        crowdsourced_context = attributes.get("crowdsourced_context", [])
        crowdsourced_context_plaintext = "\n".join([f"{ctx.get('title', 'N/A')}: {ctx.get('details', 'N/A')}" for ctx in crowdsourced_context]) if crowdsourced_context else "N/A"
        report["crowdsourced_context"] = crowdsourced_context_plaintext

        # Extract last downloaded file (if available)
        last_downloaded_file_hash = attributes.get("last_http_response_content_sha256", None)
        if last_downloaded_file_hash:
            print(f"Last downloaded file SHA256: {last_downloaded_file_hash}")
            # Fetch the downloaded file details using the file's hash
            file_report = get_hash_report(last_downloaded_file_hash, status_output, progress_bar)
            report["last_downloaded_file"] = file_report
        else:
            print("No last downloaded file found.")
            report["last_downloaded_file"] = "No last downloaded file available."

        return report
    else:
        print(f"Failed to fetch VirusTotal report for ID: {url_id}. Status Code: {response.status_code}, Response: {response.text}")
        return None


def submit_url_for_rescan(url_id, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Submitting ID {url_id} for rescan...</b>'))
            display(progress_bar)
    print(f"Submitting ID {url_id} for rescan.")
    
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}/analyse"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.post(url, headers=headers)
    
    if response.status_code == 200:
        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f'<b>ID {url_id} rescan submitted successfully.</b>'))
                display(progress_bar)
        print(f"ID {url_id} submitted for rescan.")
        return response.json()
    else:
        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f'<b>Failed to submit ID {url_id} for rescan. Status Code: {response.status_code}</b>'))
                display(progress_bar)
        print(f"Failed to submit ID {url_id} for rescan. Status Code: {response.status_code}")
        return None

def submit_domain_for_analysis(domain, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Submitting {domain} to VirusTotal for analysis...</b>'))
            display(progress_bar)
    print(f"Submitting {domain} to VirusTotal for analysis.")
    url_endpoint = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url_endpoint, headers=headers)
    if response.status_code == 200:
        return domain  # Return the domain as the ID
    else:
        print(f"Failed to submit to VirusTotal analysis. Status Code: {response.status_code}")
        return None

def submit_domain_for_rescan(domain, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Submitting {domain} for rescan...</b>'))
            display(progress_bar)
    print(f"Submitting {domain} for rescan.")
    
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/analyse"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.post(url, headers=headers)
    
    if response.status_code == 200:
        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f'<b>{domain} rescan submitted successfully.</b>'))
                display(progress_bar)
        print(f"{domain} submitted for rescan.")
        return response.json()
    else:
        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f'<b>Failed to submit {domain} for rescan. Status Code: {response.status_code}</b>'))
                display(progress_bar)
        print(f"Failed to submit {domain} for rescan. Status Code: {response.status_code}")
        return None

def get_domain_report(domain, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching VirusTotal report for: {domain}...</b>'))
            display(progress_bar)
    print(f"Fetching VirusTotal report for: {domain}")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        report = response.json()


        # Debug: Print full raw JSON response for troubleshooting
        # print("Raw JSON response from VirusTotal:", json.dumps(report, indent=4))

        attributes = report.get("data", {}).get("attributes", {})
        
        # Convert last_analysis_date from epoch to readable date
        last_analysis_epoch = attributes.get("last_analysis_date", None)
        last_analysis_date = datetime.utcfromtimestamp(last_analysis_epoch).strftime('%Y-%m-%d %H:%M:%S') if last_analysis_epoch else "N/A"

        # Check if the last analysis is older than 14 days, and submit for rescan if needed
        if needs_rescan(last_analysis_epoch):
            print(f"Analysis for {domain} is older than 14 days. Submitting for rescan.")
            submit_domain_for_rescan(domain, status_output, progress_bar)
            # Fetch the updated report after rescan
            time.sleep(30)  # Allow time for the rescan to complete
            response = requests.get(url, headers=headers)  # Fetch the updated report

        report["last_analysis_date"] = last_analysis_date
        
        # Convert first_submission_date from epoch to readable date
        first_submission_epoch = attributes.get("first_submission_date", None)
        first_submission_date = datetime.utcfromtimestamp(first_submission_epoch).strftime('%Y-%m-%d %H:%M:%S') if first_submission_epoch else "N/A"
        
        # Add to report
        report["last_analysis_date"] = last_analysis_date
        report["first_submission_date"] = first_submission_date


        # Fetch Crowdsourced context if available
        crowdsourced_context = report.get("data", {}).get("attributes", {}).get("crowdsourced_context", [])
        crowdsourced_context_plaintext = "\n".join([f"{ctx.get('title', 'N/A')}: {ctx.get('details', 'N/A')}" for ctx in crowdsourced_context]) if crowdsourced_context else "N/A"

        report["crowdsourced_context"] = crowdsourced_context_plaintext

        return report
    else:
        print(f"Failed to fetch VirusTotal report for: {domain}. Status Code: {response.status_code}, Response: {response.text}")
        return None

def get_hash_report(hash_id, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching VirusTotal report for {hash_id}...</b>'))
            display(progress_bar)
    print(f"Fetching VirusTotal report for {hash_id}.")
    url = f"https://www.virustotal.com/api/v3/files/{hash_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        report = response.json()
        # Debug: Print full raw JSON response for troubleshooting
        #print("Raw JSON response from VirusTotal:", json.dumps(report, indent=4))

        attributes = report.get("data", {}).get("attributes", {})
        
        # Convert last_analysis_date from epoch to readable date
        last_analysis_epoch = attributes.get("last_analysis_date", None)
        last_analysis_date = datetime.utcfromtimestamp(last_analysis_epoch).strftime('%Y-%m-%d %H:%M:%S') if last_analysis_epoch else "N/A"

        # If the analysis is older than 14 days, submit for rescan
        if needs_rescan(last_analysis_epoch):
            print(f"Analysis for {hash_id} is older than 14 days. Submitting for rescan.")
            submit_hash_for_rescan(hash_id, status_output, progress_bar)
            # Fetch the updated report after rescan
            time.sleep(30)  # Allow some time for the rescan to complete
            response = requests.get(url, headers=headers)  # Fetch the updated report

        report["last_analysis_date"] = last_analysis_date
        
        # Convert first_submission_date from epoch to readable date
        first_submission_epoch = attributes.get("first_submission_date", None)
        first_submission_date = datetime.utcfromtimestamp(first_submission_epoch).strftime('%Y-%m-%d %H:%M:%S') if first_submission_epoch else "N/A"
        
        # Add to report
        report["last_analysis_date"] = last_analysis_date
        report["first_submission_date"] = first_submission_date

        # Basic properties
        basic_properties = {
            "file_name": attributes.get("meaningful_name", "N/A"),
            "file_type": attributes.get("type_description", "N/A"),
            "file_size": attributes.get("size", "N/A"),
            "last_analysis_date": last_analysis_date,
            "first_submission_date": datetime.utcfromtimestamp(attributes.get("first_submission_date", 0)).strftime('%Y-%m-%d %H:%M:%S') if attributes.get("first_submission_date") else "N/A",
            "last_submission_date": datetime.utcfromtimestamp(attributes.get("last_submission_date", 0)).strftime('%Y-%m-%d %H:%M:%S') if attributes.get("last_submission_date") else "N/A",
        }
        report["basic_properties"] = basic_properties

        # Malicious vendors
        last_analysis_results = attributes.get("last_analysis_results", {})
        malicious_vendors = [
            vendor for vendor, details in last_analysis_results.items()
            if details.get("category") == "malicious"
        ]
        report["malicious_vendors"] = malicious_vendors

        # Crowdsourced and Livehunt YARA rules
        crowdsourced_yara_rules = attributes.get("crowdsourced_yara_results", [])
        report["crowdsourced_yara_rules"] = [
            {
                "rule_name": yara.get("rule_name", "N/A"),
                "author": yara.get("author", "N/A"),
                "source": yara.get("source", "N/A")
            }
            for yara in crowdsourced_yara_rules
        ]

        # Sigma Rules
        sigma_rules = attributes.get("crowdsourced_sigma_results", [])
        report["crowdsourced_sigma_rules"] = [
            {
                "rule_name": sigma.get("rule_name", "N/A"),
                "author": sigma.get("author", "N/A"),
                "source": sigma.get("source", "N/A")
            }
            for sigma in sigma_rules
        ]

        # Dynamic Analysis Sandbox Detections
        sandbox_verdicts = attributes.get("sandbox_verdicts", {})
        report["sandbox_verdicts"] = [
            {
                "sandbox_name": sandbox_verdicts.get(sandbox).get("sandbox_name", "N/A"),
                "verdict": sandbox_verdicts.get(sandbox).get("category", "N/A"),
                "malware_names": sandbox_verdicts.get(sandbox).get("malware_names", [])
            }
            for sandbox in sandbox_verdicts
        ]


        # Crowdsourced IDS rules
        crowdsourced_ids_results = attributes.get("crowdsourced_ids_results", [])
        report["crowdsourced_ids_rules"] = [
            {
                "rule_msg": ids_rule.get("rule_msg", "N/A"),
                "alert_severity": ids_rule.get("alert_severity", "N/A"),
                "rule_source": ids_rule.get("rule_source", "N/A"),
                "rule_url": ids_rule.get("rule_url", "N/A")
            }
            for ids_rule in crowdsourced_ids_results
        ]

        return report
    else:
        print(f"Failed to fetch VirusTotal report for {hash_id}. Status Code: {response.status_code}")
        return None

def submit_hash_for_rescan(hash_id, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Submitting {hash_id} for rescan...</b>'))
            display(progress_bar)
    print(f"Submitting {hash_id} for rescan.")
    
    url = f"https://www.virustotal.com/api/v3/files/{hash_id}/analyse"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.post(url, headers=headers)
    
    if response.status_code == 200:
        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f'<b>{hash_id} rescan submitted successfully.</b>'))
                display(progress_bar)
        print(f"{hash_id} submitted for rescan.")
        return response.json()
    else:
        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f'<b>Failed to submit {hash_id} for rescan. Status Code: {response.status_code}</b>'))
                display(progress_bar)
        print(f"Failed to submit {hash_id} for rescan. Status Code: {response.status_code}")
        return None