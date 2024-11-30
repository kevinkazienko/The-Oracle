import requests
import json
import base64
from datetime import datetime, timedelta, timezone
import time
from api.api_keys import virus_total_api_key
from IPython.display import clear_output, HTML, display
from file_operations.file_utils import is_ip, is_domain, is_hash, is_url

VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"

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

def handle_virustotal_ioc(ioc, status_output=None, progress_bar=None):
    ioc_type = detect_ioc_type(ioc)

    if ioc_type == "domain":
        print(f"Detected domain. Fetching report for {ioc}.")
        return get_virustotal_domain_report(ioc, status_output, progress_bar)

    elif ioc_type == "url":
        print(f"Detected URL. Fetching report for {ioc}.")
        return get_virustotal_url_report(ioc, status_output, progress_bar)

    else:
        print(f"Unsupported IOC type '{ioc_type}' for {ioc}.")
        return None

def detect_ioc_type(ioc):
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

def get_ip_passive_dns(ip, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching Passive DNS data for IP: {ip}...</b>'))
            display(progress_bar)
    print(f"Fetching Passive DNS data for IP: {ip}")
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        resolutions = [
            {
                "hostname": item["attributes"]["host_name"],
                "resolved_date": datetime.utcfromtimestamp(item["attributes"]["date"]).strftime('%Y-%m-%d %H:%M:%S')
            }
            for item in data.get("data", [])
        ]
        return resolutions
    else:
        print(f"Failed to fetch Passive DNS data for IP: {ip}. Status Code: {response.status_code}")
        return None

def get_ip_communicating_files(ip, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching Communicating Files for IP: {ip}...</b>'))
            display(progress_bar)
    print(f"Fetching Communicating Files for IP: {ip}")
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/communicating_files"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    params = {
        "limit": 40  # Adjust the limit as needed
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        files = [
            {
                "file_id": item["id"],
                "sha256": item["attributes"].get("sha256"),
                "first_submission_date": datetime.utcfromtimestamp(item["attributes"].get("first_submission_date", 0)).strftime('%Y-%m-%d %H:%M:%S'),
                "last_analysis_stats": item["attributes"].get("last_analysis_stats", {})
            }
            for item in data.get("data", [])
        ]
        return files
    else:
        print(f"Failed to fetch Communicating Files for IP: {ip}. Status Code: {response.status_code}")
        return None

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

        # Fetch Passive DNS data
        passive_dns = get_ip_passive_dns(ip, status_output, progress_bar)
        report["passive_dns"] = passive_dns

        # Fetch Communicating Files data
        communicating_files = get_ip_communicating_files(ip, status_output, progress_bar)
        report["communicating_files"] = communicating_files

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

def get_virustotal_url_report(url_input, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            display(HTML(f'<b>Fetching VirusTotal URL report for: {url_input}...</b>'))
            display(progress_bar)
    print(f"Fetching VirusTotal URL report for: {url_input}")

    # Encode the URL to a URL ID as per VirusTotal's requirements
    url_id = base64.urlsafe_b64encode(url_input.encode()).decode().strip('=')

    url = f"{VIRUSTOTAL_BASE_URL}/urls/{url_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        report = response.json()
        return parse_virustotal_url_report(url_input, report, status_output, progress_bar)
    else:
        print(f"Failed to fetch VirusTotal URL report for: {url_input}. Status Code: {response.status_code}, Response: {response.text}")
        return f"VirusTotal Report:\nNo data available for URL {url_input}.\n"

def parse_virustotal_url_report(url_input, report, status_output=None, progress_bar=None):
    data = report.get("data", {})
    attributes = data.get("attributes", {})
    if not attributes:
        return f"VirusTotal Report:\nNo data available for URL {url_input}.\n"

    try:
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        harmless = last_analysis_stats.get('harmless', 'N/A')
        malicious = last_analysis_stats.get('malicious', 'N/A')
        suspicious = last_analysis_stats.get('suspicious', 'N/A')
        timeout = last_analysis_stats.get('timeout', 'N/A')
        undetected = last_analysis_stats.get('undetected', 'N/A')

        last_analysis_date = attributes.get('last_analysis_date', None)
        last_analysis_date_formatted = (
            datetime.utcfromtimestamp(last_analysis_date).strftime('%Y-%m-%d %H:%M:%S')
            if last_analysis_date else "N/A"
        )

        # Extract AV vendors
        av_results = attributes.get('last_analysis_results', {})
        malicious_vendors = [engine for engine, result in av_results.items() if result.get('category') == 'malicious']
        suspicious_vendors = [engine for engine, result in av_results.items() if result.get('category') == 'suspicious']

        tags = ', '.join(attributes.get('tags', [])) or 'N/A'
        categories = attributes.get('categories', {})
        categories_str = ', '.join(categories.values()) if categories else 'N/A'
        popularity_ranks = attributes.get('popularity_ranks', {})
        popularity_str = ', '.join([f"{source}: {info.get('rank')}" for source, info in popularity_ranks.items() if isinstance(info, dict)])

        # Extract last downloaded file
        last_downloaded_file_hash = attributes.get('last_http_response_content_sha256', None)
        last_downloaded_file_info = "No last downloaded file found"
        if last_downloaded_file_hash:
            last_downloaded_file_info = f"Last downloaded file SHA256: {last_downloaded_file_hash}"
            # Optionally, fetch details about the last downloaded file

        # Build the report
        vt_result = (
            f"VirusTotal URL Report:\n"
            f"  - URL: {attributes.get('url', 'N/A')}\n"
            f"  - Harmless: {harmless}, Malicious: {malicious}, Suspicious: {suspicious}, Timeout: {timeout}, Undetected: {undetected}\n"
            f"  - Malicious Vendors: {', '.join(malicious_vendors) or 'None'}\n"
            f"  - Suspicious Vendors: {', '.join(suspicious_vendors) or 'None'}\n"
            f"  - Tags: {tags}\n"
            f"  - Categories: {categories_str}\n"
            f"  - Popularity Ranks: {popularity_str}\n"
            f"  - Last Analysis Date: {last_analysis_date_formatted}\n"
            f"  - {last_downloaded_file_info}\n"
        )

        # Add Passive DNS Data if available
        # (Note: VirusTotal API may not provide Passive DNS data for URLs directly)
        passive_dns_data = attributes.get("passive_dns", [])
        if passive_dns_data:
            passive_dns_str = "\n".join([
                f"    - IP Address: {item['ip_address']}, Resolved Date: {item['resolved_date']}"
                for item in passive_dns_data
            ])
            vt_result += f"  - Passive DNS Data:\n{passive_dns_str}\n"
        else:
            vt_result += "  - Passive DNS Data: N/A\n"

        # Add Communicating Files Data if available
        communicating_files_data = attributes.get("communicating_files", [])
        if communicating_files_data:
            communicating_files_str = "\n".join([
                f"    - File ID: {item['file_id']}, SHA256: {item['sha256']}, First Submission Date: {item['first_submission_date']}"
                for item in communicating_files_data
            ])
            vt_result += f"  - Communicating Files:\n{communicating_files_str}\n"
        else:
            vt_result += "  - Communicating Files: N/A\n"

        # Add Crowdsourced Context
        crowdsourced_context = attributes.get("crowdsourced_context", [])
        if crowdsourced_context:
            crowdsourced_context_formatted = "\n".join([
                f"    - {ctx.get('title', 'N/A')}: {ctx.get('details', 'N/A')}"
                for ctx in crowdsourced_context
            ])
            vt_result += f"  - Crowdsourced Context:\n{crowdsourced_context_formatted}\n"
        else:
            vt_result += "  - Crowdsourced Context: N/A\n"

        return vt_result

    except KeyError as e:
        return f"Error parsing VirusTotal report: {e}\n"


def get_url_communicating_files(url_id, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching Communicating Files for URL ID: {url_id}...</b>'))
            display(progress_bar)
    print(f"Fetching Communicating Files for URL ID: {url_id}")
    # Debug print to show the endpoint being used
    print(f"DEBUG: VirusTotal URL communicating files endpoint: https://www.virustotal.com/api/v3/urls/{url_id}/communicating_files")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}/communicating_files"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    params = {
        "limit": 40  # Adjust as needed
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        files = [
            {
                "file_id": item["id"],
                "sha256": item["attributes"].get("sha256"),
                "first_submission_date": datetime.utcfromtimestamp(item["attributes"].get("first_submission_date", 0)).strftime('%Y-%m-%d %H:%M:%S'),
                "last_analysis_stats": item["attributes"].get("last_analysis_stats", {})
            }
            for item in data.get("data", [])
        ]
        return files
    else:
        print(f"Failed to fetch Communicating Files for URL ID: {url_id}. Status Code: {response.status_code}")
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

def get_domain_passive_dns(domain, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching Passive DNS data for Domain: {domain}...</b>'))
            display(progress_bar)
    print(f"Fetching Passive DNS data for Domain: {domain}")
    print(f"DEBUG: VirusTotal domain resolutions endpoint: https://www.virustotal.com/api/v3/domains/{domain}/resolutions")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        resolutions = [
            {
                "ip_address": item["attributes"]["ip_address"],
                "resolved_date": datetime.utcfromtimestamp(item["attributes"]["date"]).strftime('%Y-%m-%d %H:%M:%S')
            }
            for item in data.get("data", [])
        ]
        return resolutions
    else:
        print(f"Failed to fetch Passive DNS data for Domain: {domain}. Status Code: {response.status_code}")
        return None

def get_domain_communicating_files(domain, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching Communicating Files for Domain: {domain}...</b>'))
            display(progress_bar)
    print(f"Fetching Communicating Files for Domain: {domain}")
    print(f"DEBUG: VirusTotal domain communicating files endpoint: https://www.virustotal.com/api/v3/domains/{domain}/communicating_files")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/communicating_files"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    params = {
        "limit": 40  # Adjust the limit as needed
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        files = [
            {
                "file_id": item["id"],
                "sha256": item["attributes"].get("sha256"),
                "first_submission_date": datetime.utcfromtimestamp(item["attributes"].get("first_submission_date", 0)).strftime('%Y-%m-%d %H:%M:%S'),
                "last_analysis_stats": item["attributes"].get("last_analysis_stats", {})
            }
            for item in data.get("data", [])
        ]
        return files
    else:
        print(f"Failed to fetch Communicating Files for Domain: {domain}. Status Code: {response.status_code}")
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

def get_virustotal_domain_report(domain, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            display(HTML(f'<b>Fetching VirusTotal domain report for: {domain}...</b>'))
            display(progress_bar)
    print(f"Fetching VirusTotal domain report for: {domain}")
    url = f"{VIRUSTOTAL_BASE_URL}/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        report = response.json()
        return parse_virustotal_domain_report(domain, report)
    else:
        print(f"Failed to fetch VirusTotal domain report for: {domain}. Status Code: {response.status_code}, Response: {response.text}")
        return f"VirusTotal Report:\nNo data available for domain {domain}.\n"

def parse_virustotal_domain_report(domain, report):
    attributes = report.get("data", {}).get("attributes", {})
    if not attributes:
        return f"VirusTotal Report:\nNo data available for domain {domain}.\n"

    report_lines = []
    report_lines.append(f"VirusTotal Domain Report:")
    report_lines.append(f"  - Domain: {domain}")

    # Iterate over all keys in the attributes and add them to the report
    for key, value in attributes.items():
        if key == "last_analysis_results":
            # Process last_analysis_results separately
            malicious_vendors = [engine for engine, result in value.items() if result.get('category') == 'malicious']
            suspicious_vendors = [engine for engine, result in value.items() if result.get('category') == 'suspicious']
            report_lines.append(f"  - Malicious Vendors: {', '.join(malicious_vendors) or 'None'}")
            report_lines.append(f"  - Suspicious Vendors: {', '.join(suspicious_vendors) or 'None'}")
        elif key == "last_dns_records":
            # Process last_dns_records
            dns_records = "\n".join([
                f"    - Type: {record.get('type')}, TTL: {record.get('ttl')}, Value: {record.get('value')}"
                for record in value
            ])
            report_lines.append(f"  - Last DNS Records:\n{dns_records}")
        elif key == "popularity_ranks":
            # Process popularity_ranks
            popularity_str = ', '.join([f"{source}: {info.get('rank')}" for source, info in value.items()])
            report_lines.append(f"  - Popularity Ranks: {popularity_str}")
        elif key == "last_analysis_stats":
            # Process last_analysis_stats
            stats = ", ".join([f"{k.capitalize()}: {v}" for k, v in value.items()])
            report_lines.append(f"  - Last Analysis Stats: {stats}")
        elif key == "whois":
            # Add WHOIS information
            report_lines.append(f"  - WHOIS:\n   - {value}")
        elif isinstance(value, dict):
            # For nested dictionaries, process keys and values
            nested_str = ', '.join([f"{k}: {v}" for k, v in value.items()])
            report_lines.append(f"  - {key.capitalize()}: {nested_str}")
        elif isinstance(value, list):
            # For lists, join the items
            list_str = ', '.join(map(str, value))
            report_lines.append(f"  - {key.capitalize()}: {list_str}")
        else:
            # For other types, add the value directly
            report_lines.append(f"  - {key.capitalize()}: {value}")

    return "\n".join(report_lines)

def get_file_contacted_ips(file_id, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching Contacted IPs for File: {file_id}...</b>'))
            display(progress_bar)
    print(f"Fetching Contacted IPs for File: {file_id}")
    
    url = f"https://www.virustotal.com/api/v3/files/{file_id}/contacted_ips"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    params = {
        "limit": 40  # Adjust the limit as needed
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        ips = [
            {
                "ip_address": item["id"],
                "country": item["attributes"].get("country", "N/A"),
                "last_analysis_stats": item["attributes"].get("last_analysis_stats", {})
            }
            for item in data.get("data", [])
        ]
        return ips
    else:
        print(f"Failed to fetch Contacted IPs for File: {file_id}. Status Code: {response.status_code}")
        return None


def get_file_contacted_domains(file_id, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching Contacted Domains for File: {file_id}...</b>'))
            display(progress_bar)
    print(f"Fetching Contacted Domains for File: {file_id}")
    
    url = f"https://www.virustotal.com/api/v3/files/{file_id}/contacted_domains"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    params = {
        "limit": 40  # Adjust the limit as needed
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        domains = [
            {
                "domain": item["id"],
                "last_analysis_stats": item["attributes"].get("last_analysis_stats", {})
            }
            for item in data.get("data", [])
        ]
        return domains
    else:
        print(f"Failed to fetch Contacted Domains for File: {file_id}. Status Code: {response.status_code}")
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

        # Fetch Contacted IPs
        contacted_ips = get_file_contacted_ips(hash_id, status_output, progress_bar)
        report["contacted_ips"] = contacted_ips

        # Fetch Contacted Domains
        contacted_domains = get_file_contacted_domains(hash_id, status_output, progress_bar)
        report["contacted_domains"] = contacted_domains

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