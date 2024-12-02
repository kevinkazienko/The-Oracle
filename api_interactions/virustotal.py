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
        "limit": 10  # Limit to top 10 communicating files
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        files = []
        file_name_cache = {}  # Cache to store file names and avoid redundant requests
        
        file_entries = data.get("data", [])
        max_files_to_fetch = 10  # Limit to 10 files as per your request

        
        delay_between_requests = 1  # seconds

        # Inform the user about the expected total time
        estimated_time = (max_files_to_fetch - 1) * delay_between_requests
        print(f"Fetching details for {max_files_to_fetch} files will take approximately {estimated_time} seconds due to API rate limits.")

        for idx, item in enumerate(file_entries):
            if idx >= max_files_to_fetch:
                break
            file_id = item["id"]
            sha256 = item["attributes"].get("sha256", "N/A")
            first_submission_ts = item["attributes"].get("first_submission_date", 0)
            first_submission_date = datetime.utcfromtimestamp(first_submission_ts).strftime('%Y-%m-%d %H:%M:%S') if first_submission_ts else 'N/A'
            last_analysis_stats = item["attributes"].get("last_analysis_stats", {})
        
            # Fetch the file name
            if file_id in file_name_cache:
                file_name = file_name_cache[file_id]
            else:
                file_name = get_file_name_from_virustotal(file_id, status_output, progress_bar)
                file_name_cache[file_id] = file_name
                # Update progress bar
                if progress_bar:
                    progress_bar.value += 1 / max_files_to_fetch
                # Respect rate limits
                if idx < max_files_to_fetch - 1:
                    print(f"Waiting {delay_between_requests} seconds to respect rate limits...")
                    time.sleep(delay_between_requests)
            
            # Extract AV detections
            av_detections = {
                "malicious": last_analysis_stats.get("malicious", 0),
                "suspicious": last_analysis_stats.get("suspicious", 0),
                "undetected": last_analysis_stats.get("undetected", 0),
                "harmless": last_analysis_stats.get("harmless", 0)
            }
            
            # Append the file details
            files.append({
                "file_name": file_name,
                "sha256": sha256,
                "first_submission_date": first_submission_date,
                "av_detections": av_detections  # Include AV detection stats
            })
        
        return files
    else:
        print(f"Failed to fetch Communicating Files for IP: {ip}. Status Code: {response.status_code}")
        return None

def get_file_name_from_virustotal(file_id, status_output=None, progress_bar=None):
    url = f"https://www.virustotal.com/api/v3/files/{file_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        file_report = response.json()
        attributes = file_report.get('data', {}).get('attributes', {})
        # Try to get the meaningful name or the first name in the names list
        file_name = attributes.get('meaningful_name')
        if not file_name:
            names_list = attributes.get('names', [])
            file_name = names_list[0] if names_list else 'Unknown'
        return file_name
    else:
        print(f"Failed to fetch file details for file ID: {file_id}. Status Code: {response.status_code}")
        return 'N/A'

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
    print(f"DEBUG: VirusTotal URL report endpoint: https://www.virustotal.com/api/v3/urls/{url}")
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
    print(f"DEBUG: VirusTotal URL report endpoint: https://www.virustotal.com/api/v3/urls/{url_id}")
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

def get_downloaded_files(entry):
    url = f"https://www.virustotal.com/api/v3/urls/{entry}/relations"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    print(f"DEBUG: Response JSON for Downloaded Files (URL: {entry}):\n{response.json()}\n")
    if response.status_code == 200:
        data = response.json()
        downloaded_files = [
            {
                "sha256": file.get("id"),
                "meaningful_name": file["attributes"].get("meaningful_name", "N/A")
            }
            for file in data.get("data", []) if file.get("type") == "file"
        ]
        return downloaded_files
    else:
        print(f"Failed to fetch relations for entry: {entry}. Status Code: {response.status_code}")
        return []

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
        print(f"DEBUG: VirusTotal Domain rescan endpoint: https://www.virustotal.com/api/v3/domains/{domain}/analyse")
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
    print(f"DEBUG: VirusTotal Domain report endpoint: https://www.virustotal.com/api/v3/domains/{domain}")
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

        # Fetch Passive DNS data for the domain
        passive_dns = get_domain_passive_dns(domain, status_output, progress_bar)
        report["passive_dns"] = passive_dns

        return report
    else:
        print(f"Failed to fetch VirusTotal report for: {domain}. Status Code: {response.status_code}, Response: {response.text}")
        return None

# def get_ip_av_detections(ip, status_output=None, progress_bar=None):
#     """
#     Fetch AV detection stats for a given IP using VirusTotal API.
#     """
#     if status_output:
#         with status_output:
#             clear_output(wait=True)
#             display(HTML(f'<b>Fetching AV detections for IP: {ip}...</b>'))
#             display(progress_bar)
#     print(f"Fetching AV detections for IP: {ip}")
    
#     url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
#     headers = {
#         "accept": "application/json",
#         "x-apikey": virus_total_api_key
#     }
#     response = requests.get(url, headers=headers)
#     if response.status_code == 200:
#         data = response.json()
#         last_analysis_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
#         return {
#             "malicious": last_analysis_stats.get("malicious", 0),
#             "suspicious": last_analysis_stats.get("suspicious", 0),
#             "undetected": last_analysis_stats.get("undetected", 0),
#             "harmless": last_analysis_stats.get("harmless", 0)
#         }
#     else:
#         print(f"Failed to fetch AV detections for IP: {ip}. Status Code: {response.status_code}")
#         return {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0}


def get_domain_passive_dns(domain, status_output=None, progress_bar=None):
    """
    Fetch Passive DNS resolutions and AV detections for a given domain using VirusTotal API.
    """
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching Passive DNS data for Domain: {domain}...</b>'))
            display(progress_bar)
    print(f"Fetching Passive DNS data for Domain: {domain}")
    
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions?limit=10"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        try:
            data = response.json()
            #print(f"DEBUG: Raw JSON response for Passive DNS:\n{json.dumps(data, indent=4)}\n")  # Log full response
            
            resolutions = []
            for item in data.get("data", []):
                attributes = item.get("attributes", {})
                ip_address = attributes.get("ip_address", "N/A")
                resolved_date = datetime.utcfromtimestamp(attributes.get("date", 0)).strftime('%Y-%m-%d %H:%M:%S')
                host_name = attributes.get("host_name", "N/A")
                
                # IP AV detections
                ip_av_detections = attributes.get("ip_address_last_analysis_stats", {
                    "malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0
                })
                
                # Hostname AV detections
                host_av_detections = attributes.get("host_name_last_analysis_stats", {
                    "malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0
                })
                
                resolution = {
                    "ip_address": ip_address,
                    "resolved_date": resolved_date,
                    "host_name": host_name,
                    "ip_av_detections": {
                        "malicious": ip_av_detections.get("malicious", 0),
                        "suspicious": ip_av_detections.get("suspicious", 0),
                        "undetected": ip_av_detections.get("undetected", 0),
                        "harmless": ip_av_detections.get("harmless", 0)
                    },
                    "host_av_detections": {
                        "malicious": host_av_detections.get("malicious", 0),
                        "suspicious": host_av_detections.get("suspicious", 0),
                        "undetected": host_av_detections.get("undetected", 0),
                        "harmless": host_av_detections.get("harmless", 0)
                    }
                }
                resolutions.append(resolution)
            
            print(f"DEBUG: Parsed Resolutions:\n{json.dumps(resolutions, indent=4)}\n")  # Log parsed data
            return resolutions
        
        except Exception as e:
            print(f"ERROR: Exception while processing Passive DNS data: {e}")
            return []
    
    else:
        print(f"Failed to fetch Passive DNS data for Domain: {domain}. Status Code: {response.status_code}")
        print(f"Response: {response.text}")  # Log error response
        return []

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