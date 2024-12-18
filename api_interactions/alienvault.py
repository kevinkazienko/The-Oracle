import requests
import json
from api.api_keys import alienvault_api_key
from file_operations.file_utils import is_ip, is_url, is_hash, is_domain
from IPython.display import clear_output, HTML, display  # Added import

def get_alienvault_report(query, status_output=None, progress_bar=None, verbose=False):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'Fetching AlienVault report for query: {query}'))
            display(progress_bar)
    print(f"Fetching AlienVault report for query: {query}")
    try:
        if is_ip(query):
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{query}/general"
        elif is_domain(query):
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{query}/general"
        elif is_url(query):
            domain = query.split("/")[2]  # Extract domain from the URL
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        elif is_hash(query):
            url = f"https://otx.alienvault.com/api/v1/indicators/file/{query}/general"
        else:
            raise ValueError(f"Unsupported query type: {query}")

        headers = {"X-OTX-API-KEY": alienvault_api_key}

        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()


        # Debug: Raw JSON dump
        # print("DEBUG: Raw JSON response from AlienVault OTX:")
        # print(json.dumps(data, indent=4))  # Pretty-print the JSON with indentation

        return data

    except (requests.RequestException, KeyError) as e:
        print(f"Error getting AlienVault OTX report: {e}")
        return f"Error getting AlienVault OTX report: {e}"