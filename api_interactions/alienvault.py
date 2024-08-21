import requests
import json
from api.api_keys import alienvault_api_key
from file_operations.file_utils import is_ip, is_url, is_hash
from IPython.display import clear_output, HTML, display  # Added import

def get_alienvault_report(query, status_output=None, progress_bar=None, verbose=False):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching AlienVault OTX report for query: {query}...</b>'))
            display(progress_bar)
    print(f"Fetching AlienVault OTX report for query: {query}")
    try:
        if is_ip(query):
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{query}/general"
        elif is_url(query):
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{query}/general"
        elif is_hash(query):
            url = f"https://otx.alienvault.com/api/v1/indicators/file/{query}/general"
        else:
            raise ValueError(f"Unsupported query type: {query}")

        headers = {"X-OTX-API-KEY": alienvault_api_key}

        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        # Print the JSON structure for debugging purposes
        #print_json_structure(data)

        return data

    except (requests.RequestException, KeyError) as e:
        print(f"Error getting AlienVault OTX report: {e}")
        return f"Error getting AlienVault OTX report: {e}"