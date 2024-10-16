import requests
import json
import urllib.parse
from api.api_keys import binaryedge_api_key
from IPython.display import clear_output, HTML, display

# BinaryEdge API Key
BINARYEDGE_API_KEY = binaryedge_api_key  # Replace with your actual API key

# API endpoint for querying IPs and domains/URLs
BINARYEDGE_API_URL = "https://api.binaryedge.io/v2/query/"

def get_binaryedge_report(ioc, ioc_type, status_output=None, progress_bar=None):
    try:
        headers = {'X-Key': BINARYEDGE_API_KEY}

        # Adjust endpoint based on the IOC type
        if ioc_type == "ip":
            url = f"https://api.binaryedge.io/v2/query/ip/{ioc}"
        elif ioc_type == "domain":
            url = f"https://api.binaryedge.io/v2/query/domain/{ioc}"
        elif ioc_type == "url":
            # Extract the domain from the URL
            parsed_url = urllib.parse.urlparse(ioc)
            domain = parsed_url.netloc
            url = f"https://api.binaryedge.io/v2/query/domain/{domain}"
        else:
            if status_output:
                with status_output:
                    display(HTML(f"<b>Error: Unsupported IOC type '{ioc_type}'.</b>"))
                    display(progress_bar)
            print(f"Error: Unsupported IOC type '{ioc_type}'")
            return None

        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f"<b>BinaryEdge querying {ioc}...</b>"))
                display(progress_bar)
        print(f"Querying {ioc} in BinaryEdge...")

        #if status_output:
         #   with status_output:
                #display(HTML(f"<b>Querying BinaryEdge for {ioc}...</b>"))
                #display(progress_bar)
            #print(f"Querying BinaryEdge for {ioc}...")

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            report = response.json()

            if status_output:
                with status_output:
                    display(HTML(f"<b>BinaryEdge report for {ioc} retrieved successfully.</b>"))
                    display(progress_bar)
                print(f"BinaryEdge report for {ioc} retrieved successfully.")
            if progress_bar:
                progress_bar.value += 5  # Adjust progress increment

            return report
        else:
            if status_output:
                with status_output:
                    display(HTML(f"<b>Error: Received status code {response.status_code} from BinaryEdge API.</b>"))
            return {'status': response.status_code, 'message': response.text}
    except Exception as e:
        if status_output:
            with status_output:
                display(HTML(f"<b>Exception occurred while querying BinaryEdge: {str(e)}</b>"))
        return None