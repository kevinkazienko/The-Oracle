import requests
import json
from file_operations.file_utils import is_ip
from api.api_keys import shodan_api_key
from IPython.display import clear_output, HTML, display  # Added import

def get_shodan_report(query, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching Shodan report for query: {query}...</b>'))
            display(progress_bar)
    print(f"Fetching Shodan report for query: {query}")
    try:
        if is_ip(query):
            url = f"https://api.shodan.io/shodan/host/{query}"
        else:
            url = f"https://api.shodan.io/dns/resolve?hostnames={query}"
            params = {"key": shodan_api_key}
            response = requests.get(url, params=params)
            response.raise_for_status()

            data = response.json()
            if query not in data:
                return {"report": "N/A"}
            else:
                ip = data[query]
                url = f"https://api.shodan.io/shodan/host/{ip}"

        params = {
            "key": shodan_api_key
        }
        response = requests.get(url, params=params)
        response.raise_for_status()

        data = response.json()

        if "error" in data:
            return {"report": "N/A"}
        elif not data.get("data"):
            return {"report": "N/A"}
        else:
            ip_info = {
                "- Open Ports": ", ".join(str(port) for port in data.get('ports', [])),
                "- Organization": data.get('org', 'N/A'),
                "- ASN": data.get('asn', 'N/A'),
                "- City": data.get('city', 'N/A'),
                "- Country": data.get('country_name', 'N/A'),
                "- Hostnames": ', '.join(data.get('hostnames', ['N/A'])),
                "- Domains": ', '.join(data.get('domains', ['N/A'])),
                "- Vulnerabilities": ', '.join(data.get('vulns', [])) if data.get('vulns') else 'N/A',
                "- Last Update": data.get('last_update', 'N/A')
            }
            return {"report": ip_info}

    except requests.exceptions.RequestException as e:
        print(f"Error getting Shodan report: {e}")
        return {"report": "N/A"}
    except json.JSONDecodeError as e:
        print(f"Error decoding Shodan JSON response: {e}")
        return {"report": "N/A"}