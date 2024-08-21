from api.api_keys import (
    censys_api_key, 
    censys_secret
)
from file_operations.file_utils import (
    is_ip, 
    is_url, 
    is_hash
)
import requests
from IPython.display import clear_output, HTML, display

def get_censys_data(censys_api_key, censys_secret, query, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching report from Censys for {query}...</b>'))
            display(progress_bar)
    
    API_URL_HOSTS = "https://search.censys.io/api/v2/hosts/"
    API_URL_DOMAINS = "https://search.censys.io/api/v2/domains/"
    UID = censys_api_key
    SECRET = censys_secret

    auth = (UID, SECRET)

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    # Determine if the query is an IP or a domain
    if is_ip(query):
        endpoint = API_URL_HOSTS
    else:
        endpoint = API_URL_DOMAINS

    try:
        res = requests.get(f"{endpoint}{query}", headers=headers, auth=auth)
        res.raise_for_status()
        response_data = res.json().get('result', {})

        # Extracting relevant data
        ip_address = response_data.get('ip', 'N/A')
        autonomous_system = response_data.get('autonomous_system', {})
        asn = autonomous_system.get('asn', 'N/A')
        organization = autonomous_system.get('description', 'N/A')
        country = response_data.get('location', {}).get('country', 'N/A')
        city = response_data.get('location', {}).get('city', 'N/A')
        latitude = response_data.get('location', {}).get('coordinates', {}).get('latitude', 'N/A')
        longitude = response_data.get('location', {}).get('coordinates', {}).get('longitude', 'N/A')
        last_updated = response_data.get('last_updated_at', 'N/A')
        services = response_data.get('services', [])
        operating_system = services[0].get('software', [{}])[0].get('product', 'N/A') if services else 'N/A'

        services_summary = [{"port": service.get('port', 'N/A'), "service_name": service.get('service_name', 'N/A'), 
                             "observed_at": service.get('observed_at', 'N/A')} for service in services]

        data_summary = {
            "ip": ip_address,
            "asn": asn,
            "organization": organization,
            "country": country,
            "city": city,
            "latitude": latitude,
            "longitude": longitude,
            "operating_system": operating_system,
            "services": services_summary,
            "last_updated": last_updated
        }

    except requests.exceptions.RequestException as e:
        data_summary = {"error": str(e)}
    
    return data_summary





