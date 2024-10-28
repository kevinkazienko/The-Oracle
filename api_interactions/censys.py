from api.api_keys import (
    censys_api_key, 
    censys_secret
)
from file_operations.file_utils import (
    is_ip, 
    is_url, 
    is_hash,
    is_cve
)
import requests
from IPython.display import clear_output, HTML, display

def get_censys_data(censys_api_key, censys_secret, query, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching report from Censys for {query}...</b>'))
            display(progress_bar)
            #print(f'<b>Fetching report from Censys for {query}...</b>')
    
    API_URL_HOSTS = "https://search.censys.io/api/v2/hosts/"
    UID = censys_api_key
    SECRET = censys_secret

    auth = (UID, SECRET)

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    # Determine if the query is an IP
    if is_ip(query):
        endpoint = API_URL_HOSTS
    else:
        return {"error": "Only IP-based searches are supported for this function."}

    try:
        res = requests.get(f"{endpoint}{query}", headers=headers, auth=auth)
        res.raise_for_status()
        response_data = res.json().get('result', {})

        # Extract relevant data
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

        services_summary = []
        for service in services:
            software_list = service.get('software', [])
            for software in software_list:
                product = software.get('product', 'N/A')
                version = software.get('version', 'N/A')
                cpe = software.get('cpe', 'N/A')
                cves = software.get('cves', [])

                service_entry = {
                    "port": service.get('port', 'N/A'),
                    "service_name": service.get('service_name', 'N/A'),
                    "observed_at": service.get('observed_at', 'N/A'),
                    "product": product,
                    "version": version,
                    "cpe": cpe,
                    "cves": cves
                }
                services_summary.append(service_entry)

        data_summary = {
            "ip": ip_address,
            "asn": asn,
            "organization": organization,
            "country": country,
            "city": city,
            "latitude": latitude,
            "longitude": longitude,
            "services": services_summary,
            "last_updated": last_updated
        }

    except requests.exceptions.RequestException as e:
        data_summary = {"error": str(e)}

    return data_summary


def search_cves_on_censys(censys_api_key, censys_secret, query, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Searching CVEs on Censys for {query}...</b>'))
            display(progress_bar)

    API_URL_SEARCH = "https://search.censys.io/api/v2/hosts/search"
    UID = censys_api_key
    SECRET = censys_secret

    auth = (UID, SECRET)

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    query_payload = {
        "q": query
    }

    cves_summary = []
    try:
        res = requests.post(API_URL_SEARCH, json=query_payload, headers=headers, auth=auth)
        res.raise_for_status()
        response_data = res.json()

        # Log the raw response to inspect it
        #print("DEBUG: Raw Censys API Response:", response_data)

        hits = response_data.get('result', {}).get('hits', [])
        total_hits = len(hits)

        if progress_bar:
            progress_bar.total = total_hits

        for index, result in enumerate(hits):
            ip = result.get('ip', 'N/A')
            autonomous_system = result.get('autonomous_system', {})
            as_description = autonomous_system.get('description', 'N/A')
            asn = autonomous_system.get('asn', 'N/A')
            bgp_prefix = autonomous_system.get('bgp_prefix', 'N/A')
            
            dns_info = result.get('dns', {}).get('reverse_dns', {}).get('names', [])
            dns_names = ', '.join(dns_info) if dns_info else 'N/A'

            location = result.get('location', {})
            city = location.get('city', 'N/A')
            province = location.get('province', 'N/A')
            country = location.get('country', 'N/A')
            continent = location.get('continent', 'N/A')
            coordinates = location.get('coordinates', {})
            latitude = coordinates.get('latitude', 'N/A')
            longitude = coordinates.get('longitude', 'N/A')

            operating_system = result.get('operating_system', {})
            os_product = operating_system.get('product', 'N/A')
            os_vendor = operating_system.get('vendor', 'N/A')
            os_version = operating_system.get('version', 'N/A')
            cpe = operating_system.get('cpe', 'N/A')

            services = result.get('services', [])
            service_details = []
            for service in services:
                service_name = service.get('extended_service_name', 'N/A')
                port = service.get('port', 'N/A')
                transport_protocol = service.get('transport_protocol', 'N/A')
                certificate = service.get('certificate', 'N/A')
                service_details.append(f"{service_name} (port {port}, protocol {transport_protocol}, cert: {certificate})")

            matched_services = result.get('matched_services', [])
            matched_service_details = []
            for matched in matched_services:
                matched_name = matched.get('extended_service_name', 'N/A')
                matched_port = matched.get('port', 'N/A')
                matched_protocol = matched.get('transport_protocol', 'N/A')
                matched_cert = matched.get('certificate', 'N/A')
                matched_service_details.append(f"{matched_name} (port {matched_port}, protocol {matched_protocol}, cert: {matched_cert})")

            # Collecting CVE information
            cve_list = []
            for service in services:
                vulnerabilities = service.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    cve_id = vuln.get('id', 'N/A')
                    cvss = vuln.get('cvss', {}).get('base', 'N/A')  # Handle CVSS as a nested dictionary
                    known_exploited = vuln.get('known_exploited', 'N/A')

                    cve_list.append({
                        "CVE ID": cve_id,
                        "CVSS": cvss,
                        "Known Exploited": known_exploited,
                    })

            # Append the results into the summary
            cves_summary.append({
                "IP": ip,
                "Autonomous System": as_description,
                "ASN": asn,
                "BGP Prefix": bgp_prefix,
                "DNS Names": dns_names,
                "Location": {
                    "City": city,
                    "Province": province,
                    "Country": country,
                    "Continent": continent,
                    "Latitude": latitude,
                    "Longitude": longitude
                },
                "Operating System": {
                    "Product": os_product,
                    "Vendor": os_vendor,
                    "Version": os_version,
                    "CPE": cpe
                },
                "Services": service_details,
                "Matched Services": matched_service_details,
                "CVEs": cve_list
            })

            

    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVE data from Censys: {str(e)}")
        cves_summary = {"error": str(e)}

    return cves_summary


def search_censys_org(censys_api_key, censys_secret, org_name, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Searching WHOIS organizations on Censys for {org_name}...</b>'))
            display(progress_bar)

    API_URL_SEARCH = "https://search.censys.io/api/v2/hosts/search"
    UID = censys_api_key
    SECRET = censys_secret

    auth = (UID, SECRET)

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    query_payload = {
        "q": f"whois.organization.name:\"{org_name}\""
    }

    org_summary = []
    try:
        res = requests.post(API_URL_SEARCH, json=query_payload, headers=headers, auth=auth)
        res.raise_for_status()
        response_data = res.json()

        #print("DEBUG: Full JSON response from Censys:", response_data)

        hits = response_data.get('result', {}).get('hits', [])
        total_hits = len(hits)

        if progress_bar:
            progress_bar.total = total_hits

        for index, result in enumerate(hits):
            ip = result.get('ip', 'N/A')
            asn_info = result.get('autonomous_system', {})
            as_description = asn_info.get('description', 'N/A')
            asn = asn_info.get('asn', 'N/A')

            # Extract location information
            location = result.get('location', {})
            city = location.get('city', 'N/A')
            province = location.get('province', 'N/A')
            country = location.get('country', 'N/A')
            postal_code = location.get('postal_code', 'N/A')
            latitude = location.get('coordinates', {}).get('latitude', 'N/A')
            longitude = location.get('coordinates', {}).get('longitude', 'N/A')

            # Extract services
            services = result.get('services', [])
            service_details = []
            for service in services:
                service_name = service.get('extended_service_name', 'N/A')
                transport_protocol = service.get('transport_protocol', 'N/A')
                port = service.get('port', 'N/A')
                service_details.append(f"{service_name} ({transport_protocol} port {port})")

            # Add all the information to the org_summary list
            org_summary.append({
                "IP": ip,
                "ASN": asn,
                "Autonomous System": as_description,
                "City": city,
                "Province": province,
                "Country": country,
                "Postal Code": postal_code,
                "Latitude": latitude,
                "Longitude": longitude,
                "Services": service_details
            })

            if progress_bar:
                progress_bar.value += 1

    except requests.exceptions.RequestException as e:
        print(f"Error fetching organization data from Censys: {str(e)}")
        org_summary = {"error": str(e)}

    return org_summary





