import requests
import json
import urllib.parse
import base64
from api.api_keys import metadefender_api_key
from IPython.display import clear_output, HTML, display


def analyze_with_metadefender(ioc, ioc_type, metadefender_api_key, status_output=None, progress_bar=None):
    base_url = 'https://api.metadefender.com/v4/'


    # If the IOC is a URL, extract the domain
    if ioc_type == 'url':
        parsed_url = urllib.parse.urlparse(ioc)
        domain = parsed_url.netloc  # Extract the domain from the URL
        ioc = domain
        ioc_type = 'domain'  # Change the IOC type to domain for Metadefender

    # Determine the endpoint based on IOC type
    if ioc_type == 'ip':
        endpoint = f"ip/{ioc}"
    elif ioc_type == 'domain':
        endpoint = f"domain/{ioc}"
    elif ioc_type == 'url':
        encoded_url = base64.urlsafe_b64encode(ioc.encode()).decode()  # URL-safe Base64 encoding
        endpoint = f"url/{encoded_url}"
    elif ioc_type == 'hash':
        endpoint = f"hash/{ioc}"
    else:
        return "Metadefender: Unsupported IOC type"

    headers = {
        'apikey': metadefender_api_key
    }

    try:
        # Update status before making the API call
        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f"<b>Metadefender querying {ioc}...</b>"))
                display(progress_bar)
        print(f"Querying {ioc} in Metadefender...")
        print(f"Using endpoint: {base_url}{endpoint}")

        response = requests.get(f"{base_url}{endpoint}", headers=headers)
        response.raise_for_status()
        metadefender_data = response.json()

        # Process the Metadefender report based on the type
        report = ""
        if ioc_type == 'ip':
            report = process_metadefender_ip_report(metadefender_data)
        elif ioc_type in ['domain', 'url']:
            report = process_metadefender_url_report(metadefender_data)
        elif ioc_type == 'hash':
            report = process_metadefender_hash_report(metadefender_data)
        else:
            report = f"Metadefender: Unsupported IOC type '{ioc_type}'"

        if progress_bar:
            progress_bar.value += 1  # Increment the progress

        return report

    except requests.exceptions.RequestException as e:
        return f"Metadefender: Error retrieving data for {ioc}: {str(e)}"

# Function to process Metadefender IP reports
def process_metadefender_ip_report(report):
    if not report:
        return "Metadefender IP Report: No data available"

    address = report.get("address", "N/A")
    lookup_results = report.get("lookup_results", {})
    geo_info = report.get("geo_info", {})

    detected_by = lookup_results.get("detected_by", "N/A")
    sources = lookup_results.get("sources", [])

    country = geo_info.get("country", {}).get("name", "N/A")
    city = geo_info.get("city", {}).get("name", "N/A")
    latitude = geo_info.get("location", {}).get("latitude", "N/A")
    longitude = geo_info.get("location", {}).get("longitude", "N/A")

    # Safely handle the 'subdivisions' key in case it's an empty list or missing
    subdivisions = geo_info.get("subdivisions", [])
    if subdivisions and isinstance(subdivisions, list) and len(subdivisions) > 0:
        subdivision = subdivisions[0].get("name", "N/A")
    else:
        subdivision = "N/A"

    sources_info = ""
    for source in sources:
        provider = source.get("provider", "N/A")
        assessment = source.get("assessment", "N/A")
        update_time = source.get("update_time", "N/A")
        status = source.get("status", "N/A")
        sources_info += f"\n      - Provider: {provider}\n       - Status: {status}\n       - Last Updated: {update_time}\n       - Assessment: {assessment}"

    # This full report should only be included in the main output, not the score breakdown
    return (f"Metadefender IP Report:\n"
            f"  - Address: {address}\n"
            f"  - Detected By: {detected_by} sources\n"
            f"  - Geo Info:\n"
            f"      - Country: {country}\n"
            f"      - City: {city}\n"
            f"      - Subdivision: {subdivision}\n"
            f"      - Latitude: {latitude}\n"
            f"      - Longitude: {longitude}\n"
            f"  - Threat Sources: {sources_info if sources_info else 'None detected'}")

# Function to process Metadefender URL/domain reports
def process_metadefender_url_report(report):
    if not report:
        return "Metadefender URL/Domain Report: No data available"

    scan_result = report.get('scan_result', {})
    detections = scan_result.get('detections', [])
    detection_summary = ', '.join([det['threat_name'] for det in detections]) if detections else 'No threats detected'

    return (f"Metadefender URL/Domain Report:\n"
            f"  - Detections: {detection_summary}")

# Function to process Metadefender Hash reports
def process_metadefender_hash_report(report):
    if not report:
        return "Metadefender Hash Report: No data available"

    scan_result = report.get('scan_result', {})
    scan_all_result = scan_result.get('scan_all_result_a', 'N/A')

    detected_by = scan_result.get('total_detected_engines', 0)
    total_engines = scan_result.get('total_av_engines', 0)

    return (f"Metadefender Hash Report:\n"
            f"  - Total AV Engines: {total_engines}\n"
            f"  - Detected By: {detected_by} engines\n"
            f"  - Scan Result: {scan_all_result}")