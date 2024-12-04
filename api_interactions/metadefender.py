import requests
import json
import urllib.parse
import base64
from api.api_keys import metadefender_api_key
from IPython.display import clear_output, HTML, display
from file_operations.file_utils import is_ip, is_url, is_domain, is_hash, is_cve


def analyze_with_metadefender(ioc, ioc_type=None, metadefender_api_key=None, status_output=None, progress_bar=None):
    base_url = 'https://api.metadefender.com/v4/'
    ioc_type = ioc_type.strip().lower()

    # Determine endpoint based on IOC type, with specific handling for URL IOC
    if not ioc_type:
        if is_ip(ioc):
            ioc_type = 'ip'
        elif is_url(ioc):
            ioc_type = 'url'
        elif is_domain(ioc):
            ioc_type = 'domain'
        elif is_hash(ioc):
            ioc_type = 'hash'
        else:
            return "Metadefender: Unsupported IOC type"

    

    print(f"DEBUG: Metadefender Detected IOC Type: {ioc_type} for IOC: {ioc}")

    # Construct the endpoint based on IOC type
    if ioc_type == 'url':
        parsed_url = urllib.parse.urlparse(ioc)
        ioc = parsed_url.netloc
        endpoint = f"url/{ioc}"
    elif ioc_type == 'ip':
        endpoint = f"ip/{ioc}"
    elif ioc_type == 'domain':
        endpoint = f"domain/{ioc}"
    elif ioc_type == 'hash':
        endpoint = f"hash/{ioc}"
    else:
        return "Metadefender: Unsupported IOC type"

    # Set headers and handle the display of status and progress bar
    headers = {'apikey': metadefender_api_key}
    
    try:
        # Display initial query status
        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f"<b>Metadefender querying {ioc}...</b>"))
                if progress_bar:
                    display(progress_bar)
                    
        # Execute the request
        print(f"Querying {ioc} in Metadefender with endpoint: {base_url}{endpoint}")
        response = requests.get(f"{base_url}{endpoint}", headers=headers)
        response.raise_for_status()
        metadefender_data = response.json()
        #print("DEBUG: JSON response from Metadefender:", json.dumps(metadefender_data, indent=4))
        
        # Display data retrieved status
        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f"<b>Data retrieved from Metadefender for {ioc}.</b>"))
                if progress_bar:
                    display(progress_bar)
        
        # Process and format the report based on IOC type
        report = ""
        if ioc_type == 'ip':
            report = process_metadefender_ip_report(metadefender_data)
        elif ioc_type == 'url':
            report = process_metadefender_url_report(metadefender_data)
        elif ioc_type == 'domain':
            report = process_metadefender_dom_report(metadefender_data)
        elif ioc_type == 'hash':
            report = process_metadefender_hash_report(metadefender_data)

        # Increment progress bar if available
        if progress_bar:
            progress_bar.value += 1

        return report

    except requests.exceptions.RequestException as e:
        error_message = f"Metadefender: Error retrieving data for {ioc}: {str(e)}"
        print(error_message)  # Log error for debugging
        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f"<b>{error_message}</b>"))
        return error_message

# Function to process Metadefender IP reports
def process_metadefender_ip_report(report):
    if not report:
        return "Metadefender IP Report: No data available"
    
    # Extract and safely handle fields
    address = report.get("address", "N/A")
    lookup_results = report.get("lookup_results", {})
    geo_info = report.get("geo_info", {})
    
    detected_by = lookup_results.get("detected_by", "N/A")
    sources = lookup_results.get("sources", [])

    country = geo_info.get("country", {}).get("name", "N/A")
    city = geo_info.get("city", {}).get("name", "N/A")
    latitude = geo_info.get("location", {}).get("latitude", "N/A")
    longitude = geo_info.get("location", {}).get("longitude", "N/A")
    
    subdivisions = geo_info.get("subdivisions", [])
    subdivision = subdivisions[0].get("name", "N/A") if subdivisions else "N/A"

    sources_info = "\n".join(
        f"    - Provider: {source.get('provider', 'N/A')}\n     - Status: {source.get('status', 'N/A')}\n "
        f"    - Assessment: {source.get('assessment', 'N/A')}\n     - Last Updated: {source.get('update_time', 'N/A')}"
        for source in sources
    )

    return (
        f"Metadefender IP Report:\n"
        f"  - Address: {address}\n"
        f"  - Detected By: {detected_by} sources\n"
        f"  - Geo Info:\n"
        f"      - Country: {country}\n"
        f"      - City: {city}\n"
        f"      - Subdivision: {subdivision}\n"
        f"      - Latitude: {latitude}\n"
        f"      - Longitude: {longitude}\n"
        f"  - Threat Sources:\n{sources_info or 'None detected'}"
    )

# Function to process Metadefender URL/domain reports
def process_metadefender_url_report(report):
    if not report:
        return "Metadefender URL/Domain Report: No data available"
    
    scan_result = report.get('scan_result', {})
    detections = scan_result.get('detections', [])
    detection_summary = ', '.join(det.get('threat_name', 'Unknown Threat') for det in detections) or 'No threats detected'
    
    return f"Metadefender URL/Domain Report:\n  - Detections: {detection_summary}"


def process_metadefender_dom_report(report):
    if not report:
        return "Metadefender Domain Report: No data available"
    
    # Extract the domain address
    domain_address = report.get('address', 'Unknown Domain')

    # Extract lookup results
    lookup_results = report.get('lookup_results', {})
    start_time = lookup_results.get('start_time', 'Unknown')
    detected_by = lookup_results.get('detected_by', 0)

    # Extract sources
    sources = lookup_results.get('sources', [])
    if not sources:
        sources_summary = "No detection sources available"
    else:
        sources_summary = "\n".join(
            f"  - Provider: {source.get('provider', 'Unknown Provider')}\n"
            f"    - Assessment: {source.get('assessment', 'None')}\n"
            f"     - Detect Time: {source.get('detect_time', 'N/A')}\n"
            f"     - Update Time: {source.get('update_time', 'N/A')}\n"
            f"     - Status: {source.get('status', 'Unknown')}"
            for source in sources
        )
    
    # Build the report
    report_str = (
        f"Metadefender Domain Report:\n"
        f"  - Domain Address: {domain_address}\n"
        f"    - Start Time: {start_time}\n"
        f"    - Detected By: {detected_by} source(s)\n"
        f"    - Sources:\n{sources_summary}"
    )
    
    return report_str

# Function to process Metadefender Hash reports
def process_metadefender_hash_report(report):
    if not report:
        return "Metadefender Hash Report: No data available"
    
    # File information
    file_info = report.get('file_info', {})
    file_name = file_info.get('display_name', 'N/A')
    file_size = file_info.get('file_size', 'N/A')
    file_type = file_info.get('file_type_description', 'N/A')
    md5 = file_info.get('md5', 'N/A')
    sha1 = file_info.get('sha1', 'N/A')
    sha256 = file_info.get('sha256', 'N/A')
    
    # Threat information
    threat_name = report.get('threat_name', 'N/A')
    malware_family = report.get('malware_family', 'N/A')
    malware_type = ', '.join(report.get('malware_type', []))
    
    # Process information
    process_info = report.get('process_info', {})
    process_result = process_info.get('result', 'N/A')
    blocked_reason = process_info.get('blocked_reason', 'N/A')
    
    # Scan results summary
    scan_results = report.get('scan_results', {})
    scan_all_result = scan_results.get('scan_all_result_a', 'N/A')
    total_engines = scan_results.get('total_avs', 0)
    detected_by = scan_results.get('total_detected_avs', 0)
    start_time = scan_results.get('start_time', 'N/A')
    total_time = scan_results.get('total_time', 'N/A')
    
    # Detailed results by engine
    scan_details = scan_results.get('scan_details', {})
    detailed_results = []
    for engine, details in scan_details.items():
        engine_result = details.get('scan_result_i', 'N/A')
        threat_found = details.get('threat_found', 'None')
        scan_time = details.get('scan_time', 'N/A')
        def_time = details.get('def_time', 'N/A')
        detailed_results.append(
            f"    - Engine: {engine}\n"
            f"      - Result: {'Detected' if engine_result == 1 else 'Not Detected'}\n"
            f"      - Threat Found: {threat_found}\n"
            f"      - Scan Time: {scan_time} ms\n"
            f"      - Definition Time: {def_time}"
        )
    
    # Sanitization information
    sanitized_info = report.get('sanitized', {})
    sanitized_result = sanitized_info.get('result', 'N/A')
    sanitized_reason = sanitized_info.get('reason', 'N/A')
    
    # Data Loss Prevention (DLP) information
    dlp_info = report.get('dlp_info', {})
    dlp_verdict = dlp_info.get('verdict', 'N/A')
    dlp_metadata_removal = dlp_info.get('metadata_removal', {}).get('result', 'N/A')
    dlp_recursive_processing = dlp_info.get('recursive_processing', {}).get('result', 'N/A')
    dlp_redact = dlp_info.get('redact', {}).get('result', 'N/A')
    dlp_watermark = dlp_info.get('watermark', {}).get('result', 'N/A')
    
    # Build the full report
    return (
        f"Metadefender Hash Report:\n"
        f"  - File Name: {file_name}\n"
        f"  - File Size: {file_size} bytes\n"
        f"  - File Type: {file_type}\n"
        f"  - MD5: {md5}\n"
        f"  - SHA1: {sha1}\n"
        f"  - SHA256: {sha256}\n"
        f"  - Threat Name: {threat_name}\n"
        f"  - Malware Family: {malware_family}\n"
        f"  - Malware Type: {malware_type}\n"
        f"  - Process Result: {process_result} (Blocked Reason: {blocked_reason})\n"
        f"  - Total AV Engines: {total_engines}\n"
        f"  - Detected By: {detected_by} engines\n"
        f"  - Overall Scan Result: {scan_all_result}\n"
        f"  - Scan Start Time: {start_time}\n"
        f"  - Total Scan Time: {total_time} ms\n"
        f"  - Detailed Results by Engine:\n" + "\n".join(detailed_results) + "\n"
        f"  - Sanitization Result: {sanitized_result} (Reason: {sanitized_reason})\n"
        f"  - DLP Verdict: {dlp_verdict}\n"
        f"  - DLP Metadata Removal: {dlp_metadata_removal}\n"
        f"  - DLP Recursive Processing: {dlp_recursive_processing}\n"
        f"  - DLP Redact: {dlp_redact}\n"
        f"  - DLP Watermark: {dlp_watermark}"
        f"  - DLP Metadata Removal: {dlp_metadata_removal}\n"
        f"  - DLP Recursive Processing: {dlp_recursive_processing}\n"
        f"  - DLP Redact: {dlp_redact}\n"
        f"  - DLP Watermark: {dlp_watermark}"
    )