import requests
import json
import urllib
import argparse
#from defang import defang
from pprint import pprint as pp
from file_operations.file_utils import (
    is_ip, 
    is_url, 
    is_hash,
    is_domain,
    sanitize_and_defang
)
from IPython.display import clear_output, HTML, display

# Set the Borealis host
global BOREALIS_HOST
BOREALIS_HOST = "https://borealis.ino.u.azure.chimera.cyber.gc.ca"


# Borealis function
def request_borealis(request, ioc_type, modules=None, print_response=True, print_geolocation=True, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Fetching report from Borealis for {request}...</b>'))
            display(progress_bar)

    # Sanitize the request for URLs
    if request.startswith("http"):
        request = urllib.parse.quote_plus(request)

    # Define correct modules based on IOC type
    if modules:
        selected_modules = modules
    else:
        selected_modules = get_modules_by_ioc_type(ioc_type)  # Select appropriate modules based on IOC type

    response = requests.get(f"{BOREALIS_HOST}/process/{request}?modules={selected_modules}&ioc_type={ioc_type}")

    if response.ok:
        jresponse = response.json()
        print(f"Borealis report on {request} has been received.")
    else:
        print("Error: server did not return 200 OK response")
        return None

    return jresponse

# Format Borealis report
def format_borealis_report(report, ioc_type, request):
    if not report:
        return "Borealis Report:\nN/A\n\n"

    formatted_result = f"Borealis Report for {sanitize_and_defang(request)}:\n"

    # # Extract IP from 'ips' list
    # if ioc_type == "ip":
    #     ip_field = report.get('ips', [])
    #     ip_address = ip_field[0] if ip_field else 'N/A'  # Fetch the first IP in the list
    #     formatted_result += f"IP: {sanitize_and_defang(ip_address)}\n"
    # elif ioc_type == "url":
    #     domain = report.get('domain', 'N/A')
    #     formatted_result += f"Domain: {sanitize_and_defang(domain)}\n"
    #     formatted_result += "IP Addresses:\n"
    #     for ip_info in report.get('ip_addresses', []):
    #         formatted_result += f"  - {sanitize_and_defang(ip_info)}\n"
    # elif ioc_type == "hash":
    #     formatted_result += f"Hash: {sanitize_and_defang(report.get('hash', 'N/A'))}\n"

    # Loop through the modules and format them
    modules = report.get("modules", {})
    for module_name, module_data in modules.items():
        formatted_result += f"\n{module_name.upper()}:\n"  # Show the module name without "Module:"

        # If the module data is a list, format each entry
        if isinstance(module_data, list):
            for item in module_data:
                if isinstance(item, dict):
                    formatted_result += format_dict(item, 4)  # Format dicts nicely
                else:
                    formatted_result += f"    - {item}\n"
        # If the module data is a dictionary, format it
        elif isinstance(module_data, dict):
            formatted_result += format_dict(module_data, 4)
        else:
            formatted_result += f"    - {module_data}\n"

    return formatted_result.strip()


def format_dict(d, indent=2):
    """
    Helper function to format nested dictionaries with indentation.
    """
    formatted_str = ""
    for key, value in d.items():
        if isinstance(value, dict):
            formatted_str += f"{' ' * indent}- {key}:\n{format_dict(value, indent + 2)}"
        elif isinstance(value, list):
            formatted_str += f"{' ' * indent}- {key}:\n"
            for item in value:
                if isinstance(item, dict):
                    formatted_str += format_dict(item, indent + 2)
                else:
                    formatted_str += f"{' ' * (indent + 2)}- {item}\n"
        else:
            formatted_str += f"{' ' * indent}- {key}: {value}\n"
    return formatted_str

# Determine the modules based on IOC type
def get_modules_by_ioc_type(ioc_type):
    """
    Returns the appropriate Borealis modules based on the IOC type.
    """
    if ioc_type == "ip":
        return "Maxmind,BeAVER,NCTNS,Stonewall,ARIN,Spur,Neustar"
    elif ioc_type == "domain":
        return "AUWL,BeAVER,MOOSE,AlphabetSoup,Stonewall,Top1Million,DNSDB"
    elif ioc_type == "url":
        return "AUWL,BeAVER,SAFEBROWSING"
    else:
        return None

# Analyze function that integrates Borealis with IOC processing
def analyze_ioc(ioc):
    # Determine the type of IOC
    if is_ip(ioc):
        ioc_type = "ip"
    elif is_domain(ioc):
        ioc_type = "domain"
    elif is_url(ioc):
        ioc_type = "url"
    else:
        print("Unknown IOC type.")
        return

    # Get the corresponding modules for the IOC type
    modules = get_modules_by_ioc_type(ioc_type)

    # Request Borealis report
    result = request_borealis(request=ioc, ioc_type=ioc_type, modules=modules)
    
    # Process and format the result
    formatted_report = {sanitize_and_defang(format_borealis_report(result, ioc_type, request=ioc))}
    
    # Print or return the formatted report
    print(formatted_report)