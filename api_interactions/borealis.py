import requests
import json
import urllib
import argparse
import re
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
            display(HTML(f'<b>Fetching Borealis report for {request}...</b>'))
            display(progress_bar)

    print(f"DEBUG: Fetching Borealis report for {request}.")
    print(f"DEBUG: IOC type detected = {ioc_type}")

    # Sanitize the request for URLs
    if request.startswith("http"):
        request = urllib.parse.quote_plus(request)

    # Use provided modules or get default modules by IOC type
    selected_modules = modules if modules else get_modules_by_ioc_type(ioc_type)

    # Debugging: Show which modules are being used
    print(f"DEBUG: Selected modules for {ioc_type} = {selected_modules}")

    try:
        response = requests.get(f"{BOREALIS_HOST}/process/{request}?modules={selected_modules}&ioc_type={ioc_type}")

        if response.status_code == 503:
            print(f"ERROR: Borealis server returned 503 Service Unavailable. Skipping Borealis report for {request}.")
            return None  # Skip Borealis processing if 503 is encountered

        if response.ok:
            jresponse = response.json()
            print(f"DEBUG: Borealis report on {request} has been received.")
            return jresponse
        else:
            print(f"ERROR: Borealis server did not return 200 OK response. Status code: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Exception during Borealis request: {e}")
        return None

# Format Borealis report
def format_borealis_report(report, ioc_type, request):
    if not report:
        return "Borealis Report:\nN/A\n\n"

    formatted_result = f"Borealis Report for {sanitize_and_defang(request)}:\n"

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
        modules = "Maxmind,BeAVER,NCTNS,STONEWALL,ARIN,Spur,Neustar"
    elif ioc_type == "domain":
        modules = "AUWL,BeAVER,MOOSE,ALPHABETSOUP,STONEWALL,TOP1MILLION,DNSDB"
    elif ioc_type == "url":
        modules = "AUWL,BeAVER,SAFEBROWSING,ALPHABETSOUP"
    else:
        modules = None
    
    # Debugging: Output the modules selected for the IOC type
    print(f"DEBUG: Modules selected for {ioc_type}: {modules}")

    return modules

# Analyze function that integrates Borealis with IOC processing
def analyze_ioc(ioc, ioc_type):
    # Debugging: Output the IOC type
    print(f"DEBUG: Analyzing IOC '{ioc}' as type '{ioc_type}'")

    # Get the corresponding modules for the IOC type
    modules = get_modules_by_ioc_type(ioc_type)

    # Debugging: Output the selected modules for the IOC type
    print(f"DEBUG: Modules selected for {ioc_type}: {modules}")

    # Request Borealis report
    result = request_borealis(request=ioc, ioc_type=ioc_type, modules=modules)

    if result:
        # Process and format the result
        formatted_report = format_borealis_report(result, ioc_type, request=ioc)
        
        # Print or return the formatted report
        print(formatted_report)
    else:
        print(f"DEBUG: No Borealis report received for {ioc}")