import re
import os
import sys
import json

def ensure_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def read_file(file_name):
    input_directory = os.path.join(os.path.dirname(__file__), '..', 'input_files')
    ensure_directory_exists(input_directory)
    file_path = os.path.join(input_directory, file_name)
    try:
        with open(file_path, 'r') as f:
            print(f'Reading content from {file_path}.')
            return f.read()
    except FileNotFoundError:
        print(f'\nError: The file {file_path} was not found, check again.')
        sys.exit(1)

def write_to_file(file_name, data, category=None):
    output_directory = os.path.join(os.path.dirname(__file__), '..', 'output_files')
    file_path = os.path.join(output_directory, file_name)
    ensure_directory_exists(output_directory)

    if isinstance(data, dict):
        data = json.dumps(data, indent=4)

    sanitized_data = sanitize_and_defang(data)
    with open(file_path, 'a') as f:
        if category:
            f.write(f'{category}:{sanitized_data}\n')
        else:
            f.write(sanitized_data + '\n')

def clean_input(content):
    print('\nCleaning input.')
    # First replace defanged elements with the correct ones
    content = content.replace('[.]', '.')
    content = content.replace('hxxp', 'http')
    content = content.replace('hxxps', 'https')
    content = content.replace('[:]', ':')
    content = re.sub(r':\d+/?', '', content)  # Remove port numbers if present

    # Additionally, we can check if there is a defanged IP pattern to refang it
    defanged_ip_pattern = r'\[\.\]'  # Pattern for defanged IP
    content = re.sub(defanged_ip_pattern, '.', content)

    return content

def sanitize_and_defang(data, defang=True):
    def defang_text(text):
        # Defang URLs and IPs
        text = re.sub(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', r'\1[.]\2[.]\3[.]\4', text)  # IPs
        text = re.sub(r'(?<![\w:])(\w+\.\w+)(?![\w:])', lambda m: m.group(0).replace('.', '[.]'), text)  # URLs and domains
        text = re.sub(r'(\bhttp\b|\bhxxp\b|\bhttps\b|\bhxxps\b)', lambda x: 'hxxp' if x.group(0) == 'http' or x.group(0) == 'hxxp' else 'hxxps', text)  # Protocols

        # Avoid sanitizing specific colons
        exceptions = ['Report:', 'Reports:', 'URLScan:', 'Domains:', 'Hostnames:', 'Time:', 'URL:', 'IP:', 'Open Ports:', 'Organization:', 'ASN:', 'City:', 'Country:', 'Hostnames:', 'Domains:', 'Last Update:', 'Malicious:', 'Suspicious:', 'Safe:', 'Harmless:', 'Timeout:', 'Undetected:', '(URLS):']
        for exception in exceptions:
            text = text.replace(exception.replace(':', '[:]'), exception)

        return text

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str):
                data[key] = defang_text(value)
            elif isinstance(value, list):
                data[key] = [defang_text(item) if isinstance(item, str) else item for item in value]
    elif isinstance(data, str):
        data = defang_text(data)
    
    if not defang:
        data = data.replace('[:]', ':').replace('[.]', '.').replace('hxxp', 'http').replace('hxxps', 'https')
    
    return data

def is_ip(s):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s) is not None

def is_url(s):
    # Updated regular expression to handle subdomains, regions, and complex domains
    return re.match(r"^https?:\/\/([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/[\w\-._~:/?#[\]@!$&'()*+,;=]*)?$", s) is not None

def is_hash(s):
    return re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", s) is not None

def is_domain(s):
    """
    Check if a given string is a valid domain name.
    """
    return re.match(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", s) is not None

# Check for a valid CVE format (e.g., CVE-YYYY-NNNN)
def is_cve(input_text):
    return re.match(r'^CVE-\d{4}-\d{4,7}$', input_text.strip()) is not None


def is_org(s):
    """
    Check if the input string matches typical organization naming conventions.
    This regex assumes organization names contain letters, spaces, and special characters but are not purely numeric.
    """
    return re.match(r"^[a-zA-Z&\s.,\-']+$", s.strip()) is not None

def is_port(s):
    # Ports are numeric and range between 0 and 65535
    return re.match(r"^([0-9]{1,5})$", s) is not None and 0 <= int(s) <= 65535