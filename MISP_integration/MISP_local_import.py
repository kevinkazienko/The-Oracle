
# MISP API URL and key
misp_url = 'https://YOUR_MISP_SERVER_DOMAIN'
api_key = 'YOUR_API_KEY_TO_ACCESS_YOUR_MISP_SERVER'

# Headers for MISP API
headers = {
    'Authorization': api_key,
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

# Function to fetch a sample of IOCs from MISP
def fetch_iocs_sample():
    data = {
        "returnFormat": "json",
        "limit": 10000
    }
    response = requests.post(f"{misp_url}/attributes/restSearch", headers=headers, json=data, verify=False)
    if response.ok:
        return response.json()
    else:
        print(f"Error fetching IOCs: {response.text}")
        return None

# Function to export IOCs to local files
def export_iocs_to_local(iocs):
    ioc_types = {
        'ip-src': 'ioc_ips.txt',
        'url': 'ioc_urls.txt',
        'md5': 'ioc_md5_hashes.txt',
        'sha1': 'ioc_sha1_hashes.txt',
        'sha256': 'ioc_sha256_hashes.txt'
    }

    # Create a dictionary to store file content based on IOC type
    ioc_content = {ioc_type: '' for ioc_type in ioc_types}

    for ioc in iocs.get('response', {}).get('Attribute', []):
        ioc_type = ioc['type']
        value = ioc['value']
        if ioc_type in ioc_content:
            ioc_content[ioc_type] += value + '\n'

    # Write content to local files
    for ioc_type, file_name in ioc_types.items():
        with open(file_name, 'w') as file:
            file.write(ioc_content[ioc_type])

# Main function
def main():
    iocs = fetch_iocs_sample()
    if iocs:
        export_iocs_to_local(iocs)

if __name__ == "__main__":
    main()