import requests
import json
import urllib.parse
from collections import Counter, defaultdict
from datetime import datetime
from api.api_keys import binaryedge_api_key
from IPython.display import clear_output, HTML, display

# BinaryEdge API Key
BINARYEDGE_API_KEY = binaryedge_api_key  # Replace with your actual API key

# API endpoint for querying IPs and domains/URLs
BINARYEDGE_API_URL = "https://api.binaryedge.io/v2/query/"

def format_date(timestamp):
    if isinstance(timestamp, (int, float)):
        try:
            # Check if the timestamp is in milliseconds (larger than 1e12)
            if timestamp > 1e12:
                timestamp = timestamp / 1000  # Convert milliseconds to seconds
            return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        except (OSError, ValueError):
            return 'Invalid timestamp'
    return 'N/A'

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
                    display(HTML(f"Error: Unsupported IOC type '{ioc_type}'."))
                    display(progress_bar)
            print(f"Error: Unsupported IOC type '{ioc_type}'")
            return None

        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f"BinaryEdge querying {ioc}"))
                display(progress_bar)
        print(f"Querying {ioc} in BinaryEdge")

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            report = response.json()

            if status_output:
                with status_output:
                    #display(HTML(f"<b>BinaryEdge report for {ioc} retrieved successfully.</b>"))
                    #display(progress_bar)
                    print(f"BinaryEdge report for {ioc} retrieved successfully.")
            if progress_bar:
                progress_bar.value += 1  # Adjust progress increment

            return report
        else:
            if status_output:
                with status_output:
                    display(HTML(f"Error: Received status code {response.status_code} from BinaryEdge API."))
            return {'status': response.status_code, 'message': response.text}
    except Exception as e:
        if status_output:
            with status_output:
                display(HTML(f"Exception occurred while querying BinaryEdge: {str(e)}"))
        return None


def search_binaryedge_by_port(port, country=None, status_output=None, progress_bar=None):
    try:
        headers = {'X-Key': BINARYEDGE_API_KEY}
        
        # Map country name to ISO 3166-1 alpha-2 code
        country_codes = {
            'Afghanistan': 'AF', 'Albania': 'AL', 'Algeria': 'DZ', 'Andorra': 'AD', 'Angola': 'AO', 'Antigua and Barbuda': 'AG',
            'Argentina': 'AR', 'Armenia': 'AM', 'Australia': 'AU', 'Austria': 'AT', 'Azerbaijan': 'AZ', 'Bahamas': 'BS', 'Bahrain': 'BH',
            'Bangladesh': 'BD', 'Barbados': 'BB', 'Belarus': 'BY', 'Belgium': 'BE', 'Belize': 'BZ', 'Benin': 'BJ', 'Bhutan': 'BT',
            'Bolivia': 'BO', 'Bosnia and Herzegovina': 'BA', 'Botswana': 'BW', 'Brazil': 'BR', 'Brunei': 'BN', 'Bulgaria': 'BG',
            'Burkina Faso': 'BF', 'Burundi': 'BI', 'Cabo Verde': 'CV', 'Cambodia': 'KH', 'Cameroon': 'CM', 'Canada': 'CA',
            'Central African Republic': 'CF', 'Chad': 'TD', 'Chile': 'CL', 'China': 'CN', 'Colombia': 'CO', 'Comoros': 'KM',
            'Congo (Congo-Brazzaville)': 'CG', 'Costa Rica': 'CR', 'Croatia': 'HR', 'Cuba': 'CU', 'Cyprus': 'CY', 'Czech Republic': 'CZ',
            'Denmark': 'DK', 'Djibouti': 'DJ', 'Dominica': 'DM', 'Dominican Republic': 'DO', 'Ecuador': 'EC', 'Egypt': 'EG',
            'El Salvador': 'SV', 'Equatorial Guinea': 'GQ', 'Eritrea': 'ER', 'Estonia': 'EE', 'Eswatini': 'SZ', 'Ethiopia': 'ET',
            'Fiji': 'FJ', 'Finland': 'FI', 'France': 'FR', 'Gabon': 'GA', 'Gambia': 'GM', 'Georgia': 'GE', 'Germany': 'DE', 'Ghana': 'GH',
            'Greece': 'GR', 'Grenada': 'GD', 'Guatemala': 'GT', 'Guinea': 'GN', 'Guinea-Bissau': 'GW', 'Guyana': 'GY', 'Haiti': 'HT',
            'Honduras': 'HN', 'Hungary': 'HU', 'Iceland': 'IS', 'India': 'IN', 'Indonesia': 'ID', 'Iran': 'IR', 'Iraq': 'IQ',
            'Ireland': 'IE', 'Israel': 'IL', 'Italy': 'IT', 'Jamaica': 'JM', 'Japan': 'JP', 'Jordan': 'JO', 'Kazakhstan': 'KZ',
            'Kenya': 'KE', 'Kiribati': 'KI', 'Kuwait': 'KW', 'Kyrgyzstan': 'KG', 'Laos': 'LA', 'Latvia': 'LV', 'Lebanon': 'LB',
            'Lesotho': 'LS', 'Liberia': 'LR', 'Libya': 'LY', 'Liechtenstein': 'LI', 'Lithuania': 'LT', 'Luxembourg': 'LU',
            'Madagascar': 'MG', 'Malawi': 'MW', 'Malaysia': 'MY', 'Maldives': 'MV', 'Mali': 'ML', 'Malta': 'MT', 'Marshall Islands': 'MH',
            'Mauritania': 'MR', 'Mauritius': 'MU', 'Mexico': 'MX', 'Micronesia': 'FM', 'Moldova': 'MD', 'Monaco': 'MC', 'Mongolia': 'MN',
            'Montenegro': 'ME', 'Morocco': 'MA', 'Mozambique': 'MZ', 'Myanmar (Burma)': 'MM', 'Namibia': 'NA', 'Nauru': 'NR',
            'Nepal': 'NP', 'Netherlands': 'NL', 'New Zealand': 'NZ', 'Nicaragua': 'NI', 'Niger': 'NE', 'Nigeria': 'NG', 'North Korea': 'KP',
            'North Macedonia': 'MK', 'Norway': 'NO', 'Oman': 'OM', 'Pakistan': 'PK', 'Palau': 'PW', 'Palestine': 'PS', 'Panama': 'PA',
            'Papua New Guinea': 'PG', 'Paraguay': 'PY', 'Peru': 'PE', 'Philippines': 'PH', 'Poland': 'PL', 'Portugal': 'PT', 'Qatar': 'QA',
            'Romania': 'RO', 'Russia': 'RU', 'Rwanda': 'RW', 'Saint Kitts and Nevis': 'KN', 'Saint Lucia': 'LC',
            'Saint Vincent and the Grenadines': 'VC', 'Samoa': 'WS', 'San Marino': 'SM', 'Sao Tome and Principe': 'ST', 'Saudi Arabia': 'SA',
            'Senegal': 'SN', 'Serbia': 'RS', 'Seychelles': 'SC', 'Sierra Leone': 'SL', 'Singapore': 'SG', 'Slovakia': 'SK',
            'Slovenia': 'SI', 'Solomon Islands': 'SB', 'Somalia': 'SO', 'South Africa': 'ZA', 'South Korea': 'KR', 'South Sudan': 'SS',
            'Spain': 'ES', 'Sri Lanka': 'LK', 'Sudan': 'SD', 'Suriname': 'SR', 'Sweden': 'SE', 'Switzerland': 'CH', 'Syria': 'SY',
            'Taiwan': 'TW', 'Tajikistan': 'TJ', 'Tanzania': 'TZ', 'Thailand': 'TH', 'Timor-Leste': 'TL', 'Togo': 'TG', 'Tonga': 'TO',
            'Trinidad and Tobago': 'TT', 'Tunisia': 'TN', 'Turkey': 'TR', 'Turkmenistan': 'TM', 'Tuvalu': 'TV', 'Uganda': 'UG',
            'Ukraine': 'UA', 'United Arab Emirates': 'AE', 'United Kingdom': 'GB', 'United States': 'US', 'Uruguay': 'UY', 'Uzbekistan': 'UZ',
            'Vanuatu': 'VU', 'Vatican City': 'VA', 'Venezuela': 'VE', 'Vietnam': 'VN', 'Yemen': 'YE', 'Zambia': 'ZM', 'Zimbabwe': 'ZW'
        }
        
        # Construct the query with the country code if a valid country is selected
        if country and country != 'All':
            country_code = country_codes.get(country)
            if not country_code:
                print(f"DEBUG: No country code found for {country}. Querying without country filter.")
                query = f"port:{port}"
            else:
                query = f"country:{country_code} port:{port}"
        else:
            query = f"port:{port}"

        # Construct the URL for the BinaryEdge search query
        url = f"https://api.binaryedge.io/v2/query/search?query={urllib.parse.quote(query)}"
        print(f"DEBUG: BinaryEdge Query URL: {url}")
        
        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f"BinaryEdge querying port {port}"))
                display(progress_bar)
        
        print(f"Querying BinaryEdge with query: {query}")

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            report = response.json()

            # Parse each event in the response and extract relevant information
            events = report.get("events", [])
            event_details = []

            for event in events:
                target_info = event.get("target", {})
                origin_info = event.get("origin", {})
                result_info = event.get("result", {}).get("data", {}).get("response", {})

                # Extract important fields from the event
                details = {
                    "Target IP": target_info.get("ip", "N/A"),
                    "Target Port": target_info.get("port", "N/A"),
                    "Target Protocol": target_info.get("protocol", "N/A"),
                    "Origin IP": origin_info.get("ip", "N/A"),
                    "Origin Country": origin_info.get("country", "N/A"),
                    "Origin Region": origin_info.get("region", "N/A"),
                    "Origin Timestamp": origin_info.get("ts", "N/A"),
                    "Response Status": result_info.get("status", {}).get("message", "N/A"),
                    "Response Code": result_info.get("status", {}).get("code", "N/A"),
                    "Response URL": result_info.get("url", "N/A"),
                    "Response Body (Content)": result_info.get("body", {}).get("content", "N/A")[:100] + "...",  # Trim body for display
                    "Response Headers": result_info.get("headers", {}).get("headers", {}),
                }

                event_details.append(details)

            # Return event details
            return {"events": event_details}

        else:
            print(f"Failed to query BinaryEdge API: {response.status_code}, {response.text}")
            return None

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def search_binaryedge_product(product_name, status_output=None, progress_bar=None):
    headers = {'X-Key': BINARYEDGE_API_KEY}
    url = f"https://api.binaryedge.io/v2/query/search?query=product:{product_name}"
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            report = response.json()
            
            # DEBUG: Check the entire JSON structure
            print(f"DEBUG: BinaryEdge full response JSON: {report}")
            
            events = report.get("events", [])
            
            # Initialize summary counters
            port_counter = Counter()
            version_counter = Counter()
            country_counter = Counter()

            # Loop through events to populate summary data
            for event in events:
                target = event.get('target', {})
                port = f"{target.get('port', 'N/A')}/{target.get('protocol', 'N/A')}"
                
                # Service information for version and product
                service_data = event.get('result', {}).get('data', {}).get('service', {})
                version = service_data.get('version', 'N/A')
                product = service_data.get('product', 'N/A')
                
                # Origin information for country
                origin_data = event.get('origin', {})
                country = origin_data.get('country', 'N/A')

                # DEBUG: Verify extracted fields
                # print(f"DEBUG: Extracted port: {port}")
                # print(f"DEBUG: Extracted version: {version}")
                # print(f"DEBUG: Extracted product: {product}")
                # print(f"DEBUG: Extracted country: {country}")

                # Update counters
                port_counter[port] += 1
                version_counter[(port, version)] += 1
                country_counter[(port, country)] += 1

            # Generate summary output with formatted alignment
            summary_lines = [f"BinaryEdge Summary for Product {product_name}:"]
            summary_lines.append(f"{'Ports':<12}{'Entries':<10}{'Versions':<12}{'Entries':<10}{'Countries':<12}{'Entries':<10}")
            for port, port_count in port_counter.items():
                version, version_count = max((v, count) for (p, v), count in version_counter.items() if p == port)
                country, country_count = max((c, count) for (p, c), count in country_counter.items() if p == port)
                
                summary_lines.append(f"{port:<12}{port_count:<10}{version:<12}{version_count:<10}{country:<12}{country_count:<10}")
            
            summary_output = "\n".join(summary_lines)
            
            # DEBUG: Show the generated summary
            print("DEBUG: Generated Summary:\n", summary_output)
            
            # Return both the report data and the summary
            return {"summary": summary_output, "events": events}

        else:
            print(f"Error querying BinaryEdge API: {response.status_code} - {response.text}")
            return {"summary": "No results or error in fetching data.", "events": []}

    except Exception as e:
        print(f"An error occurred: {e}")
        return {"summary": "Error during query execution.", "events": []}


def search_binaryedge_product_port_country(product, port=None, country=None, status_output=None, progress_bar=None):
    headers = {'X-Key': BINARYEDGE_API_KEY}
    
    # Construct query based on product, port, and optional country
    query = f"product:{product}"
    if port:
        query += f" port:{port}"
    if country:
        query += f" country:{country}"

    # URL encode the query
    url = f"https://api.binaryedge.io/v2/query/search?query={urllib.parse.quote(query)}"
    print(f"DEBUG: BinaryEdge Query URL: {url}")

    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f"BinaryEdge querying {product}:{port}, in {country}"))
            display(progress_bar)

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error querying BinaryEdge: {response.status_code}")
        return {"error": response.text}
