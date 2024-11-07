import requests
import json
from file_operations.file_utils import is_ip
from urllib.parse import quote
import urllib.parse
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


def search_shodan_cve_country(cve, country, status_output=None, progress_bar=None):
    #data = {}
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Searching Shodan for query: {cve}...</b>'))
            display(progress_bar)
    print(f"Searching Shodan for query: {cve}")
    try:
        print(f"DEBUG: Searching Shodan for CVE: {cve}, Country: {country}")
        # Ensure CVE and country are strings before quoting them, handling None
        cve = cve if isinstance(cve, str) else ''
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
        # If no country is passed or 'All' is selected, omit it from the query
        if country and country.lower() != "all":
            query = f"vuln:{cve} country:{country}"
        else:
            query = f"vuln:{cve}"
        # Convert country name to its ISO 3166-1 alpha-2 code if necessary
        country_code = country_codes.get(country, '') if country.lower() != "all" else ''
        
        # If no country is passed or 'All' is selected, omit it from the query
        if country_code:
            query = f"vuln:{cve}+country:{country_code}"
        else:
            query = f"vuln:{cve}"
        
        country = country if isinstance(country, str) else ''
        
        
        
        # URL-encode individual parts of the query string except for the '+'
        encoded_query = urllib.parse.quote_plus(query.replace('+', ' ')).replace('%20', '+')
        
        # Construct the Shodan API URL
        url = f"https://api.shodan.io/shodan/host/search?key={shodan_api_key}&query={encoded_query}&facets=city,port,org,product,os"
        
        # Print the query URL for debugging purposes
        print(f"DEBUG: Shodan API Query URL: {url}")
        
        response = requests.get(url)

        #print(f"DEBUG: Full Shodan API response: {response.json()}")
        
        # Check for a successful status code before proceeding
        if response.status_code != 200:
            print(f"Error: Received status code {response.status_code} from Shodan API")
            return {"results": "Error occurred."}
        
        #try:
            # Attempt to decode the JSON response
        data = response.json()
        # print(f"DEBUG: Shodan API response (truncated): {json.dumps(data)[:500]}")
        #print(f"DEBUG: Parsed JSON Data (Limited): {json.dumps(data.get('matches', [])[:2], indent=2)}")
        
        
        # Extract the total number of results
        total_results = data.get("total", 0)

        # Extract all facet information without limiting
        top_cities = data.get("facets", {}).get("city", [])
        top_ports = data.get("facets", {}).get("port", [])
        top_orgs = data.get("facets", {}).get("org", [])
        top_products = data.get("facets", {}).get("product", [])
        top_os = data.get("facets", {}).get("os", [])

        # Extract limited matches (limit to 1 or 2)
        limited_matches = data.get("matches", [])[:20]


        # Return both facets and the limited number of matches
        return {
            "total": total_results,
            "facets": {
                "total": total_results,
                "city": top_cities,
                "port": top_ports,
                "org": top_orgs,
                "product": top_products,
                "os": top_os
            },
            "matches": limited_matches
        }

    except requests.exceptions.RequestException as e:
        print(f"Error searching Shodan for CVE: {e}")
        return {"results": "Error occurred."}
    except json.JSONDecodeError as e:
        print(f"Error decoding Shodan JSON response: {e}")
        return {"results": "Error occurred."}



def search_shodan_org(org, status_output=None, progress_bar=None):
    # Ensure that org is stripped of any 'org:' prefix
    cleaned_org_name = org.replace('org:', '').strip()
    print(f"DEBUG: Searching Shodan for Organization: {cleaned_org_name}")

    # Proceed with making the Shodan API call using the cleaned_org_name
    query = f"org:{cleaned_org_name}"  # Using the cleaned name in the query
    print(f"DEBUG: search_shodan_org called with org = {cleaned_org_name}")

    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Searching Shodan for organization: {cleaned_org_name}...</b>'))
            display(progress_bar)

    try:
        print(f"DEBUG: Searching Shodan for Organization: {cleaned_org_name}")
        
        # URL-encode the query
        encoded_query = urllib.parse.quote_plus(query.replace('+', ' ')).replace('%20', '+')

        # Construct the Shodan API URL with the org filter
        url = f"https://api.shodan.io/shodan/host/search?key={shodan_api_key}&query={encoded_query}&facets=port,org"
        
        # Print the query URL for debugging purposes
        print(f"DEBUG: Shodan API Query URL: {url}")
        
        response = requests.get(url)

        # Check for a successful status code before proceeding
        if response.status_code != 200:
            print(f"Error: Received status code {response.status_code} from Shodan API")
            return {"results": "Error occurred."}

        # Decode the JSON response
        data = response.json()
        #print(f"DEBUG: Shodan API response: {data}")

        # Extract the total number of results
        total_results = data.get('total', 0)
        facets = data.get('facets', {})
        matches = data.get('matches', [])

        # Extract top ports and top organizations from the facets
        top_ports = facets.get("port", [])
        top_orgs = facets.get("org", [])

        # Process the matches section
        processed_matches = []
        for match in matches:
            processed_match = {
                "ip_str": match.get("ip_str", "N/A"),
                "port": match.get("port", "N/A"),
                "org": match.get("org", "N/A"),
                "asn": match.get("asn", "N/A"),
                "isp": match.get("isp", "N/A"),
                "product": match.get("product", "N/A"),
                "os": match.get("os", "N/A"),
                "domains": match.get("domains", []),
                "location": {
                    "city": match.get("location", {}).get("city", "N/A"),
                    "region_code": match.get("location", {}).get("region_code", "N/A"),
                    "country_name": match.get("location", {}).get("country_name", "N/A"),
                    "longitude": match.get("location", {}).get("longitude", "N/A"),
                    "latitude": match.get("location", {}).get("latitude", "N/A")
                },
                "snmp": match.get("snmp", {}),
                "ntp": match.get("ntp", {}),
                "data": match.get("data", "N/A"),
                "vulns": match.get("vulns", {})
            }
            processed_matches.append(processed_match)

        # Return the total, facets, and matches
        return {
            "total": total_results,
            "facets": {
                "port": top_ports,
                "org": top_orgs  # Extracting top organizations
            },
            "matches": processed_matches
        }

    except requests.exceptions.RequestException as e:
        print(f"Error searching Shodan for Organization: {e}")
        return {"results": "Error occurred."}
    except json.JSONDecodeError as e:
        print(f"Error decoding Shodan JSON response: {e}")
        return {"results": "Error occurred."}


def search_shodan_product_country(product, country, status_output=None, progress_bar=None):
    # Ensure that product is stripped of any 'prod:' prefix
    cleaned_product_name = product.replace('prod:', '').strip()

    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Searching Shodan for product: {cleaned_product_name} in {country if country else "any country"}...</b>'))
            display(progress_bar)
    
    print(f"DEBUG: Searching Shodan for product: {cleaned_product_name}, Country: {country}")

    try:
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
        
        # Handle case where no country or "All" is selected
        if country and country.lower() != "all":
            country_code = country_codes.get(country, '')
            query = f"product:{cleaned_product_name} country:{country_code}"
        else:
            query = f"product:{cleaned_product_name}"

        # URL-encode the query
        encoded_query = urllib.parse.quote_plus(query.replace('+', ' ')).replace('%20', '+')

        # Construct the Shodan API URL
        url = f"https://api.shodan.io/shodan/host/search?key={shodan_api_key}&query={encoded_query}&facets=city,port,org,product,os"
        
        # Print the query URL for debugging purposes
        print(f"DEBUG: Shodan API Query URL: {url}")
        
        # Make the API request
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for non-2xx responses

        data = response.json()
        #print(f"DEBUG: Shodan API response: {data}")
        
        # Check for matches
        if "matches" not in data or not data.get("matches"):
            return {"report": "N/A"}
        
        # Extract the total number of results
        total_results = data.get("total", 0)

        # Extract facet information
        top_cities = data.get("facets", {}).get("city", [])
        top_ports = data.get("facets", {}).get("port", [])
        top_orgs = data.get("facets", {}).get("org", [])
        top_products = data.get("facets", {}).get("product", [])
        top_os = data.get("facets", {}).get("os", [])

        # Extract matches
        limited_matches = data.get("matches", [])  # Limit to a few matches if needed

        # Return both facets and matches
        return {
            "total": total_results,
            "facets": {
                "total": total_results,
                "city": top_cities,
                "port": top_ports,
                "org": top_orgs,
                "product": top_products,
                "os": top_os
            },
            "matches": limited_matches
        }

    except requests.exceptions.RequestException as e:
        print(f"Error searching Shodan for product: {e}")
        return {"results": "Error occurred."}
    except json.JSONDecodeError as e:
        print(f"Error decoding Shodan JSON response: {e}")
        return {"results": "Error occurred."}

def search_shodan_by_port(port, country=None, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Searching Shodan for hosts with port: {port} in {country if country else "any country"}...</b>'))
            display(progress_bar)
    print(f"Searching Shodan for hosts with port: {port} in {country if country else 'any country'}")

    # Dictionary to map country names to their ISO 3166-1 alpha-2 country codes
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

    try:
        # Ensure the port is a string for query purposes
        port = str(port)

        # Convert country name to its ISO 3166-1 alpha-2 code if necessary
        country_code = country_codes.get(country, '') if country and country.lower() != "all" else ''

        # Construct the query based on whether a country is provided or not
        if country_code:
            query = f"port:{port} country:{country_code}"
        else:
            query = f"port:{port}"

        # URL-encode the query
        encoded_query = urllib.parse.quote_plus(query.replace('+', ' ')).replace('%20', '+')

        # Construct the Shodan API URL with the port filter and optional country filter
        url = f"https://api.shodan.io/shodan/host/search?key={shodan_api_key}&query={encoded_query}&facets=city,org,product"

        # Print the query URL for debugging purposes
        print(f"DEBUG: Shodan API Query URL: {url}")

        response = requests.get(url)

        # Check for a successful status code before proceeding
        if response.status_code != 200:
            print(f"Error: Received status code {response.status_code} from Shodan API")
            return {"results": "Error occurred."}

        # Attempt to decode the JSON response
        data = response.json()

        #print(f"DEBUG: Full Shodan API response: {json.dumps(data, indent=2)}")
        # Extract the total number of results
        total_results = data.get("total", 0)
        facets = data.get("facets", {})  # Ensure facets is extracted from the response safely
        matches = data.get("matches", [])

        # Extract facet information, such as top orgs, products, and cities
        top_orgs = facets.get("org", [])
        top_products = facets.get("product", [])  # Corrected to 'product'
        top_cities = facets.get("city", [])

        # Process the matches section
        processed_matches = []
        for match in matches:
            processed_match = {
                "ip_str": match.get("ip_str", "N/A"),
                "port": match.get("port", "N/A"),
                "org": match.get("org", "N/A"),
                "asn": match.get("asn", "N/A"),
                "isp": match.get("isp", "N/A"),
                "product": match.get("product", "N/A"),
                "os": match.get("os", "N/A"),
                "domains": match.get("domains", []),
                "location": {
                    "city": match.get("location", {}).get("city", "N/A"),
                    "region_code": match.get("location", {}).get("region_code", "N/A"),
                    "country_name": match.get("location", {}).get("country_name", "N/A"),
                    "longitude": match.get("location", {}).get("longitude", "N/A"),
                    "latitude": match.get("location", {}).get("latitude", "N/A")
                },
                "data": match.get("data", "N/A"),
                "vulns": match.get("vulns", [])
            }

            # Add the processed match to the list
            processed_matches.append(processed_match)

        # Return both facets and the processed matches
        return {
            "total": total_results,
            "facets": {
                "org": top_orgs,
                "product": top_products,  # Corrected to 'product'
                "city": top_cities
            },
            "matches": processed_matches
        }

    except requests.exceptions.RequestException as e:
        print(f"Error searching Shodan for Port: {e}")
        return {"results": "Error occurred."}
    except json.JSONDecodeError as e:
        print(f"Error decoding Shodan JSON response: {e}")
        return {"results": "Error occurred."}

def search_shodan_product_in_country(product, country, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Searching Shodan for product: {product} in {country}...</b>'))
            display(progress_bar)
    
    print(f"Searching Shodan for product: {product} in {country}")
    
    try:
        # Map country names to their ISO 3166-1 alpha-2 country codes
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

        # Convert country name to its ISO 3166-1 alpha-2 code
        country_code = country_codes.get(country, '')

        if not country_code:
            raise ValueError(f"Country '{country}' not recognized or unsupported.")

        # Build the Shodan query for the product and country
        query = f"product:{product} country:{country_code}"
        
        # URL-encode the query
        encoded_query = urllib.parse.quote_plus(query.replace('+', ' ')).replace('%20', '+')

        # Construct the Shodan API URL
        url = f"https://api.shodan.io/shodan/host/search?key={shodan_api_key}&query={encoded_query}&facets=city,port,org,product"

        # Print the query URL for debugging purposes
        print(f"DEBUG: Shodan API Query URL: {url}")

        # Send the request
        response = requests.get(url)
        response.raise_for_status()

        # Decode the JSON response
        data = response.json()
        #print(f"DEBUG: Full Shodan API response: {json.dumps(data, indent=2)[:20000]}...")

        facets = data.get("facets", {})

        # Extract the total number of results
        total_results = data.get("total", 0)

        # Extract facet information for top cities, orgs, and products
        top_cities = facets.get("city", [])
        top_ports = facets.get("port", [])
        top_orgs = facets.get("org", [])
        top_products = facets.get("product", [])  # Versions are in "product" facet

        # Process the matches section
        matches = data.get("matches", [])
        processed_matches = []
        for match in matches:
            processed_match = {
                "ip_str": match.get("ip_str", "N/A"),
                "port": match.get("port", "N/A"),
                "org": match.get("org", "N/A"),
                "asn": match.get("asn", "N/A"),
                "isp": match.get("isp", "N/A"),
                "product": match.get("product", "N/A"),
                "os": match.get("os", "N/A"),
                "domains": match.get("domains", []),
                "location": {
                    "city": match.get("location", {}).get("city", "N/A"),
                    "region_code": match.get("location", {}).get("region_code", "N/A"),
                    "country_name": match.get("location", {}).get("country_name", "N/A"),
                    "longitude": match.get("location", {}).get("longitude", "N/A"),
                    "latitude": match.get("location", {}).get("latitude", "N/A")
                },
                #"data": match.get("data", "N/A"),
                "vulns": match.get("opts", {}).get("vulns", [])
            }

            # Add the processed match to the list
            processed_matches.append(processed_match)

        # Return the processed matches, limited to 5 results for control
        return {
            "total": data.get("total", 0),
            "matches": processed_matches[:5]  # Limit to 5 matches for output control
        }

    except requests.exceptions.RequestException as e:
        print(f"Error searching Shodan for Product: {e}")
        return {"results": "Error occurred."}
    except json.JSONDecodeError as e:
        print(f"Error decoding Shodan JSON response: {e}")
        return {"results": "Error occurred."}


def search_shodan_product_port_country(product, port=None, country=None, status_output=None, progress_bar=None):
    try:
        # Map country names to their ISO 3166-1 alpha-2 country codes
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

        # Convert country name to its ISO 3166-1 alpha-2 code
        country_code = country_codes.get(country, '')

        if country and not country_code:
            raise ValueError(f"Country '{country}' not recognized or unsupported.")

        # Construct the query
        query = f"product:{product}"
        if port:
            query += f" port:{port}"
        if country_code:
            query += f" country:{country_code}"

        # URL encode the query
        encoded_query = urllib.parse.quote(query)
        url = f"https://api.shodan.io/shodan/host/search?key={shodan_api_key}&query={encoded_query}&facets=org"

        print(f"DEBUG: Shodan API Query URL: {url}")

        if status_output:
            with status_output:
                clear_output(wait=True)
                display(HTML(f'<b>Shodan querying product {product}, port {port}, country {country}...</b>'))
                display(progress_bar)

        # Make the request
        response = requests.get(url)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error querying Shodan: {response.status_code}")
            return {"error": response.text}

        facets = data.get("facets", {})

        # Extract the total number of results
        total_results = data.get("total", 0)

        # Extract facet information for top cities, orgs, and products
        top_orgs = facets.get("org", [])

    except requests.exceptions.RequestException as e:
        print(f"Error searching Shodan for Product: {e}")
        return {"results": "Error occurred."}
    except json.JSONDecodeError as e:
        print(f"Error decoding Shodan JSON response: {e}")
        return {"results": "Error occurred."}