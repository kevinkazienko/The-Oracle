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
            'Afghanistan': 'AF',
            'Albania': 'AL',
            'Algeria': 'DZ',
            'Andorra': 'AD',
            'Angola': 'AO',
            'Antigua and Barbuda': 'AG',
            'Argentina': 'AR',
            'Armenia': 'AM',
            'Australia': 'AU',
            'Austria': 'AT',
            'Azerbaijan': 'AZ',
            'Bahamas': 'BS',
            'Bahrain': 'BH',
            'Bangladesh': 'BD',
            'Barbados': 'BB',
            'Belarus': 'BY',
            'Belgium': 'BE',
            'Belize': 'BZ',
            'Benin': 'BJ',
            'Bhutan': 'BT',
            'Bolivia': 'BO',
            'Bosnia and Herzegovina': 'BA',
            'Botswana': 'BW',
            'Brazil': 'BR',
            'Brunei': 'BN',
            'Bulgaria': 'BG',
            'Burkina Faso': 'BF',
            'Burundi': 'BI',
            'Cabo Verde': 'CV',
            'Cambodia': 'KH',
            'Cameroon': 'CM',
            'Canada': 'CA',
            'Central African Republic': 'CF',
            'Chad': 'TD',
            'Chile': 'CL',
            'China': 'CN',
            'Colombia': 'CO',
            'Comoros': 'KM',
            'Congo (Congo-Brazzaville)': 'CG',
            'Costa Rica': 'CR',
            'Croatia': 'HR',
            'Cuba': 'CU',
            'Cyprus': 'CY',
            'Czech Republic': 'CZ',
            'Democratic Republic of the Congo': 'CD',
            'Denmark': 'DK',
            'Djibouti': 'DJ',
            'Dominica': 'DM',
            'Dominican Republic': 'DO',
            'Ecuador': 'EC',
            'Egypt': 'EG',
            'El Salvador': 'SV',
            'Equatorial Guinea': 'GQ',
            'Eritrea': 'ER',
            'Estonia': 'EE',
            'Eswatini': 'SZ',
            'Ethiopia': 'ET',
            'Fiji': 'FJ',
            'Finland': 'FI',
            'France': 'FR',
            'Gabon': 'GA',
            'Gambia': 'GM',
            'Georgia': 'GE',
            'Germany': 'DE',
            'Ghana': 'GH',
            'Greece': 'GR',
            'Grenada': 'GD',
            'Guatemala': 'GT',
            'Guinea': 'GN',
            'Guinea-Bissau': 'GW',
            'Guyana': 'GY',
            'Haiti': 'HT',
            'Honduras': 'HN',
            'Hungary': 'HU',
            'Iceland': 'IS',
            'India': 'IN',
            'Indonesia': 'ID',
            'Iran': 'IR',
            'Iraq': 'IQ',
            'Ireland': 'IE',
            'Israel': 'IL',
            'Italy': 'IT',
            'Jamaica': 'JM',
            'Japan': 'JP',
            'Jordan': 'JO',
            'Kazakhstan': 'KZ',
            'Kenya': 'KE',
            'Kiribati': 'KI',
            'Kuwait': 'KW',
            'Kyrgyzstan': 'KG',
            'Laos': 'LA',
            'Latvia': 'LV',
            'Lebanon': 'LB',
            'Lesotho': 'LS',
            'Liberia': 'LR',
            'Libya': 'LY',
            'Liechtenstein': 'LI',
            'Lithuania': 'LT',
            'Luxembourg': 'LU',
            'Madagascar': 'MG',
            'Malawi': 'MW',
            'Malaysia': 'MY',
            'Maldives': 'MV',
            'Mali': 'ML',
            'Malta': 'MT',
            'Marshall Islands': 'MH',
            'Mauritania': 'MR',
            'Mauritius': 'MU',
            'Mexico': 'MX',
            'Micronesia': 'FM',
            'Moldova': 'MD',
            'Monaco': 'MC',
            'Mongolia': 'MN',
            'Montenegro': 'ME',
            'Morocco': 'MA',
            'Mozambique': 'MZ',
            'Myanmar (Burma)': 'MM',
            'Namibia': 'NA',
            'Nauru': 'NR',
            'Nepal': 'NP',
            'Netherlands': 'NL',
            'New Zealand': 'NZ',
            'Nicaragua': 'NI',
            'Niger': 'NE',
            'Nigeria': 'NG',
            'North Korea': 'KP',
            'North Macedonia': 'MK',
            'Norway': 'NO',
            'Oman': 'OM',
            'Pakistan': 'PK',
            'Palau': 'PW',
            'Palestine': 'PS',
            'Panama': 'PA',
            'Papua New Guinea': 'PG',
            'Paraguay': 'PY',
            'Peru': 'PE',
            'Philippines': 'PH',
            'Poland': 'PL',
            'Portugal': 'PT',
            'Qatar': 'QA',
            'Romania': 'RO',
            'Russia': 'RU',
            'Rwanda': 'RW',
            'Saint Kitts and Nevis': 'KN',
            'Saint Lucia': 'LC',
            'Saint Vincent and the Grenadines': 'VC',
            'Samoa': 'WS',
            'San Marino': 'SM',
            'Sao Tome and Principe': 'ST',
            'Saudi Arabia': 'SA',
            'Senegal': 'SN',
            'Serbia': 'RS',
            'Seychelles': 'SC',
            'Sierra Leone': 'SL',
            'Singapore': 'SG',
            'Slovakia': 'SK',
            'Slovenia': 'SI',
            'Solomon Islands': 'SB',
            'Somalia': 'SO',
            'South Africa': 'ZA',
            'South Korea': 'KR',
            'South Sudan': 'SS',
            'Spain': 'ES',
            'Sri Lanka': 'LK',
            'Sudan': 'SD',
            'Suriname': 'SR',
            'Sweden': 'SE',
            'Switzerland': 'CH',
            'Syria': 'SY',
            'Taiwan': 'TW',
            'Tajikistan': 'TJ',
            'Tanzania': 'TZ',
            'Thailand': 'TH',
            'Timor-Leste': 'TL',
            'Togo': 'TG',
            'Tonga': 'TO',
            'Trinidad and Tobago': 'TT',
            'Tunisia': 'TN',
            'Turkey': 'TR',
            'Turkmenistan': 'TM',
            'Tuvalu': 'TV',
            'Uganda': 'UG',
            'Ukraine': 'UA',
            'United Arab Emirates': 'AE',
            'United Kingdom': 'GB',
            'United States': 'US',
            'Uruguay': 'UY',
            'Uzbekistan': 'UZ',
            'Vanuatu': 'VU',
            'Vatican City': 'VA',
            'Venezuela': 'VE',
            'Vietnam': 'VN',
            'Yemen': 'YE',
            'Zambia': 'ZM',
            'Zimbabwe': 'ZW'
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
        limited_matches = data.get("matches", [])[:10]


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
    print(f"DEBUG: search_shodan_org called with org = {org}")
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Searching Shodan for organization: {org}...</b>'))
            display(progress_bar)
    
    print(f"Searching Shodan for organization: {org}")
    
    try:
        print(f"DEBUG: Searching Shodan for Organization: {org}")
        
        # Ensure org is a valid string before proceeding
        org = org if isinstance(org, str) else ''
        
        # Construct the Shodan query for the organization
        query = f"org:{org}"

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
        
        # Attempt to decode the JSON response
        data = response.json()
        #print(f"DEBUG: Full Shodan JSON Response: {json.dumps(data, indent=2)}")

        # Extract the total number of results
        total_results = data.get("total", 0)
        facets = data.get("facets", {})  # Ensure facets is extracted from the response safely
        matches = data.get("matches", [])

        # Extract facet information, such as top ports and orgs
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

            # Add the processed match to the list
            processed_matches.append(processed_match)

        # Debugging output for clarity
        # print(f"DEBUG: Total Results: {total_results}")
        # print(f"DEBUG: Facets: {json.dumps(facets, indent=2)}")
        # print(f"DEBUG: Processed Matches: {json.dumps(processed_matches, indent=2)}")

        # Return both facets and the processed matches
        return {
            "total": total_results,
            "facets": {
                "total": total_results,
                "port": top_ports,
                "org": top_orgs
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
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'<b>Searching Shodan for product: {product} in {country}...</b>'))
            display(progress_bar)
    print(f"Searching Shodan for product: {product} within country: {country}")
    
    try:
        # Build the Shodan API URL and params
        query = f"product:{product} country:{country}"
        params = {
            "key": shodan_api_key,
            "query": query
        }
        url = "https://api.shodan.io/shodan/host/search"
        response = requests.get(url, params=params)
        response.raise_for_status()

        data = response.json()
        
        # Check for matches
        if "matches" not in data or not data.get("matches"):
            return {"report": "N/A"}
        
        # Extract individual host results
        results = []
        for match in data["matches"]:
            ip_address = match.get("ip_str", "N/A")
            open_ports = ", ".join(str(port) for port in match.get("ports", []))
            organization = match.get("org", "N/A")
            asn = match.get("asn", "N/A")
            city = match.get("location", {}).get("city", "N/A")
            country_name = match.get("location", {}).get("country_name", "N/A")
            timestamp = match.get("timestamp", "N/A")

            results.append({
                "IP": ip_address,
                "Open Ports": open_ports,
                "Organization": organization,
                "ASN": asn,
                "City": city,
                "Country": country_name,
                "Product": product,
                "Last Update": timestamp
            })

        return {"results": results}

    except requests.exceptions.RequestException as e:
        print(f"Error searching Shodan for product: {e}")
        return {"report": "N/A"}
    except json.JSONDecodeError as e:
        print(f"Error decoding Shodan JSON response: {e}")
        return {"report": "N/A"}