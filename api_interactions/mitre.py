import requests
import json
from IPython.display import clear_output, HTML, display  # Added import

def get_mitre_cve_details(cve_id, status_output=None, progress_bar=None):
    MITRE_API_URL = f"https://cveawg.mitre.org/api/cve/{cve_id}"

    headers = {
        "User-Agent": "YourAppName/1.0 (YourEmail@example.com)"
    }

    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'Fetching MITRE report for {cve_id}'))
            display(progress_bar)
        print(f"Fetching MITRE report for {cve_id}")

    try:
        response = requests.get(MITRE_API_URL, headers=headers)
        response.raise_for_status()
        
        data = response.json()

        # Debug print to show the full JSON response from MITRE
        #print(f"DEBUG: MITRE JSON response for {cve_id}: {json.dumps(data, indent=2)}")

        # Extracting fields based on the JSON structure
        cve_metadata = data.get("cveMetadata", {})
        cna = data.get("containers", {}).get("cna", {})
        adp = data.get("containers", {}).get("adp", [])

        report = {
            "cve_id": cve_metadata.get("cveId", "N/A"),
            "assigner_org_id": cve_metadata.get("assignerOrgId", "N/A"),
            "state": cve_metadata.get("state", "N/A"),
            "assigner_short_name": cve_metadata.get("assignerShortName", "N/A"),
            "date_reserved": cve_metadata.get("dateReserved", "N/A"),
            "date_published": cve_metadata.get("datePublished", "N/A"),
            "date_updated": cve_metadata.get("dateUpdated", "N/A"),
            "title": cna.get("title", "N/A"),
            "source": cna.get("source", {}).get("advisory", "N/A"),
            "affected_products": [
                {
                    "product": item.get("product", "N/A"),
                    "vendor": item.get("vendor", "N/A"),
                    "modules": item.get("modules", []),
                    "platforms": item.get("platforms", []),
                    "repo": item.get("repo", "N/A"),
                    "versions": [
                        {
                            "version": version.get("version", "N/A"),
                            "lessThan": version.get("lessThan", "N/A"),
                            "status": version.get("status", "N/A"),
                            "versionType": version.get("versionType", "N/A")
                        } for version in item.get("versions", [])
                    ]
                } for item in cna.get("affected", [])
            ],
            "description": next((desc.get("value", "N/A") for desc in cna.get("descriptions", []) if desc.get("lang", "en") == "en"), "N/A"),
            "cvss_v3_1": cna.get("metrics", [{}])[0].get("cvssV3_1", {}),
            "problem_types": [
                {
                    "cwe_id": desc.get("cweId", "N/A"),
                    "description": desc.get("description", "N/A")
                } for problem in cna.get("problemTypes", []) for desc in problem.get("descriptions", [])
            ],
            "references": [ref.get("url", "N/A") for ref in cna.get("references", [])],
            "adp_info": [
                {
                    "title": adp_item.get("title", "N/A"),
                    "timeline": [
                        {
                            "time": event.get("time", "N/A"),
                            "description": event.get("value", "N/A")
                        } for event in adp_item.get("timeline", [])
                    ],
                    "affected_products": [
                        {
                            "vendor": product.get("vendor", "N/A"),
                            "product": product.get("product", "N/A"),
                            "cpes": product.get("cpes", [])
                        } for product in adp_item.get("affected", [])
                    ]
                } for adp_item in adp
            ]
        }

        return report

    except requests.exceptions.RequestException as e:
        print(f"Error fetching MITRE report for CVE: {cve_id}: {e}")
        return {"report": "Error occurred."}
    except json.JSONDecodeError as e:
        print(f"Error decoding MITRE JSON response for {cve_id}: {e}")
        return {"report": "Error occurred."}