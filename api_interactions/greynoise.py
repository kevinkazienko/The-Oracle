import requests
from api.api_keys import greynoise_api_key  # Your GreyNoise API key
from IPython.display import clear_output, HTML, display  # Added import

def get_greynoise_report(ip, status_output=None, progress_bar=None):
    if status_output:
        with status_output:
            clear_output(wait=True)
            display(HTML(f'Fetching GreyNoise report {ip}'))
            display(progress_bar)
    print(f"Fetching GreyNoise report {ip}")
    try:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {
            "key": greynoise_api_key
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        data = response.json()

        if data.get("error"):
            return {"error": data["error"]}

        report = {
            "ip": data.get("ip", "N/A"),
            "noise": data.get("noise", "N/A"),
            "riot": data.get("riot", "N/A"),
            "classification": data.get("classification", "N/A"),
            "name": data.get("name", "N/A"),
            "link": data.get("link", "N/A"),
            "last_seen": data.get("last_seen", "N/A"),
            "message": data.get("message", "N/A"),
            "first_seen": data.get("first_seen", "N/A")
        }

        if data.get("noise"):
            report.update({
                "actor": data.get("actor", "N/A"),
                "category": data.get("category", "N/A"),
                "cve": data.get("cve", []),
                "raw_data": data.get("raw_data", "N/A"),
                "tags": data.get("tags", [])
            })

        return report

    except requests.exceptions.RequestException as e:
        print(f"Error getting GreyNoise report: {e}")
        return {"error": f"Error getting GreyNoise report"}