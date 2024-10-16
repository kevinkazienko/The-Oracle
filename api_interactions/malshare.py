import requests
import json
from datetime import datetime
import time
from IPython.display import clear_output, HTML, display
from api.api_keys import malshare_api_key

# Base URL for Malshare API
MALSHARE_BASE_URL = "https://malshare.com/api.php"


# Function to get hash report with real-time status and progress
# Base URL for Malshare API
MALSHARE_BASE_URL = "https://malshare.com/api.php"

# Function to get hash report with real-time status and progress
def get_malshare_hash_report(file_hash, status_output=None, progress_bar=None):
    print(f"Fetching Malshare report for {file_hash}.")
    
    # Correct URL to fetch hash details
    url = f"{MALSHARE_BASE_URL}?api_key={malshare_api_key}&action=details&hash={file_hash}"
    print(f"Request URL: {url}")
    
    try:
        response = requests.get(url)
        
        if response.status_code == 200:
            report = response.json()
            #print(f"Malshare Response Data: {json.dumps(report, indent=4)}")

            if report:
                # Extract relevant fields from the report
                file_name = report.get("FILENAMES", ["N/A"])[0]
                md5 = report.get("MD5", "N/A")
                sha1 = report.get("SHA1", "N/A")
                sha256 = report.get("SHA256", "N/A")
                file_type = report.get("F_TYPE", "N/A")

                return {
                    "file_name": file_name,
                    "md5": md5,
                    "sha1": sha1,
                    "sha256": sha256,
                    "file_type": file_type,
                    "report_data": report  # Full report for further analysis
                }
            else:
                print(f"No report found for hash {file_hash}")
                return None
        else:
            print(f"Failed to fetch Malshare report for {file_hash}. Status Code: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None
