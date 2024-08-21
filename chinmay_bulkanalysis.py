import time
import json

def bulk_analysis(iocs, output_file_path=None, delay=5):
    all_combined_reports = {}  # Dictionary to hold reports for each IOC type
    malicious_iocs = []

    # Define custom delays for each API
    api_delays = {
        "VirusTotal": 0.5,   # Adjust as per your enterprise rate limits
        "AbuseIPDB": 1,      # Adjust as per your enterprise rate limits
        "Shodan": 0.2,       # Adjust as per your enterprise rate limits
        "AlienVault": 0.3,   # Adjust as per your enterprise rate limits
        "IPQualityScore": 1, # Adjust as per your enterprise rate limits
        "GreyNoise": 0.5,    # Adjust as per your enterprise rate limits
    }

    # Function to add a report to the summary
    def add_report(summary, category, entry, report_name, report):
        if category not in summary:
            summary[category] = {}
        if entry not in summary[category]:
            summary[category][entry] = {}
        summary[category][entry][report_name] = report

    # Function to extract summary data from the reports
    def extract_summary_data(reports):
        summary = {}
        for category, entries in reports.items():
            summary[category] = []
            for entry, report_data in entries.items():
                entry_summary = {"entry": entry}
                vt_report = report_data.get("VirusTotal")
                if vt_report:
                    vt_malicious = vt_report['data']['attributes']['last_analysis_stats']['malicious']
                    entry_summary["VirusTotal"] = f"Malicious Score: {vt_malicious}"
                if "AbuseIPDB" in report_data:
                    entry_summary["AbuseIPDB"] = report_data["AbuseIPDB"].get("report", "N/A")
                if "Shodan" in report_data:
                    entry_summary["Shodan"] = report_data["Shodan"].get("report", "N/A")
                if "AlienVault" in report_data:
                    entry_summary["AlienVault"] = report_data["AlienVault"].get("report", "N/A")
                if "IPQualityScore" in report_data:
                    ipqs_report = report_data["IPQualityScore"]
                    tor_status = ipqs_report.get("tor", "Unknown")
                    fraud_score = ipqs_report.get("fraud_score", "Unknown")
                    entry_summary["IPQualityScore"] = f"Tor: {tor_status}, Fraud Score: {fraud_score}"
                if "GreyNoise" in report_data:
                    entry_summary["GreyNoise"] = report_data["GreyNoise"].get("report", "N/A")

                summary[category].append(entry_summary)
        return summary

    # Scan and Fetch Reports
    summary_reports = {}

    for category, entries in iocs.items():
        if entries:
            print(f"Processing {category.upper()}...")
            for count, entry in enumerate(entries, start=1):
                print(f"\nScanning {category.capitalize()} [{count}/{len(entries)}]: {entry}")

                # Fetch all reports for this IOC, with delays
                if category == "ips":
                    report_vt_ip = get_ip_report(entry)
                    time.sleep(api_delays["VirusTotal"])
                    add_report(summary_reports, category, entry, "VirusTotal", report_vt_ip)

                    report_abuseipdb = get_abuseipdb_report(entry)
                    time.sleep(api_delays["AbuseIPDB"])
                    add_report(summary_reports, category, entry, "AbuseIPDB", report_abuseipdb)

                    report_shodan = get_shodan_report(entry)
                    time.sleep(api_delays["Shodan"])
                    add_report(summary_reports, category, entry, "Shodan", report_shodan)

                    report_otx = get_alienvault_report(entry)
                    time.sleep(api_delays["AlienVault"])
                    add_report(summary_reports, category, entry, "AlienVault", report_otx)

                    report_ipqualityscore = get_ipqualityscore_report(entry)
                    time.sleep(api_delays["IPQualityScore"])
                    add_report(summary_reports, category, entry, "IPQualityScore", report_ipqualityscore)

                    report_greynoise = get_greynoise_report(entry)
                    time.sleep(api_delays["GreyNoise"])
                    add_report(summary_reports, category, entry, "GreyNoise", report_greynoise)

                    if report_vt_ip:
                        malicious_score = report_vt_ip['data']['attributes']['last_analysis_stats']['malicious']
                        if malicious_score > 0:
                            malicious_iocs.append((entry, malicious_score))

                elif category == "hashes":
                    report_vt_hash = get_hash_report(entry)
                    time.sleep(delay)
                    add_report(summary_reports, category, entry, "VirusTotal", report_vt_hash)

                    report_mb = get_malwarebazaar_hash_report(entry)
                    time.sleep(delay)
                    add_report(summary_reports, category, entry, "MalwareBazaar", report_mb)

                    report_shodan = get_shodan_report(entry)
                    time.sleep(delay)
                    add_report(summary_reports, category, entry, "Shodan", report_shodan)

                    report_otx = get_alienvault_report(entry)
                    time.sleep(delay)
                    add_report(summary_reports, category, entry, "AlienVault", report_otx)

                    if report_vt_hash:
                        last_analysis_stats = report_vt_hash['data']['attributes']['last_analysis_stats']
                        malicious = last_analysis_stats['malicious']
                        if malicious > 0:
                            malicious_iocs.append((entry, malicious))

    # Sort and filter the top 5 malicious IOCs
    top_malicious_iocs = sorted(malicious_iocs, key=lambda x: x[1], reverse=True)[:5]

    # Generate the summary report
    summary_data = extract_summary_data(summary_reports)
    top_malicious_summary = {
        "top_malicious_iocs": top_malicious_iocs,
        "summary_reports": summary_data
    }

    if output_file_path:
        with open(output_file_path, 'w') as file:
            json.dump(top_malicious_summary, file, indent=4)
    else:
        print(json.dumps(top_malicious_summary, indent=4))

    return top_malicious_summary
