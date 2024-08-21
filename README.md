# Infra-Validation

A Security Operations Center (SOC) analyst’s role is to monitor an organization’s computer systems, identify suspicious activity or security breaches, and investigate whether they pose a real threat to the company.
However, a SOC often faces challenges when they spend time analyzing Indicators of Compromise (IOCs) that are not active or not malicious.  

Here are some of the issues:
+ **False Positives**: False positives can waste valuable time and resources as analysts investigate non-existent incidents. This can lead to SOC analysts spending a significant amount of time chasing down alerts that end up being harmless, reducing their efficiency and effectiveness.
+ **Resource Allocation**: The time spent on analyzing inactive or non-malicious IOCs could be better utilized for proactive threat hunting or improving the organization’s overall security posture. This misallocation of resources can impact the SOC’s ability to respond to actual threats in a timely manner.
+ **Alert Fatigue**: Constantly dealing with false positives can lead to alert fatigue, where analysts may start to ignore or overlook alerts due to the high volume of false positives. This can potentially lead to missed detections of actual threats.
+ **Skill Development**: Spending time on non-malicious IOCs can hinder the skill development of SOC analysts. Instead of gaining experience and knowledge from investigating real threats, they are spending time on irrelevant IOCs.
To tackle these issues effectively, implementing advanced analytics tools, developing robust filtering mechanisms, and leveraging automation technologies are crucial.
IOC validation is part of the strategy that can help reduce the number of false positives and allow SOC analysts to focus on more critical tasks.

---

# Description

This conjunction of Python scripts is designed for security analysts, researchers, and enthusiasts, facilitating automated interactions with multiple cybersecurity APIs including VirusTotal, MalwareBazaar, and AbuseIPDB. The tool automates the process of sending API requests to these platforms, handling requests and responses effectively. It is particularly useful for quickly gathering and analyzing data related to file hashes, IP addresses, or domain information, thereby streamlining tasks in cybersecurity analysis and research.

## Table of Contents
- [Description](#description)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Dependencies](#dependencies)
  - [Installation](#installation)
  - [Setting Up](#setting-up)
  - [API Keys Configuration](#api-keys-configuration)
- [Usage](#usage)
- [Future Improvements](#future-improvements)
- [Version History](#version-history)
- [Troubleshooting](#troubleshooting)
- [Testing](#testing)
- [Flow Chart](#flow-chart)
- [Big thanks!](#big-thanks)

## Features

- **VirusTotal API Integration**: Automate IP, URL/Domain and file hash queries and receive detailed analysis reports.
- **MalwareBazaar Access**: Easily check and retrieve data about various malware samples.
- **AbuseIPDB Lookup**: Quickly look up and analyze the reputation of IP addresses.
- **Shodan Report**: Additional reporting enhancement from Shodan.
- **IPQualityScore**: Checks IOC's for fraud activity and other reputation scoring.
- **AlienVault OTX**: Additional augmentation from AlienVault OTX, including pulses.
- **Grey Noise**: Has the IOC been seen by Grey Noise, what do they think?
- **Borealis**: Now open-source and integrated into the script. [08/19/2024]
- **Jupyter Notebook UI**: Still in development...
- **User-friendly Configuration**: Simple setup with API key configuration and easy-to-use functions.
- **Extensible Framework**: Designed for easy addition of more APIs or enhancement of existing functionalities.
- **Modular Design**: Functions are now separated into different modules for better maintainability and scalability. [12/03/2023]
- **Input Sanitization**: Enhanced input processing to remove unnecessary port numbers and other artifacts. [12/03/2023]
- **Output Sanitization**: IOC's in output reports are defanged for safe sharing. [07/11/2024]
- **Maliciousness Scoring**: The script will scan IOC's and if the available data from the last 14 days deems the IOC to be malicious, the IOC will be flagged as malicious in the verdict and give a score breakdown.

## Getting Started

### Dependencies

- Python 3.x
- `requests` library <i>(if not already installed in your environment)</i>

### Installation

**Disclaimer:** <i>This notebook will likely only run in an Unclassified environment as scans from this tool typically fail to breach the perimeter of a PB or higher network. This tool is also mostly non-attributable as it simply performs the same search a user does when visiting the validation sources website and performing the analysis/scan there.</i>

**Uploading .zip to JupyHub**: 

At this time the only way to install the notebook is by the following:
- Download the repository as an archive (.zip, .tar, etc)
- Upload the archive to JupyHub into the directory of your choice (Root directory recommended)
- Extract the archive:
   - `unzip infra-validation-<branch>.zip -d infra-validation` <-- your branch may vary depending on if you get the repo from main or dev
   - Then open the infra-validation directory in JupyHub and run `ioc_validator_ui.ipynb`

### Setting Up

Replace the API keys in the `api/api_keys.py`  with your own obtained from VirusTotal, MalwareBazaar, AbuseIPDB and other sources as described below.

### API Keys Configuration

The script requires API keys for all validation sources. Follow these steps to configure them:

1. **Obtain API Keys**:
   
   - Register and obtain an API key from [VirusTotal](https://www.virustotal.com/).
   - Do the same for [MalwareBazaar](https://bazaar.abuse.ch/) and [AbuseIPDB](https://www.abuseipdb.com/).
   - Other vendors will likely have a similar approach, most vendors have free but limited API access, granting enhanced features with paid API access.

2. **Configure the Script**:

   - Open the `api/api_keys.py` file in a text editor.
   - First three lines are for API keys [VirusTotal, MalwareBazaar and AbuseiPDB].
   - Replace the placeholder values with your actual API keys.

### Usage

This tool runs in a Jupyter Notebook and has a UI. All that's needed to get started is running the ioc_validator_ui.ipynb notebook.
Ensure you have the necessary API keys set up in api_keys.py.

**Here is a basic example of how to run the script**

**Run the UI notebook and choose option (ie. IP scan), enter your IOC and select whether to save the output to a file:**

![image](https://gitlab.chimera.cyber.gc.ca/kevin.kazienko/infra-validation/-/raw/main/validator_new_ui.png?ref_type=heads)

**Start validation process:**

![image](https://gitlab.chimera.cyber.gc.ca/kevin.kazienko/infra-validation/-/raw/main/progress_indicator.png?ref_type=heads)

**Script runs and scans given IOC(s) and provides a report:**

![image](https://gitlab.chimera.cyber.gc.ca/kevin.kazienko/infra-validation/-/raw/main/analysis_output_for_ip.png?ref_type=heads)

**Example Bulk Report for IP's:**
![image](https://gitlab.chimera.cyber.gc.ca/kevin.kazienko/infra-validation/-/raw/main/bulk_ips.png?ref_type=heads)

**Example Bulk Combined Report:**
![image](https://gitlab.chimera.cyber.gc.ca/kevin.kazienko/infra-validation/-/raw/main/bulk_combined.png?ref_type=heads)

## Future Improvements 

- [X] Integrate additional cybersecurity-related APIs to provide more comprehensive data analysis.
- [X] Searching for reliable Vendors.
- [X] Add support for different types of data, like threat intelligence feeds, DNS query information, and SSL certificate details.
- [X] Integrate Borealis for enhanced IOC augmentation.
- [ ] Optimize performance to handle large volumes of IOCs with minimal latency.

## Version History:
**V1**  
VirusTotal, AbuseIPDB and MalwareBazaar interaction.

**V1.5**  
Shodan, AlienVault, GreyNoise, IPQualityScore interaction.

**V1.8**  
Revamped reporting mechanism so analysis and bulk analysis are completely separate. Also added the beginnings of a UI for the scripts for each of use.

**V1.9**  
Added a companion notebook to add a UI element. Added URLScan API, as well as defanging for reports.

**V2.0**
Integrate Borealis search for further augmentation.