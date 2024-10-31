![image](https://github.com/kevinkazienko/The-Oracle/blob/main/The_Oracle_Banner_IOC_Validation_Tool2.jpg)
![image](https://github.com/kevinkazienko/The-Oracle/blob/main/oracle_logo.jpg)  

# The Oracle

A Security Operations Center (SOC) analyst’s role is to monitor an organization’s computer systems and networks, identify suspicious activity or security breaches and investigate whether they pose a real threat to the organization; however, a SOC often faces challenges spending time and resources analyzing Indicators of Compromise (IOCs) that are not active and no longer malicious or never were to begin with.

Here are some of the issues:
+ **False Positives**: False positives can waste valuable time and resources as analysts investigate non-existent incidents. This can lead to SOC analysts spending a significant amount of time chasing down alerts that end up being harmless, reducing their efficiency and effectiveness.
+ **Resource Allocation**: The time spent on analyzing inactive or non-malicious IOCs could be better utilized for proactive threat hunting or improving the organization’s overall security posture. This misallocation of resources can impact the SOC’s ability to respond to actual threats in a timely manner.
+ **Alert Fatigue**: Constantly dealing with false positives can lead to alert fatigue, where analysts may start to ignore or overlook alerts due to the high volume of false positives. This can potentially lead to missed detections of actual threats.
+ **Skill Development**: Spending time on non-malicious IOCs can hinder the skill development of SOC analysts. Instead of gaining experience and knowledge from investigating real threats, they are spending time on irrelevant IOCs.
To tackle these issues effectively, implementing advanced analytics tools, developing robust filtering mechanisms, and leveraging automation technologies are crucial.
IOC validation is part of the strategy that can help reduce the number of false positives and allow SOC analysts to focus on more critical tasks.

---

# Description

The Oracle is designed for security analysts, researchers and enthusiasts - facilitating automated interactions with multiple trusted cybersecurity APIs including VirusTotal, MalwareBazaar, AbuseIPDB, URLScan and more. It automates the process of sending API requests to these platforms, handling requests and responses effectively. Based on the IOC being scanned, The Oracle will review the reports from applicable vendors and calculate a malicious score based on relevant parts of the report which can be used to determine maliciousness and give a verdict if the data is fresh within the last 14 days stating whether the IOC is likely still active/malicous or not.

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

## Features

- **VirusTotal API Integration and Rescan Capability**: Automate IP, URL/Domain and file hash queries and receive detailed analysis reports. If the report received from VirusTotal isn't recent within the last 14 days, the IOC is automatically resubmitted for a rescan to ensure the most current results.
- **MalwareBazaar Access**: Easily check and retrieve data about various malware samples.
- **AbuseIPDB Lookup**: Quickly look up and analyze the reputation of IP addresses.
- **Shodan Contextual Report**: Additional reporting enhancement from Shodan.
- **IPQualityScore Reputation**: Checks IOC's for fraud activity and other reputation scoring. Severity 2 is currently in use for report data that is current within the past 14 days.
- **AlienVault OTX Contextual Report**: Additional augmentation from AlienVault OTX, including pulses.
- **Grey Noise Sighting**: Has the IOC been seen by Grey Noise, what do they think?
- **Borealis Integration**: Integrated into Borealis for enhanced IOC report augmentation.
- **MetaDefender Integration**: Integrated MetaDefender as a new source for validation.
- **User-friendly Configuration**: Simple setup with API key configuration and easy-to-use functions.
- **Extensible Framework**: Designed for easy addition of more APIs or enhancement of existing functionalities.
- **Modular Design**: Functions are now separated into different modules for better maintainability and scalability. [12/03/2023]
- **Input Sanitization**: Enhanced input processing to remove unnecessary port numbers and other artifacts. [12/03/2023]
- **Report Output Defanging**: Enhanced output reporting with IP and domain/URL de-weaponizing.
- **Automatic IOC Type Detection**: The script now automatically detects the type of IOC being searched.
- **Search CVE's**: Search for devices vulnerable to CVE's using Shodan's vuln filter. [10/25/2024]
- **Search Organizations**: Search Shodan using the org filter. [10/25/2024]
- **Search Port and Products**: Search by port number or product name and country. [10/29/2024]

## Getting Started

### Dependencies

- Python 3.x
- `requests` library

### Installation

1. **Clone the Repository**: 

   * Download the zip archive to your system
   * Upload the zip archive to your Jupyhub U (Unclassified) instance <b><u><i> NOT PB</b></u></i>
   * Once the archive is uploaded, open a new tab and select Terminal
   * From the Terminal, type the following command  
   ``unzip The-Oracle-main.zip``
   
    

<!-- 2. **Install Dependencies**: <i> Typically not required</i>

    If you haven't installed the `requests` library, you can do so by running:

    ```bash
    pip install requests
    ```
3. **Check Requirements.txt**

   You can always run:
   ```bash
   pip install -r requirements.txt
   ```
   It will install requirements to run this script. -->

## Set Up

### API Keys Configuration

The script requires API keys for all validation sources. CCCS (Canadian Center for Cyber Security) has an enterprise subscription to several of them including VirusTotal, Censys and Shodan. You'll need to figure out getting your account added to the subscription or just use your work email to create an account and work with the "personal" api key you receive (<i>may limit results</i>). MalwareBazaar, AbuseIPDB, etc are fine to use personal API keys. 

Replace the placeholders with your actual API keys in the `api/api_keys.py`.

Links to the registration pages for all validation sources can be found in the Wiki.

### Usage

To use this tool, simply run the script with Python.
Ensure you have the necessary API keys set up in the script.

**Here is a basic example of how to run the script:**

**Script start:** <i> Run the The Oracle-UI.ipynb notebook enter IOC and click Start Validation

<i>Note: The UI accepts fanged or defanged raw input, file upload or Jupyhub local storage via input_files directory.</i>

![image](https://github.com/kevinkazienko/The-Oracle/blob/main/Screenshot%202024-10-03%20131252.png)

**Script run:** Completion results in final report for IOC

![image](https://github.com/kevinkazienko/The-Oracle/blob/main/Screenshot%202024-10-03%20131316.png
)


**Score Breakdown**

![image](https://github.com/kevinkazienko/The-Oracle/blob/main/Screenshot%202024-10-10%20060914.png)

## Future Improvements  

- [X] Integrate additional cybersecurity-related APIs to provide more comprehensive data analysis. 
- [X] Searching for reliable Vendors
- [ ] Add support for different types of data, like threat intelligence feeds, DNS query information, and SSL certificate details.
- [ ] Optimize performance to handle large volumes of IOCs with minimal latency.
- [ ] MISP integration.

## Version History:

**V1**  
VirusTotal, AbuseIPDB and MalwareBazaar interaction.

**V1.5**  
Shodan, AlienVault, GreyNoise, IPQualityScore interaction.

**V2**  
Added BinaryEdge, Borealis, new UI

**V2.1**  
Added UI support for light/dark mode

**V2.5**  
Revamped UI, auto IOC type detection for searches.

**V2.9.7**
Added Port, Product, Organization and CVE search capabilities for Shodan and Censys.

**V2.9.9**
Added BinaryEdge to Port and Product searches.