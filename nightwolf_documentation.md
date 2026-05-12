# NightWolf OSINT Framework - Usage Guide

## 1. Introduction

NightWolf OSINT (Open Source Intelligence) Framework is a Python-based tool designed for gathering publicly available information on various targets such as email addresses, phone numbers, names, usernames, IP addresses, and domains. It automates the process of querying multiple online resources and presents the findings in a structured, easy-to-read format, saving the results to JSON files for further analysis.

## 2. Features

NightWolf OSINT provides the following modules for intelligence gathering:

*   **Email OSINT**: Investigates an email address by validating its format, extracting username and domain, checking for Gravatar profiles, performing MX/DNS lookups, WHOIS queries on the domain, and generating Google Dork links for deeper searches.
*   **Phone OSINT**: Parses and validates phone numbers, extracts country, carrier, and timezone information, and provides links to reverse lookup services and social media platforms.
*   **Name OSINT**: Analyzes a person's name, suggests username permutations, and generates search links for social media platforms and people search engines.
*   **Username OSINT**: Hunts a given username across over 30 popular online platforms to identify associated profiles and generates Google Dork links.
*   **IP OSINT**: Performs IP geolocation using `ip-api.com`, provides links to threat intelligence platforms like Shodan and VirusTotal, and attempts reverse DNS lookups. It also suggests `nmap` commands for port scanning.
*   **Domain OSINT**: Gathers DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA), performs WHOIS lookups, resolves the domain to an IP address with quick geolocation, and provides links for subdomain reconnaissance and Google Dorking.

## 3. Prerequisites

Before using NightWolf OSINT, ensure you have the following installed on your Linux system:

*   **Python 3**: The script is written in Python 3.
*   **pip**: Python's package installer, used for installing Python dependencies.
*   **`dnsutils`**: A collection of DNS utilities, including `dig` and `host`, required for DNS record lookups. Install using your distribution's package manager (e.g., `sudo apt install dnsutils` on Debian/Ubuntu).
*   **`whois`**: A command-line client for WHOIS lookups, required for domain registration information. Install using your distribution's package manager (e.g., `sudo apt install whois` on Debian/Ubuntu).

## 4. Installation

Follow these steps to set up NightWolf OSINT:

1.  **Download the script**: Save the `nightwolf.py` file to your local machine.

2.  **Create `requirements.txt`**: Create a file named `requirements.txt` in the same directory as `nightwolf.py` with the following content:

    ```
    requests
    rich
    phonenumbers
    ```

3.  **Install Python dependencies**: Open your terminal, navigate to the directory where you saved the files, and run:

    ```bash
    sudo pip3 install -r requirements.txt --break-system-packages
    ```

4.  **Install system dependencies**: Install `dnsutils` and `whois` if you haven't already:

    ```bash
    sudo apt update
    sudo apt install dnsutils whois
    ```

5.  **Make the script executable**: Give execution permissions to the script:

    ```bash
    chmod +x nightwolf.py
    ```

## 5. Usage

NightWolf OSINT uses `argparse` for a user-friendly command-line interface. The general syntax is:

```bash
./nightwolf.py [MODULE_FLAG] [TARGET]
```

### Available Modules and Examples:

*   **Email OSINT**
    *   Flag: `-e` or `--email`
    *   Example: `./nightwolf.py -e target@example.com`

*   **Phone OSINT**
    *   Flag: `-p` or `--phone`
    *   Example: `./nightwolf.py -p +15551234567` (Include country code)

*   **Name OSINT**
    *   Flag: `-n` or `--name`
    *   Example: `./nightwolf.py -n 
"John Doe"


*   **Username OSINT**
    *   Flag: `-u` or `--username`
    *   Example: `./nightwolf.py -u limox_cypher`

*   **IP OSINT**
    *   Flag: `-i` or `--ip`
    *   Example: `./nightwolf.py -i 1.1.1.1`

*   **Domain OSINT**
    *   Flag: `-d` or `--domain`
    *   Example: `./nightwolf.py -d google.com`

### General Usage Notes:

*   **Help Menu**: Run `./nightwolf.py` without any arguments to display the help menu.
*   **Output**: All results are automatically saved in JSON format in the current directory. The filename will be `nw_[target]_[timestamp].json`.
*   **Error Handling**: The script includes improved error handling for network requests and external command execution. It will provide informative messages if a dependency is missing or a lookup fails.

## 6. Important Considerations

*   **Legal & Ethical Use**: This tool is intended for authorized testing, CTFs (Capture The Flag), and educational purposes only. Always obtain proper authorization before performing OSINT on targets you do not own.
*   **API Keys**: Some advanced OSINT checks (e.g., certain data breach services) may require API keys, which are not integrated into this script. Manual checks via the provided links are necessary for these cases.
*   **Rate Limiting**: Be mindful of rate limits imposed by various online services. Excessive requests may lead to temporary or permanent IP bans.

## 7. Improvements Made

*   **Argument Parsing**: Switched from `sys.argv` to `argparse` for robust and user-friendly command-line argument handling, including automatic help generation.
*   **Dependency Management**: Created a `requirements.txt` file for easier installation of Python dependencies. Improved the initial dependency check to guide users more effectively.
*   **Error Handling**: Added more specific `try-except` blocks for network requests (`requests.exceptions.RequestException`), DNS lookups (`socket.gaierror`), and external command execution (`subprocess.CalledProcessError`, `FileNotFoundError`, `subprocess.TimeoutExpired`).
*   **User Feedback**: Enhanced warning and error messages to provide clearer guidance to the user, especially when external commands like `whois` or `dig` are missing.
*   **Username Search Logic**: Improved the `_social_search` function to better identify 
non-existent profiles by checking for common "page not found" indicators in the response text, in addition to HTTP status codes.
*   **IP Geolocation Fields**: Explicitly requested specific fields from `ip-api.com` to ensure consistent and relevant data retrieval.
*   **Code Structure**: Minor refactorings for better readability and maintainability.
