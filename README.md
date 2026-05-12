# NightWolf OSINT Framework

![NightWolf Banner](https://github.com/parbatzone/NightWolf-OSINT/blob/main/nightwold_pic.png)

## Introduction

NightWolf OSINT (Open Source Intelligence) Framework is a powerful and versatile Python-based tool designed for gathering publicly available information on various targets. It automates the process of querying multiple online resources and presents the findings in a structured, easy-to-read format while saving results to JSON files for further analysis.

This tool is intended for:

* Security researchers
* Penetration testers
* Ethical hackers
* OSINT investigators
* Students learning cybersecurity

---

## Features

NightWolf OSINT includes multiple intelligence-gathering modules:

| Module         | Description                                                           |
| -------------- | --------------------------------------------------------------------- |
| Email OSINT    | Investigate publicly available information related to email addresses |
| Phone OSINT    | Gather phone-related public intelligence and carrier details          |
| Name OSINT     | Search publicly available information using full names                |
| Username OSINT | Search usernames across multiple social platforms                     |
| IP OSINT       | Collect geolocation and network information from IP addresses         |
| Domain OSINT   | Perform WHOIS lookups, DNS checks, and domain intelligence gathering  |

---

## Installation

Follow these steps to install NightWolf OSINT:

### 1. Clone the Repository

```bash
git clone https://github.com/parbatzone/NightWolf-OSINT.git
cd NightWolf-OSINTsss
```

### 2. Install Python Dependencies

Make sure Python 3 and pip are installed.

```bash
pip3 install -r requirements.txt --break-system-packages
```

### 3. Install System Dependencies

For Debian/Ubuntu/Kali Linux:

```bash
sudo apt update
sudo apt install dnsutils whois -y
```

### 4. Make the Script Executable

```bash
chmod +x nightwolf.py
```

---

## Usage

NightWolf uses `argparse` for command-line interaction.

### General Syntax

```bash
./nightwolf.py [MODULE_FLAG] [TARGET]
```

---

## Available Modules

### Email OSINT

* Flag: `-e` or `--email`

Example:

```bash
./nightwolf.py -e target@example.com
```

---

### Phone OSINT

* Flag: `-p` or `--phone`

Example:

```bash
./nightwolf.py -p +15551234567
```

---

### Name OSINT

* Flag: `-n` or `--name`

Example:

```bash
./nightwolf.py -n "John Doe"
```

---

### Username OSINT

* Flag: `-u` or `--username`

Example:

```bash
./nightwolf.py -u limox_cypher
```

---

### IP OSINT

* Flag: `-i` or `--ip`

Example:

```bash
./nightwolf.py -i 1.1.1.1
```

---

### Domain OSINT

* Flag: `-d` or `--domain`

Example:

```bash
./nightwolf.py -d google.com
```

---

## Output

All scan results are automatically saved in JSON format.

Example output filename:

```bash
nw_target_2026-05-12_18-00-00.json
```

---

## Help Menu

To display the built-in help menu:

```bash
./nightwolf.py --help
```

or simply:

```bash
./nightwolf.py
```

---

## Important Notes

### Legal & Ethical Use

This tool is intended strictly for:

* Educational purposes
* Authorized penetration testing
* CTF competitions
* Ethical OSINT investigations

Always obtain proper authorization before investigating targets you do not own.

### API Keys

Some advanced OSINT services may require API keys. Those services are not automatically integrated into the framework.

### Rate Limiting

Be aware that some services may temporarily block or rate-limit excessive requests.

---

## Improvements Made

Recent improvements include:

* Migration from `sys.argv` to `argparse`
* Improved dependency handling
* Better network error handling
* Enhanced username detection logic
* Cleaner JSON output formatting
* More readable code structure
* Better warning and error messages

---

## License

This project is licensed under the MIT License.

See the `LICENSE` file for more information.

---

## Acknowledgements

* Original Author: **Limox Cypher**

---

## Disclaimer

The developers are not responsible for any misuse of this software.

Use responsibly and legally.
