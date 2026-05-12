#!/usr/bin/env python3
"""
███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗██╗    ██╗ ██████╗ ██╗     ███████╗
████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██║    ██║██╔═══██╗██║     ██╔════╝
██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║ █╗ ██║██║   ██║██║     █████╗  
██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║███╗██║██║   ██║██║     ██╔══╝  
██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚███╔███╔╝╚██████╔╝███████╗██║     
╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚══════╝╚═╝     
                    OSINT Intelligence Framework  |  by Limox
"""

import sys
import os
import json
import time
import hashlib
import re
import socket
import urllib.parse
import argparse
from datetime import datetime

# --- Dependency Check ---
try:
    import requests
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.columns import Columns
    from rich import box
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] Please install required packages: pip3 install -r requirements.txt")
    sys.exit(1)

console = Console()

BANNER = """[bold cyan]
███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗██╗    ██╗ ██████╗ ██╗     ███████╗
████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██║    ██║██╔═══██╗██║     ██╔════╝
██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║ █╗ ██║██║   ██║██║     █████╗  
██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║███╗██║██║   ██║██║     ██╔══╝  
██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚███╔███╔╝╚██████╔╝███████╗██║     
╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚══════╝╚═╝     
[/bold cyan][dim]              OSINT Intelligence Framework  |  by Limox Cypher[/dim]
"""

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
})


# ─────────────────────────────────────────────────
#  UTILITIES
# ─────────────────────────────────────────────────

def section(title):
    console.print(f"\n[bold yellow]  ◈  {title}[/bold yellow]")
    console.print(f"[dim]  {'─' * 50}[/dim]")

def info(label, value, color="white"):
    console.print(f"  [dim]›[/dim] [cyan]{label:<22}[/cyan] [bold {color}]{value}[/bold {color}]")

def warn(msg):
    console.print(f"  [bold yellow][!][/bold yellow] {msg}")

def ok(msg):
    console.print(f"  [bold green][✓][/bold green] {msg}")

def err(msg):
    console.print(f"  [bold red][✗][/bold red] {msg}")

def spinner_task(label):
    return Progress(SpinnerColumn(style="cyan"), TextColumn(f"[dim]{label}[/dim]"), transient=True)

def save_results(target, data):
    safe = re.sub(r'[^\w\-]', '_', str(target))
    fname = f"nw_{safe}_{int(time.time())}.json"
    with open(fname, "w") as f:
        json.dump(data, f, indent=2, default=str)
    ok(f"Results saved → [bold]{fname}[/bold]")


# ─────────────────────────────────────────────────
#  EMAIL OSINT
# ─────────────────────────────────────────────────

def osint_email(email):
    results = {"target": email, "type": "email", "timestamp": str(datetime.now())}

    console.print(Panel(f"[bold cyan]TARGET:[/bold cyan] [white]{email}[/white]", 
                        title="[bold]EMAIL OSINT[/bold]", border_style="cyan"))

    # Basic validation
    section("Validation & Structure")
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    valid = bool(re.match(pattern, email))
    info("Format Valid", "✓ Yes" if valid else "✗ No", "green" if valid else "red")
    if not valid:
        err("Invalid email format. Aborting.")
        return

    username, domain = email.split("@", 1)
    info("Username", username)
    info("Domain", domain)

    # MD5/SHA1 hash (for Gravatar / breach DB lookup)
    md5 = hashlib.md5(email.lower().encode()).hexdigest()
    sha1 = hashlib.sha1(email.lower().encode()).hexdigest()
    info("MD5 Hash", md5, "dim")
    info("SHA1 Hash", sha1, "dim")
    results["md5"] = md5
    results["sha1"] = sha1

    # Gravatar check
    section("Gravatar Check")
    try:
        grav_url = f"https://www.gravatar.com/avatar/{md5}?d=404"
        r = SESSION.get(grav_url, timeout=8)
        if r.status_code == 200:
            ok(f"Gravatar profile EXISTS → https://www.gravatar.com/{md5}")
            results["gravatar"] = True
        else:
            warn("No Gravatar found")
            results["gravatar"] = False
    except requests.exceptions.RequestException as e:
        err(f"Gravatar check failed: {e}")

    # Domain MX / DNS info
    section("Domain Intelligence")
    try:
        ip = socket.gethostbyname(domain)
        info("Domain resolves to", ip, "green")
        results["domain_ip"] = ip
    except socket.gaierror:
        warn("Could not resolve domain IP")

    try:
        mx = subprocess.run(["host", "-t", "MX", domain], capture_output=True, text=True, timeout=5)
        if mx.returncode == 0 and mx.stdout.strip():
            for line in mx.stdout.strip().splitlines():
                if "mail" in line.lower() or "mx" in line.lower():
                    info("MX Record", line.split()[-1] if line.split() else line)
        else:
            warn("No MX records found or host command failed.")
    except FileNotFoundError:
        warn("host command not found. Please install dnsutils (e.g., sudo apt install dnsutils).")
    except subprocess.TimeoutExpired:
        warn("MX record lookup timed out.")
    except Exception as e:
        err(f"MX record lookup failed: {e}")

    # WHOIS on domain
    section("WHOIS (Domain)")
    try:
        w = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=10)
        if w.returncode == 0 and w.stdout.strip():
            keys = ["Registrar:", "Creation Date:", "Updated Date:", "Expiry Date:", 
                    "Registrant Name:", "Registrant Country:", "Name Server:"]
            seen = set()
            for line in w.stdout.splitlines():
                for k in keys:
                    if k.lower() in line.lower() and k not in seen:
                        val = line.split(":", 1)[-1].strip()
                        if val:
                            info(k.replace(":", ""), val)
                            seen.add(k)
        else:
            warn("WHOIS lookup failed or returned no data.")
    except FileNotFoundError:
        warn("whois command not found. Please install whois (e.g., sudo apt install whois).")
    except subprocess.TimeoutExpired:
        warn("WHOIS lookup timed out.")
    except Exception as e:
        err(f"WHOIS failed: {e}")

    # Social media username search based on email username
    section("Username → Social Recon")
    console.print(f"  [dim]Searching username:[/dim] [bold cyan]{username}[/bold cyan]")
    _social_search(username, results)

    # Breach check hint
    section("Data Breach Check")
    console.print(f"  [dim]Check manually (API key required for some services):[/dim]")
    info("HaveIBeenPwned", f"https://haveibeenpwned.com/account/{urllib.parse.quote(email)}")
    info("Dehashed", f"https://dehashed.com/search?query={urllib.parse.quote(email)}")
    info("LeakCheck", f"https://leakcheck.io/search?query={urllib.parse.quote(email)}")
    info("IntelX", f"https://intelx.io/?s={urllib.parse.quote(email)}")

    # Google dork links
    section("Google Dork Links")
    dorks = [
        (f'"{email}"', "Direct mention"),
        (f'"{email}" site:linkedin.com', "LinkedIn"),
        (f'"{email}" site:github.com', "GitHub"),
        (f'"{email}" filetype:pdf OR filetype:doc', "Documents"),
        (f'"{email}" password OR leak OR breach', "Leak mentions"),
    ]
    for dork, label in dorks:
        url = f"https://www.google.com/search?q={urllib.parse.quote(dork)}"
        info(label, url)

    save_results(email, results)


# ─────────────────────────────────────────────────
#  PHONE OSINT
# ─────────────────────────────────────────────────

def osint_phone(phone):
    results = {"target": phone, "type": "phone", "timestamp": str(datetime.now())}

    console.print(Panel(f"[bold cyan]TARGET:[/bold cyan] [white]{phone}[/white]",
                        title="[bold]PHONE OSINT[/bold]", border_style="cyan"))

    section("Parsing & Validation")
    try:
        parsed = phonenumbers.parse(phone, None)
        valid = phonenumbers.is_valid_number(parsed)
        possible = phonenumbers.is_possible_number(parsed)

        info("Valid Number", "✓ Yes" if valid else "✗ No", "green" if valid else "red")
        info("Possible Number", "✓ Yes" if possible else "Maybe Not", "green" if possible else "yellow")
        info("E.164 Format", phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164))
        info("International", phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
        info("National", phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL))
        info("Country Code", f"+{parsed.country_code}")
        info("National Number", str(parsed.national_number))

        country = geocoder.description_for_number(parsed, "en")
        carrier_name = carrier.name_for_number(parsed, "en")
        timezones = timezone.time_zones_for_number(parsed)
        num_type = phonenumbers.number_type(parsed)

        type_map = {
            0: "Fixed Line", 1: "Mobile", 2: "Fixed/Mobile", 3: "Toll Free",
            4: "Premium Rate", 6: "VOIP", 7: "Personal", 99: "Unknown"
        }

        info("Location/Country", country or "Unknown", "green" if country else "yellow")
        info("Carrier", carrier_name or "Unknown", "green" if carrier_name else "yellow")
        info("Line Type", type_map.get(num_type, "Unknown"))
        info("Timezone(s)", ", ".join(timezones) if timezones else "Unknown")

        results.update({
            "valid": valid, "country": country, "carrier": carrier_name,
            "timezones": list(timezones), "type": type_map.get(num_type, "Unknown")
        })

    except phonenumbers.phonenumberutil.NumberParseException as e:
        err(f"Could not parse number: {e}")
        warn("Tip: Include country code, e.g. +977XXXXXXXXXX for Nepal")
        return

    # Truecaller / NumLookup hints
    section("Reverse Lookup Resources")
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    plain = e164.replace("+", "")
    info("Truecaller", f"https://www.truecaller.com/search/np/{plain}")
    info("NumLookup", f"https://www.numlookup.com/?number={urllib.parse.quote(e164)}")
    info("SpyDialer", f"https://www.spydialer.com/default.aspx?search={plain}")
    info("Sync.me", f"https://sync.me/search/?number={urllib.parse.quote(e164)}")
    info("IntelX", f"https://intelx.io/?s={urllib.parse.quote(e164)}")

    # Social media
    section("Social Platform Search")
    info("WhatsApp Check", f"https://wa.me/{plain}")
    info("Telegram Search", f"https://t.me/{plain}")
    info("Viber", f"viber://add?number={plain}")

    # Google dorks
    section("Google Dork Links")
    dorks = [
        (f'"{e164}"', "E.164 mention"),
        (f'"{plain}" site:linkedin.com', "LinkedIn"),
        (f'"{e164}" OR "{phone}" leak OR breach', "Leak mentions"),
    ]
    for dork, label in dorks:
        url = f"https://www.google.com/search?q={urllib.parse.quote(dork)}"
        info(label, url)

    save_results(phone.replace("+", ""), results)


# ─────────────────────────────────────────────────
#  NAME OSINT
# ─────────────────────────────────────────────────

def osint_name(name):
    results = {"target": name, "type": "name", "timestamp": str(datetime.now())}

    console.print(Panel(f"[bold cyan]TARGET:[/bold cyan] [white]{name}[/white]",
                        title="[bold]NAME OSINT[/bold]", border_style="cyan"))

    section("Name Analysis")
    parts = name.strip().split()
    info("Full Name", name)
    info("Parts Detected", str(len(parts)))
    if len(parts) >= 2:
        info("First Name", parts[0])
        info("Last Name", parts[-1])
        if len(parts) == 3:
            info("Middle Name", parts[1])

    # Social platforms
    section("Social Media Search Links")
    enc = urllib.parse.quote(name)
    socials = [
        ("Facebook", f"https://www.facebook.com/search/people/?q={enc}"),
        ("LinkedIn", f"https://www.linkedin.com/search/results/people/?keywords={enc}"),
        ("Twitter/X", f"https://twitter.com/search?q={enc}&f=user"),
        ("Instagram", f"https://www.instagram.com/explore/tags/{enc.replace('%20','')}"),
        ("GitHub", f"https://github.com/search?q={enc}&type=users"),
        ("TikTok", f"https://www.tiktok.com/search/user?q={enc}"),
        ("YouTube", f"https://www.youtube.com/results?search_query={enc}"),
        ("Reddit", f"https://www.reddit.com/search/?q={enc}&type=user"),
        ("Pinterest", f"https://www.pinterest.com/search/users/?q={enc}"),
        ("Snapchat", f"https://www.snapchat.com/add/{enc.replace('%20','')}"),
    ]
    for platform, url in socials:
        info(platform, url)

    # People search engines
    section("People Search Engines")
    people = [
        ("Spokeo", f"https://www.spokeo.com/search?q={enc}"),
        ("Pipl", f"https://pipl.com/search/?q={enc}"),
        ("Intelius", f"https://intelius.com/search/name/{enc.replace('%20','+')}"),
        ("BeenVerified", f"https://www.beenverified.com/f/search/people?fname={parts[0]}&lname={parts[-1] if len(parts)>1 else ''}"),
        ("FastPeopleSearch", f"https://www.fastpeoplesearch.com/name/{enc.replace('%20','-')}"),
        ("TruePeopleSearch", f"https://www.truepeoplesearch.com/results?name={enc}"),
        ("WhitePages", f"https://www.whitepages.com/name/{enc.replace('%20','+')}"),
    ]
    for site, url in people:
        info(site, url)

    # Username permutations
    section("Username Permutations (for Username Search)")
    if len(parts) >= 2:
        fn, ln = parts[0].lower(), parts[-1].lower()
        usernames = [
            f"{fn}{ln}", f"{fn}.{ln}", f"{fn}_{ln}",
            f"{fn[0]}{ln}", f"{fn}{ln[0]}", f"{ln}{fn}",
            f"{fn[0]}.{ln}", f"_{fn}{ln}_", f"{fn}{ln}99",
            f"{ln}.{fn}", f"real{fn}{ln}", f"the{fn}{ln}",
        ]
        console.print(f"  [dim]Possible usernames:[/dim]")
        for u in usernames:
            console.print(f"    [cyan]•[/cyan] {u}")
        results["username_permutations"] = usernames

    # Google dorks
    section("Google Dork Links")
    dorks = [
        (f'"{name}"', "Direct name"),
        (f'"{name}" site:linkedin.com', "LinkedIn"),
        (f'"{name}" site:facebook.com', "Facebook"),
        (f'"{name}" email OR contact', "Contact info"),
        (f'"{name}" resume OR CV', "Resume/CV"),
        (f'"{name}" phone OR mobile OR number', "Phone"),
        (f'"{name}" address OR location OR lives', "Location"),
        (f'"{name}" filetype:pdf', "PDF Documents"),
    ]
    for dork, label in dorks:
        url = f"https://www.google.com/search?q={urllib.parse.quote(dork)}"
        info(label, url)

    save_results(name.replace(" ", "_"), results)


# ─────────────────────────────────────────────────
#  USERNAME OSINT
# ─────────────────────────────────────────────────

PLATFORMS = [
    ("GitHub",          "https://github.com/{}"),
    ("Twitter/X",       "https://twitter.com/{}"),
    ("Instagram",       "https://www.instagram.com/{}"),
    ("TikTok",          "https://www.tiktok.com/@{}"),
    ("Reddit",          "https://www.reddit.com/user/{}"),
    ("Pinterest",       "https://www.pinterest.com/{}"),
    ("Twitch",          "https://www.twitch.tv/{}"),
    ("YouTube",         "https://www.youtube.com/@{}"),
    ("Snapchat",        "https://www.snapchat.com/add/{}"),
    ("Telegram",        "https://t.me/{}"),
    ("Medium",          "https://medium.com/@{}"),
    ("Dev.to",          "https://dev.to/{}"),
    ("Keybase",         "https://keybase.io/{}"),
    ("GitLab",          "https://gitlab.com/{}"),
    ("Bitbucket",       "https://bitbucket.org/{}"),
    ("Pastebin",        "https://pastebin.com/u/{}"),
    ("Replit",          "https://replit.com/@{}"),
    ("HackTheBox",      "https://app.hackthebox.com/users/{}"),
    ("TryHackMe",       "https://tryhackme.com/p/{}"),
    ("HackerOne",       "https://hackerone.com/{}"),
    ("Bugcrowd",        "https://bugcrowd.com/{}"),
    ("ProductHunt",     "https://www.producthunt.com/@{}"),
    ("AngelList",       "https://angel.co/u/{}"),
    ("Steam",           "https://steamcommunity.com/id/{}"),
    ("Spotify",         "https://open.spotify.com/user/{}"),
    ("SoundCloud",      "https://soundcloud.com/{}"),
    ("Behance",         "https://www.behance.net/{}"),
    ("Dribbble",        "https://dribbble.com/{}"),
    ("Fiverr",          "https://www.fiverr.com/{}"),
    ("Etsy",            "https://www.etsy.com/people/{}"),
    ("Gravatar",        "https://en.gravatar.com/{}"),
    ("About.me",        "https://about.me/{}"),
    ("Linktree",        "https://linktr.ee/{}"),
]

def _social_search(username, results=None):
    found = []
    not_found = []
    errors = []

    console.print(f"\n  [dim]Probing {len(PLATFORMS)} platforms...[/dim]\n")

    table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE_HEAVY,
                  show_lines=False, padding=(0, 1))
    table.add_column("Status", width=8, justify="center")
    table.add_column("Platform", width=16)
    table.add_column("URL", style="dim")

    for platform, url_template in PLATFORMS:
        url = url_template.format(username)
        try:
            r = SESSION.get(url, timeout=6, allow_redirects=True)
            # Improved check: look for common 'not found' indicators or specific content
            if r.status_code == 200 and "page not found" not in r.text.lower() and "profile not found" not in r.text.lower():
                table.add_row("[bold green]FOUND[/bold green]", f"[cyan]{platform}[/cyan]", url)
                found.append({"platform": platform, "url": url})
            elif r.status_code in [404, 410]:
                table.add_row("[dim]404[/dim]", f"[dim]{platform}[/dim]", url)
                not_found.append(platform)
            else:
                # Generic status code, might be a soft 404 or other issue
                table.add_row(f"[yellow]{r.status_code}[/yellow]", f"[yellow]{platform}[/yellow]", url)
                errors.append(platform)
        except requests.exceptions.Timeout:
            table.add_row("[red]TOUT[/red]", f"[dim]{platform}[/dim]", url)
            errors.append(platform)
        except requests.exceptions.RequestException as e:
            table.add_row("[red]ERR[/red]", f"[dim]{platform}[/dim]", url)
            errors.append(platform)
        time.sleep(0.15)  # polite delay

    console.print(table)
    console.print(f"\n  [bold green]Found:[/bold green] {len(found)}  "
                  f"[dim]Not found:[/dim] {len(not_found)}  "
                  f"[yellow]Errors/unknown:[/yellow] {len(errors)}")

    if results is not None:
        results["social_found"] = found


def osint_username(username):
    results = {"target": username, "type": "username", "timestamp": str(datetime.now())}

    console.print(Panel(f"[bold cyan]TARGET:[/bold cyan] [white]{username}[/white]",
                        title="[bold]USERNAME OSINT[/bold]", border_style="cyan"))

    section("Platform Enumeration")
    _social_search(username, results)

    section("Google Dork Links")
    enc = urllib.parse.quote(username)
    dorks = [
        (f'"{username}"', "Direct mention"),
        (f'inurl:"{username}"', "URL contains"),
        (f'"{username}" email OR contact', "Contact info"),
        (f'"{username}" site:pastebin.com OR site:hastebin.com', "Pastes"),
        (f'"{username}" password OR credentials OR leaked', "Credential leaks"),
    ]
    for dork, label in dorks:
        url = f"https://www.google.com/search?q={urllib.parse.quote(dork)}"
        info(label, url)

    save_results(username, results)


# ─────────────────────────────────────────────────
#  IP OSINT
# ─────────────────────────────────────────────────

def osint_ip(ip):
    results = {"target": ip, "type": "ip", "timestamp": str(datetime.now())}

    console.print(Panel(f"[bold cyan]TARGET:[/bold cyan] [white]{ip}[/white]",
                        title="[bold]IP OSINT[/bold]", border_style="cyan"))

    section("IP Geolocation (ip-api.com)")
    try:
        # Requesting specific fields to reduce data transfer and improve clarity
        r = SESSION.get(f"http://ip-api.com/json/{ip}?fields=query,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting", timeout=8)
        data = r.json()
        if data.get("status") == "success":
            fields = [
                ("IP", data.get("query")),
                ("Country", f"{data.get('country')} ({data.get('countryCode')})"),
                ("Region", data.get("regionName")),
                ("City", data.get("city")),
                ("ZIP", data.get("zip")),
                ("Lat/Lon", f"{data.get('lat')}, {data.get('lon')}"),
                ("Timezone", data.get("timezone")),
                ("ISP", data.get("isp")),
                ("Organization", data.get("org")),
                ("AS Number", data.get("as")),
                ("ASName", data.get("asname")),
                ("Reverse DNS", data.get("reverse") or "N/A"),
                ("Mobile", str(data.get("mobile"))),
                ("Proxy/VPN", str(data.get("proxy"))),
                ("Hosting", str(data.get("hosting"))),
            ]
            for label, val in fields:
                if val:
                    color = "green" if label in ["Country", "City", "ISP"] else "white"
                    if label in ["Proxy/VPN", "Mobile", "Hosting"]:
                        color = "yellow" if val == "True" else "dim"
                    info(label, str(val), color)
            results.update(data)
        else:
            warn(f"ip-api returned: {data.get('message', 'unknown error')}")
    except requests.exceptions.RequestException as e:
        err(f"Geolocation failed: {e}")

    section("Shodan / Threat Intel Links")
    info("Shodan", f"https://www.shodan.io/host/{ip}")
    info("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{ip}")
    info("AbuseIPDB", f"https://www.abuseipdb.com/check/{ip}")
    info("GreyNoise", f"https://viz.greynoise.io/ip/{ip}")
    info("Censys", f"https://search.censys.io/hosts/{ip}")
    info("IPInfo", f"https://ipinfo.io/{ip}")
    info("ThreatBook", f"https://threatbook.io/ip/{ip}")

    section("Reverse DNS")
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        info("Hostname", hostname, "green")
        results["hostname"] = hostname
    except socket.herror:
        warn("No reverse DNS found")
    except Exception as e:
        err(f"Reverse DNS lookup failed: {e}")

    section("Port Scan Hint")
    console.print("  [dim]Run a quick scan:[/dim]")
    console.print(f"  [cyan]nmap -sV -T4 --top-ports 1000 {ip}[/cyan]")
    console.print(f"  [cyan]nmap -sC -sV -O -p- {ip}[/cyan]")

    save_results(ip.replace(".", "_"), results)


# ─────────────────────────────────────────────────
#  DOMAIN OSINT
# ─────────────────────────────────────────────────

def osint_domain(domain):
    results = {"target": domain, "type": "domain", "timestamp": str(datetime.now())}

    console.print(Panel(f"[bold cyan]TARGET:[/bold cyan] [white]{domain}[/white]",
                        title="[bold]DOMAIN OSINT[/bold]", border_style="cyan"))

    import subprocess

    section("DNS Records")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    for rtype in record_types:
        try:
            r = subprocess.run(["dig", "+short", rtype, domain],
                               capture_output=True, text=True, timeout=5)
            if r.stdout.strip():
                info(f"{rtype} Record", r.stdout.strip().replace("\n", " | "))
            else:
                warn(f"No {rtype} records found or dig command failed.")
        except FileNotFoundError:
            warn("dig command not found. Please install dnsutils (e.g., sudo apt install dnsutils).")
            break # No point in trying other dig commands if not found
        except subprocess.TimeoutExpired:
            warn(f"{rtype} record lookup timed out.")
        except Exception as e:
            err(f"{rtype} record lookup failed: {e}")

    section("WHOIS")
    try:
        w = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=10)
        if w.returncode == 0 and w.stdout.strip():
            keys = ["Registrar:", "Creation Date:", "Updated Date:", "Registry Expiry Date:",
                    "Registrant Name:", "Registrant Email:", "Registrant Country:",
                    "Admin Email:", "Name Server:"]
            seen = set()
            for line in w.stdout.splitlines():
                for k in keys:
                    if k.lower() in line.lower() and k not in seen:
                        val = line.split(":", 1)[-1].strip()
                        if val and len(val) > 1:
                            info(k.replace(":", ""), val)
                            seen.add(k)
        else:
            warn("WHOIS lookup failed or returned no data.")
    except FileNotFoundError:
        warn("whois command not found. Please install whois (e.g., sudo apt install whois).")
    except subprocess.TimeoutExpired:
        warn("WHOIS lookup timed out.")
    except Exception as e:
        err(f"WHOIS failed: {e}")

    section("IP Resolution")
    try:
        ip = socket.gethostbyname(domain)
        info("Resolves to IP", ip, "green")
        results["ip"] = ip
        # Quick geo
        r = SESSION.get(f"http://ip-api.com/json/{ip}?fields=country,city,isp,org,as", timeout=6)
        geo = r.json()
        if geo.get("status") == "success":
            info("Country", geo.get("country", ""))
            info("City", geo.get("city", ""))
            info("ISP/Org", geo.get("isp", ""))
        else:
            warn(f"ip-api returned: {geo.get('message', 'unknown error')}")
    except socket.gaierror:
        warn("Could not resolve domain IP")
    except requests.exceptions.RequestException as e:
        err(f"IP Geolocation failed: {e}")
    except Exception as e:
        err(f"IP Resolution failed: {e}")

    section("Subdomain Recon Links")
    info("crt.sh (Certs)", f"https://crt.sh/?q=%25.{domain}")
    info("DNSDumpster", f"https://dnsdumpster.com/")
    info("Shodan", f"https://www.shodan.io/search?query=hostname%3A{domain}")
    info("Censys", f"https://search.censys.io/search?resource=hosts&q={domain}")
    info("VirusTotal", f"https://www.virustotal.com/gui/domain/{domain}")
    info("URLScan", f"https://urlscan.io/search/#domain%3A{domain}")
    info("SecurityTrails", f"https://securitytrails.com/domain/{domain}/dns")
    info("Wayback Machine", f"https://web.archive.org/web/*/{domain}")

    section("Google Dork Links")
    dorks = [
        (f"site:{domain}", "All indexed pages"),
        (f"site:{domain} filetype:pdf", "PDFs"),
        (f"site:{domain} inurl:admin OR inurl:login", "Admin panels"),
        (f"site:{domain} filetype:sql OR filetype:env OR filetype:log", "Sensitive files"),
        (f"site:{domain} password OR credentials OR secret", "Secrets"),
    ]
    for dork, label in dorks:
        url = f"https://www.google.com/search?q={urllib.parse.quote(dork)}"
        info(label, url)

    save_results(domain.replace(".", "_"), results)


# ─────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────

def main():
    console.print(BANNER)

    parser = argparse.ArgumentParser(
        description="NightWolf OSINT Intelligence Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument('-e', '--email', type=str, help='Investigate an email address')
    parser.add_argument('-p', '--phone', type=str, help='Investigate a phone number (e.g., +15551234567)')
    parser.add_argument('-n', '--name', type=str, help='Investigate a person\'s name (e.g., "John Doe")')
    parser.add_argument('-u', '--username', type=str, help='Hunt a username across 30+ platforms')
    parser.add_argument('-i', '--ip', type=str, help='Investigate an IP address')
    parser.add_argument('-d', '--domain', type=str, help='Investigate a domain')

    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(0)

    try:
        if args.email:
            osint_email(args.email)
        elif args.phone:
            osint_phone(args.phone)
        elif args.name:
            osint_name(args.name)
        elif args.username:
            osint_username(args.username)
        elif args.ip:
            osint_ip(args.ip)
        elif args.domain:
            osint_domain(args.domain)
    except KeyboardInterrupt:
        console.print("\n\n[bold red]  Interrupted by user.[/bold red]")
        sys.exit(0)
    except Exception as e:
        err(f"An unexpected error occurred: {e}")
        sys.exit(1)

    console.print(f"\n[dim]  NightWolf OSINT | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")


if __name__ == "__main__":
    # Import subprocess here to avoid circular dependency with rich.console in some environments
    import subprocess 
    main()
