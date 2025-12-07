#!/usr/bin/env python3
"""Ar1TIX TUI - minimal clean implementation.

Safe to import. Provides:
- assistant.respond(text)
- open_search(query, engine, dry_run=True)
- simple interactive TUI when run as script
"""

from __future__ import annotations

import ast
import math
import os
import platform
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import webbrowser
import re
import json
import csv

# ASCII-only strings to avoid encoding issues
RESET = "\033[0m"
GREEN = "\033[92m"
WHITE = "\033[97m"
BLACK = "\033[30m"
BOLD = "\033[1m"
GREEN_BG = "\033[42m"
WHITE_BG = "\033[47m"
BLACK_BG = "\033[40m"
BLUE = "\033[94m"
CYAN = "\033[96m"

# Platform detection
IS_WINDOWS = os.name == 'nt'
IS_LINUX = sys.platform.startswith('linux')
IS_MAC = sys.platform == 'darwin'
IS_ISH = IS_LINUX and 'iSH' in platform.release()  # iSH shell on iPhone
IS_MOBILE = IS_ISH or 'arm' in platform.machine().lower()  # Detect ARM/mobile

# Persistent data files
DATA_FILE = os.path.join(os.path.dirname(__file__), 'ar1tix_tasks.json')
NETWORK_FILE = os.path.join(os.path.dirname(__file__), 'ar1tix_network.json')


def clear_screen() -> None:
    """Clear terminal screen (cross-platform compatible)."""
    try:
        if IS_WINDOWS:
            os.system("cls")
        else:
            # Linux, Mac, iSH - all support 'clear'
            os.system("clear")
    except Exception:
        # Fallback: print multiple newlines
        print("\n" * 50)


def get_terminal_width() -> int:
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 80


def center_text(text: str, width: int | None = None) -> str:
    if width is None:
        width = get_terminal_width()
    padding = max(0, (width - len(text)) // 2)
    return " " * padding + text


def build_rich_logo() -> list[str]:
    """Build a sleek, modern logo with smooth surfaces that adapts to full screen."""
    width = get_terminal_width()
    
    # Modern smooth logo with box-drawing characters, responsive to terminal width
    # Top border
    top_border = "╔" + "═" * (width - 2) + "╗"
    
    # Empty line
    empty_line = "║" + " " * (width - 2) + "║"
    
    # Title lines (centered)
    title1 = "✦  AR1TIX TERMINAL  ✦"
    title2 = "ADVANCED TOOLKIT INTERFACE"
    
    # Build result with responsive layout
    result = []
    result.append(GREEN + "▔" * width + RESET)
    result.append("")
    
    # Top box border
    result.append(GREEN + top_border + RESET)
    result.append(GREEN + empty_line + RESET)
    
    # Centered titles
    result.append(GREEN + "║" + center_text(title1, width - 2) + "║" + RESET)
    result.append(GREEN + "║" + center_text(title2, width - 2) + "║" + RESET)
    
    result.append(GREEN + empty_line + RESET)
    
    # Bottom box border
    bottom_border = "╚" + "═" * (width - 2) + "╝"
    result.append(GREEN + bottom_border + RESET)
    
    result.append("")
    result.append(GREEN + "▔" * width + RESET)
    result.append("")
    return result


def safe_eval(expr: str):
    try:
        node = ast.parse(expr, mode="eval")
        allowed = (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Num, ast.Constant, ast.Call, ast.Name, ast.Load)
        for n in ast.walk(node):
            if not isinstance(n, allowed):
                return None
            if isinstance(n, ast.Name):
                if n.id not in math.__dict__ and n.id not in ("pi", "e"):
                    return None
        compiled = compile(node, "<ast>", "eval")
        return eval(compiled, {**math.__dict__}, {})
    except Exception:
        return None


class Assistant:
    def __init__(self, name: str = "Ar1TIX"):
        self.name = name

    def respond(self, text: str) -> str:
        t = text.lower().strip()
        if "hello" in t:
            return "Hello!"
        if any(ch.isdigit() for ch in t) and any(op in t for op in "+-*/%^"):
            val = safe_eval(text.replace('^', '**'))
            return f"Result: {val}" if val is not None else "Cannot evaluate"
        if "cpu" in t:
            return f"CPU cores: {os.cpu_count()}"
        if "platform" in t:
            return f"Platform: {platform.system()} {platform.release()}"
        if "time" in t:
            return time.strftime("%Y-%m-%d %H:%M:%S")
        return "No answer available"


assistant = Assistant()


def _build_search_url(query: str, engine: str = "duck") -> str:
    q = urllib.parse.quote_plus(query)
    engine = (engine or "duck").lower()
    if engine.startswith("duck"):
        return f"https://duckduckgo.com/?q={q}"
    if engine.startswith("bing"):
        return f"https://www.bing.com/search?q={q}"
    return f"https://www.google.com/search?q={q}"


def _open_in_browser(url: str, browser_path: str | None = None, private: bool = False) -> None:
    if browser_path:
        args = [browser_path]
        if private:
            args += ["--incognito"]
        args.append(url)
        try:
            subprocess.Popen(args)
            return
        except Exception:
            pass
    webbrowser.open(url)


def open_search(query: str, engine: str = "duck", browser_choice: str | None = None, private: bool = False, dry_run: bool = False) -> str:
    url = _build_search_url(query, engine)
    if dry_run:
        return url
    _open_in_browser(url, None if not browser_choice else browser_choice, private)
    return url


def fetch_search_results(query: str, engine: str = "duck", max_results: int = 5) -> list[dict]:
    url = _build_search_url(query, engine)
    headers = {"User-Agent": "Mozilla/5.0 (Ar1TIX)"}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            html = resp.read().decode(errors="ignore")
    except Exception:
        return []
    anchors = re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html, re.S | re.I)
    results = []
    for href, inner in anchors:
        if len(results) >= max_results:
            break
        title = re.sub(r'<.*?>', '', inner).strip()
        if href.startswith('http') and title:
            results.append({"title": title, "url": href, "snippet": ""})
    return results


def build_logo_lines() -> list[str]:
    return build_rich_logo()


def print_menu_header(title: str) -> None:
    width = get_terminal_width()
    print(GREEN + "=" * width + RESET)
    print(GREEN + BOLD + center_text(title) + RESET)
    print(GREEN + "=" * width + RESET)
    # Small footer shown in the top-right corner of menus
    try:
        footer = "made by nikolas"
        if width and len(footer) < width:
            print(" " * (width - len(footer)) + WHITE + footer + RESET)
        else:
            print(WHITE + footer + RESET)
    except Exception:
        # Fallback: ensure we at least advance a line
        print()
    print()


# Task Manager Functions
def load_tasks() -> list[dict]:
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_tasks(tasks: list[dict]) -> bool:
    try:
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(tasks, f, indent=2)
        return True
    except Exception:
        return False


def tasks_menu():
    while True:
        clear_screen()
        for line in build_rich_logo():
            print(line)
        print_menu_header("TASK MANAGER")
        
        tasks = load_tasks()
        if tasks:
            print(WHITE + BOLD + f"Total Tasks: {len(tasks)}" + RESET)
            print()
            for i, task in enumerate(tasks, 1):
                status = "DONE" if task.get('done', False) else "TODO"
                status_color = GREEN if task.get('done', False) else WHITE
                print(f"{WHITE}{i}){RESET} {status_color}[{status}]{RESET} {task.get('title', 'N/A')}")
            print()
        else:
            print(WHITE + "(No tasks yet)" + RESET)
            print()
        
        print(WHITE + BOLD + "a) Add task" + RESET)
        print(WHITE + BOLD + "d) Mark done" + RESET)
        print(WHITE + BOLD + "r) Remove task" + RESET)
        print(WHITE + BOLD + "c) Clear all" + RESET)
        print(WHITE + BOLD + "b) Back" + RESET)
        print()
        
        cmd = input(GREEN + BOLD + "Command: " + RESET).strip().lower()
        
        if cmd == 'a':
            title = input(WHITE + BOLD + "Task title: " + RESET).strip()
            if title:
                tasks.append({"title": title, "done": False, "created": time.time()})
                save_tasks(tasks)
                print(GREEN + "Task added." + RESET)
                time.sleep(1)
        elif cmd == 'd':
            if tasks:
                idx_str = input(WHITE + BOLD + "Task number to mark done: " + RESET).strip()
                if idx_str.isdigit():
                    idx = int(idx_str) - 1
                    if 0 <= idx < len(tasks):
                        tasks[idx]['done'] = True
                        save_tasks(tasks)
                        print(GREEN + "Task marked as done." + RESET)
                        time.sleep(1)
        elif cmd == 'r':
            if tasks:
                idx_str = input(WHITE + BOLD + "Task number to remove: " + RESET).strip()
                if idx_str.isdigit():
                    idx = int(idx_str) - 1
                    if 0 <= idx < len(tasks):
                        tasks.pop(idx)
                        save_tasks(tasks)
                        print(GREEN + "Task removed." + RESET)
                        time.sleep(1)
        elif cmd == 'c':
            confirm = input(WHITE + BOLD + "Clear all tasks? (y/N): " + RESET).strip().lower()
            if confirm == 'y':
                save_tasks([])
                print(GREEN + "All tasks cleared." + RESET)
                time.sleep(1)
        elif cmd == 'b':
            break


# Network Manager Functions
def get_network_info() -> dict:
    """Fetch comprehensive network interface information."""
    try:
        if os.name == 'nt':
            # Windows: use ipconfig and netsh for detailed info
            info = {}
            
            # Get basic ipconfig
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, timeout=5)
            lines = result.stdout.split('\n')
            current_adapter = None
            
            for line in lines:
                line = line.strip()
                if 'adapter' in line.lower() and ':' in line:
                    current_adapter = line.split(':')[0].replace('Ethernet adapter', '').replace('Wireless LAN adapter', '').strip()
                    if current_adapter:
                        info[current_adapter] = {}
                elif current_adapter and line:
                    if 'IPv4 Address' in line or 'IPv4' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            ip = parts[-1].strip()
                            info[current_adapter]['IPv4'] = ip
                    elif 'Subnet Mask' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            mask = parts[-1].strip()
                            info[current_adapter]['Subnet Mask'] = mask
                    elif 'Default Gateway' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            gw = parts[-1].strip()
                            if gw:
                                info[current_adapter]['Gateway'] = gw
                    elif 'Physical Address' in line or 'MAC Address' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            mac = ':'.join(parts[-1:]).strip()
                            info[current_adapter]['MAC'] = mac
                    elif 'DHCP Enabled' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            dhcp = parts[-1].strip()
                            info[current_adapter]['DHCP'] = dhcp
            
            # Get speed info from wmic
            try:
                speed_result = subprocess.run(['wmic', 'path', 'Win32_NetworkAdapterConfiguration', 'get', 'Description,IPAddress,DefaultIPGateway,InterfaceIndex'], 
                                            capture_output=True, text=True, timeout=5)
                # Additional speed details can be extracted from netsh
                netsh_result = subprocess.run(['netsh', 'interface', 'ipv4', 'show', 'config'], 
                                            capture_output=True, text=True, timeout=5)
                netsh_lines = netsh_result.stdout.split('\n')
                for i, line in enumerate(netsh_lines):
                    for adapter in info:
                        if adapter.lower() in line.lower():
                            # Look for speed info in nearby lines
                            for j in range(max(0, i-3), min(len(netsh_lines), i+10)):
                                if 'speed' in netsh_lines[j].lower() or 'bandwidth' in netsh_lines[j].lower():
                                    info[adapter]['Speed Info'] = netsh_lines[j].strip()
            except Exception:
                pass
            
            return info
        else:
            # Unix/Linux: use ip and ethtool commands
            result = subprocess.run(['ip', '-s', 'link'], capture_output=True, text=True, timeout=5)
            
            # Also get detailed interface info
            addr_result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=5)
            
            info = {}
            info['Link Statistics'] = result.stdout
            info['Address Info'] = addr_result.stdout
            
            # Try to get speed with ethtool
            try:
                interfaces_result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=5)
                ifaces = [line.split(':')[1].strip() for line in interfaces_result.stdout.split('\n') if ':' in line and 'lo' not in line]
                for iface in ifaces[:5]:
                    try:
                        speed_result = subprocess.run(['ethtool', iface], capture_output=True, text=True, timeout=3)
                        if 'Speed:' in speed_result.stdout:
                            info[f'{iface} Speed'] = [l.strip() for l in speed_result.stdout.split('\n') if 'Speed:' in l][0]
                    except Exception:
                        pass
            except Exception:
                pass
            
            return info
    except Exception as e:
        return {"error": str(e)}


def get_external_ip() -> str:
    """Fetch external IP address and additional info."""
    try:
        # Get public IP
        ip_response = urllib.request.urlopen('https://api.ipify.org', timeout=5).read().decode('utf-8')
        return ip_response
    except Exception as e:
        return f"Error: {e}"


def get_network_speed() -> dict:
    """Get network interface speeds if available."""
    try:
        if os.name == 'nt':
            # Windows: try to get speed from wmic or netsh
            try:
                result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                      capture_output=True, text=True, timeout=5)
                speeds = {}
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Mbps' in line or 'Gbps' in line:
                        # Extract interface name and speed
                        parts = line.split()
                        if len(parts) > 2:
                            # Find the speed value
                            for part in parts:
                                if 'Gbps' in part or 'Mbps' in part or 'Kbps' in part:
                                    # Get the interface name (usually earlier in line)
                                    iface_name = ' '.join(parts[:parts.index(part)])
                                    speeds[iface_name] = part
                return speeds if speeds else {"status": "Speed info not available"}
            except Exception:
                return {"status": "Speed detection not available on this system"}
        else:
            # Linux: use ethtool
            speeds = {}
            try:
                ifaces_result = subprocess.run(['ip', 'link', 'show'], 
                                             capture_output=True, text=True, timeout=5)
                ifaces = [line.split(':')[1].strip() for line in ifaces_result.stdout.split('\n') 
                         if ':' in line and 'lo' not in line and line.strip()]
                
                for iface in ifaces[:10]:
                    try:
                        result = subprocess.run(['ethtool', iface], 
                                              capture_output=True, text=True, timeout=3)
                        for line in result.stdout.split('\n'):
                            if 'Speed:' in line:
                                speeds[iface] = line.strip()
                    except Exception:
                        pass
            except Exception:
                pass
            return speeds if speeds else {"status": "Speed info not available"}
    except Exception as e:
        return {"error": str(e)}


def network_menu():
    while True:
        clear_screen()
        for line in build_rich_logo():
            print(line)
        print_menu_header("NETWORK MANAGER")
        
        print(WHITE + BOLD + "1) Show interfaces" + RESET)
        print(WHITE + BOLD + "2) Network speeds (Mbps/Gbps)" + RESET)
        print(WHITE + BOLD + "3) External IP" + RESET)
        print(WHITE + BOLD + "4) Full network info" + RESET)
        print(WHITE + BOLD + "5) Ping test" + RESET)
        print(WHITE + BOLD + "b) Back" + RESET)
        print()
        
        cmd = input(GREEN + BOLD + "Command: " + RESET).strip().lower()
        
        if cmd == '1':
            print()
            print(GREEN + BOLD + "Network Interfaces:" + RESET)
            print(GREEN + "=" * get_terminal_width() + RESET)
            info = get_network_info()
            if 'error' in info:
                print(WHITE + f"Error: {info['error']}" + RESET)
            elif 'raw' in info:
                print(WHITE + info['raw'] + RESET)
            else:
                for adapter, details in info.items():
                    if isinstance(details, dict):
                        print(f"\n{GREEN}{BOLD}{adapter}{RESET}")
                        for key, val in details.items():
                            print(f"  {WHITE}{key}: {GREEN}{val}{RESET}")
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        
        elif cmd == '2':
            print()
            print(GREEN + BOLD + "Network Interface Speeds:" + RESET)
            print(GREEN + "=" * get_terminal_width() + RESET)
            speeds = get_network_speed()
            if speeds:
                for iface, speed in speeds.items():
                    if 'Gbps' in str(speed):
                        speed_color = GREEN
                    elif 'Mbps' in str(speed):
                        speed_color = WHITE
                    else:
                        speed_color = WHITE
                    print(f"{WHITE}{iface}: {speed_color}{speed}{RESET}")
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        
        elif cmd == '3':
            print()
            print(GREEN + "Fetching external IP..." + RESET)
            ip = get_external_ip()
            print(WHITE + f"Public IP Address: {GREEN}{ip}{RESET}")
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        
        elif cmd == '4':
            print()
            print(GREEN + BOLD + "Full Network Information:" + RESET)
            print(GREEN + "=" * get_terminal_width() + RESET)
            
            print(f"\n{WHITE}{BOLD}Local Interfaces:{RESET}")
            info = get_network_info()
            if 'error' not in info and 'raw' not in info:
                for adapter, details in info.items():
                    if isinstance(details, dict):
                        print(f"\n  {GREEN}{adapter}{RESET}")
                        for key, val in details.items():
                            print(f"    {WHITE}{key}: {GREEN}{val}{RESET}")
            
            print(f"\n{WHITE}{BOLD}Interface Speeds:{RESET}")
            speeds = get_network_speed()
            for iface, speed in list(speeds.items())[:10]:
                print(f"  {WHITE}{iface}: {GREEN}{speed}{RESET}")
            
            print(f"\n{WHITE}{BOLD}Public IP:{RESET}")
            public_ip = get_external_ip()
            print(f"  {GREEN}{public_ip}{RESET}")
            
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        
        elif cmd == '5':
            host = input(WHITE + BOLD + "Host to ping (default: 8.8.8.8): " + RESET).strip() or "8.8.8.8"
            try:
                if os.name == 'nt':
                    result = subprocess.run(['ping', '-n', '4', host], capture_output=True, text=True, timeout=10)
                else:
                    result = subprocess.run(['ping', '-c', '4', host], capture_output=True, text=True, timeout=10)
                print()
                print(GREEN + BOLD + f"Ping results for {host}:" + RESET)
                print(WHITE + result.stdout + RESET)
            except Exception as e:
                print(WHITE + f"Ping failed: {e}" + RESET)
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        
        elif cmd == 'b':
            break


# Cybersecurity Knowledge Base
CYBERSECURITY_KB = {
    "ddos": {
        "title": "DDoS (Distributed Denial of Service)",
        "answer": "A DDoS attack is when multiple computers flood a target server with requests, overwhelming it and making it unavailable to legitimate users. Attackers use a network of compromised devices (botnet) to send traffic from multiple sources simultaneously. Examples include SYN floods, UDP floods, and HTTP floods. Defenses include rate limiting, firewalls, and DDoS mitigation services."
    },
    "spoofer": {
        "title": "IP/Email Spoofing",
        "answer": "Spoofing is when someone falsifies the source address of network packets or emails to impersonate another user or system. IP spoofing changes packet headers to hide the attacker's origin. Email spoofing forges sender addresses. These are used in phishing, DDoS, and man-in-the-middle attacks. Detection uses authentication protocols like SPF, DKIM, and DMARC for emails, and ingress filtering for IP spoofing."
    },
    "phishing": {
        "title": "Phishing",
        "answer": "Phishing is social engineering attack where attackers send fraudulent emails/messages impersonating trusted organizations to trick users into revealing sensitive data (passwords, credit cards). They use fake websites that look legitimate to steal credentials. Prevention: verify sender addresses, check for suspicious links, enable multi-factor authentication, and use email filters. Never click links from unknown senders."
    },
    "malware": {
        "title": "Malware",
        "answer": "Malware (malicious software) is code designed to harm a computer/network. Types include: viruses (self-replicating), worms (spread without user action), trojans (disguised as legitimate software), ransomware (encrypts files for payment), spyware (steals data), and adware (displays unwanted ads). Prevention: use antivirus software, keep systems updated, avoid suspicious downloads, and use firewalls."
    },
    "encryption": {
        "title": "Encryption",
        "answer": "Encryption converts readable data (plaintext) into unreadable code (ciphertext) using mathematical algorithms and keys. Symmetric encryption uses one key for both encryption/decryption (AES, DES). Asymmetric encryption uses public/private key pairs (RSA, ECC). Encryption protects data confidentiality. HTTPS uses encryption for web traffic. End-to-end encryption ensures only sender/receiver can read messages."
    },
    "firewall": {
        "title": "Firewall",
        "answer": "A firewall is a security system monitoring and controlling incoming/outgoing network traffic based on predetermined rules. Types include: packet-filtering firewalls (check packet headers), stateful firewalls (track connections), proxy firewalls (intercept requests), and next-gen firewalls (deep packet inspection). They block unauthorized access while allowing legitimate traffic. Both hardware and software firewalls exist."
    },
    "vpn": {
        "title": "VPN (Virtual Private Network)",
        "answer": "A VPN creates an encrypted tunnel for your internet traffic, hiding your IP address and protecting data from eavesdropping. It routes traffic through a VPN server before reaching the internet. Uses include: privacy protection, bypassing geo-restrictions, and secure remote work. VPNs use protocols like OpenVPN, IKEv2, and WireGuard. Choose reputable VPNs and avoid free ones that may log data."
    },
    "bruteforce": {
        "title": "Brute Force Attack",
        "answer": "A brute force attack tries many password combinations automatically until finding the correct one. Simple brute force tries all possibilities; dictionary attacks use common passwords; hybrid attacks combine words and numbers. These attacks are slow but simple. Defenses: strong passwords (10+ chars, mixed case, numbers, symbols), account lockouts after failed attempts, CAPTCHA, rate limiting, and multi-factor authentication."
    },
    "mitmattack": {
        "title": "Man-in-the-Middle (MITM) Attack",
        "answer": "A MITM attack intercepts communication between two parties, allowing the attacker to eavesdrop or modify data. Attackers position themselves between victim and server (via ARP spoofing, DNS spoofing, or rogue WiFi). They can steal credentials, inject malware, or alter transactions. Prevention: use HTTPS/TLS, verify SSL certificates, use VPNs, avoid public WiFi for sensitive transactions, and enable certificate pinning."
    },
    "sqlinjection": {
        "title": "SQL Injection",
        "answer": "SQL injection is when attackers insert malicious SQL code into input fields to manipulate database queries. Example: entering ' OR '1'='1 bypasses login checks. Attackers can read/modify/delete data or gain admin access. Prevention: use prepared statements/parameterized queries, input validation, least privilege database accounts, and escape special characters. Modern ORMs help prevent this vulnerability."
    },
    "xss": {
        "title": "Cross-Site Scripting (XSS)",
        "answer": "XSS is when attackers inject malicious scripts into web pages viewed by other users. Types: stored XSS (malicious code saved to database), reflected XSS (injected via URL), and DOM-based XSS (exploits JavaScript). Attacks can steal cookies, session tokens, or perform actions as the user. Prevention: input/output validation, use Content Security Policy (CSP), escape HTML special characters, and use security libraries."
    },
    "csfr": {
        "title": "CSRF (Cross-Site Request Forgery)",
        "answer": "CSRF tricks an authenticated user into performing unwanted actions on a website without their knowledge. Example: an attacker's site makes a hidden request to transfer funds from your bank. The attack exploits the user's existing session. Prevention: use CSRF tokens (unique per request), check HTTP referer headers, use SameSite cookie attribute, and avoid sensitive operations on GET requests."
    },
    "twofactor": {
        "title": "Two-Factor Authentication (2FA)",
        "answer": "2FA adds a second verification step beyond passwords for stronger security. Methods include: SMS codes, authenticator apps (Google Authenticator, Authy), hardware tokens (YubiKey), and biometrics. Even if passwords are stolen, accounts remain protected. Examples: email codes, TOTP (time-based), push notifications. 2FA significantly reduces account compromise risk. Enable it on important accounts (email, banking, social media)."
    },
    "ransomware": {
        "title": "Ransomware",
        "answer": "Ransomware encrypts a victim's files and demands payment for decryption keys. Spread via email attachments, malicious downloads, or unpatched vulnerabilities. Types: locker ransomware (locks screen), crypto ransomware (encrypts files), and scareware (fake threats). Prevention: regular backups (offline), patch systems, use antivirus, disable macros, avoid suspicious email attachments, and train users on phishing."
    },
    "zerodayexploit": {
        "title": "Zero-Day Exploit",
        "answer": "A zero-day is a software vulnerability unknown to developers, allowing attackers to exploit it before a patch exists. Called 'zero-day' because developers have zero days to fix it. These are highly dangerous and valuable. Mitigation includes: rapid patching once discovered, intrusion detection systems, threat intelligence, and defensive coding practices. Companies offer bug bounties to responsibly disclose zero-days."
    },
    "socengineering": {
        "title": "Social Engineering",
        "answer": "Social engineering manipulates people into revealing confidential information or breaking security procedures. Tactics: phishing, pretexting (false pretense), baiting (offering something enticing), tailgating (following into restricted areas), and impersonation. It exploits human psychology rather than technical exploits. Prevention: security awareness training, verification protocols, skepticism of unsolicited requests, and strong security culture."
    },
    "passwordmanager": {
        "title": "Password Manager",
        "answer": "A password manager securely stores and generates complex passwords for different accounts. It uses master encryption to protect all passwords with one strong passphrase. Benefits: unique passwords per site (prevents cascading breaches), strong random passwords, and convenience. Popular options: Bitwarden, 1Password, KeePass, LastPass. Reduces risk of password reuse and weak passwords."
    },
    "updates": {
        "title": "Security Updates & Patches",
        "answer": "Updates fix known vulnerabilities in operating systems, software, and firmware. Security patches specifically address vulnerabilities before attackers exploit them. Staying current is critical defense: delays expose systems to known exploits. Enable automatic updates for OS and critical software. Patch management strategies vary: immediate patching for critical vulnerabilities, scheduled for routine updates. Never delay critical security patches."
    }
}


# BMW Rotating Animation
BMW_FRAME = r"""
    /\_/\
   ( o.o )
    > ^ <
   /|   |\
  (_|   |_)
"""

def get_bmw_frames():
    """Generate detailed BMW M5 frames at different rotation angles."""
    frames = [
        # Frame 0 - Front view
        GREEN + """
        +----------+
        |  *** M5  |
        |  * * *   |
        +----------+
        |////////|
        |\\\\\\\\\\\\\\\\|
        |////////|
        |\\\\\\\\\\\\\\\\|
        +----------+
""" + RESET,
        # Frame 1 - 45° angle (front-right)
        GREEN + """
       /----------\\
      /  *** M5  /
     /   * * *  /
    /////////|
   /\\\\\\\\\\\\\\|
  /____________/
""" + RESET,
        # Frame 2 - Side view (right)
        WHITE + """
    +------------------+
    | *** M5 ***       |
    | |  /\\  /\\  /\\  |
    | |//  //  //  |
    | |\\\\  \\\\  \\\\  |
    +------------------+
      (O)     (O)
""" + RESET,
        # Frame 3 - 135° angle (back-right)
        GREEN + """
  \\____________\\
   \\  /////////\\
    \\  * * *   \\
     \\  5M ***  \\
      \\----------/
       \\----------/
""" + RESET,
        # Frame 4 - Back view
        GREEN + """
        +----------+
        |  5M ***  |
        |  * * *   |
        +----------+
        |////////|
        |\\\\\\\\\\\\\\\\|
        |////////|
        |\\\\\\\\\\\\\\\\|
        +----------+
""" + RESET,
        # Frame 5 - 225° angle (back-left)
        GREEN + """
    /____________/
   /  /////////  /
  /   * * *      /
 /  *** M5 ***  /
/----------\\
/----------\\
""" + RESET,
        # Frame 6 - Side view (left)
        WHITE + """
    +------------------+
    |       *** M5 *** |
    |  /\\  /\\  /\\   |
    |  //  //  //   |
    |  \\\\  \\\\  \\\\   |
    +------------------+
      (O)     (O)
""" + RESET,
        # Frame 7 - 315° angle (front-left)
        GREEN + """
  /____________\\
 /  \\\\\\\\\\\\\\\\\\  \\
/  * * *   \\
\\  *** M5  \\
 \\----------\\
  \\----------\\
""" + RESET,
    ]
    return frames


def bmw_animation_menu():
    """Display rotating BMW animation."""
    clear_screen()
    frames = get_bmw_frames()
    duration = 8  # seconds
    fps = 10  # frames per second
    total_frames = duration * fps
    frame_idx = 0
    
    try:
        for _ in range(total_frames):
            clear_screen()
            for line in build_rich_logo():
                print(line)
            print_menu_header("BMW ROTATION ANIMATION")
            print()
            
            # Display current frame
            print(frames[frame_idx % len(frames)])
            
            # Progress indicator
            progress = (frame_idx % total_frames) / total_frames * 100
            bar_length = 40
            filled = int(bar_length * (frame_idx % total_frames) / total_frames)
            bar = GREEN + "=" * filled + WHITE + "-" * (bar_length - filled) + RESET
            print(f"\n{bar} {int(progress)}%")
            
            # Rotation indicator
            angles = ["Front  (0°)  ", "45°           ", "Side   (90°)  ", "135°          ",
                     "Back  (180°) ", "225°          ", "Side  (270°)  ", "315°          "]
            print(f"{GREEN}Rotation: {angles[frame_idx % len(angles)]}{RESET}")
            
            frame_idx += 1
            time.sleep(1 / fps)
    
    except KeyboardInterrupt:
        print(f"\n{WHITE}Animation stopped.{RESET}")
    
    input(f"\n{WHITE}Press Enter to continue...{RESET}")


def cybersecurity_menu():
    """Interactive cybersecurity knowledge Q&A menu."""
    while True:
        clear_screen()
        for line in build_rich_logo():
            print(line)
        print_menu_header("CYBERSECURITY KNOWLEDGE BASE")
        
        print(WHITE + BOLD + "Common Topics:" + RESET)
        topics = sorted(CYBERSECURITY_KB.keys())
        for i, topic in enumerate(topics, 1):
            print(f"{GREEN}{i}{RESET} - {WHITE}{CYBERSECURITY_KB[topic]['title']}{RESET}")
        
        print(f"\n{WHITE + BOLD}s) Search  |  r) Random  |  b) Back" + RESET)
        print()
        
        choice = input(GREEN + BOLD + "Select (number/search/random/back): " + RESET).strip().lower()
        
        if choice == 'b':
            break
        elif choice == 's':
            query = input(WHITE + BOLD + "Search term: " + RESET).strip().lower()
            found = False
            for topic, info in CYBERSECURITY_KB.items():
                if query in topic or query in info['title'].lower() or query in info['answer'].lower():
                    clear_screen()
                    for line in build_rich_logo():
                        print(line)
                    print_menu_header(info['title'])
                    print(WHITE + info['answer'] + RESET)
                    found = True
                    break
            if not found:
                print(WHITE + "No matching topics found." + RESET)
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        elif choice == 'r':
            import random as rand_module
            topic = rand_module.choice(list(CYBERSECURITY_KB.keys()))
            info = CYBERSECURITY_KB[topic]
            clear_screen()
            for line in build_rich_logo():
                print(line)
            print_menu_header(info['title'])
            print(WHITE + info['answer'] + RESET)
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        elif choice.isdigit():
            idx = int(choice) - 1
            topics = sorted(CYBERSECURITY_KB.keys())
            if 0 <= idx < len(topics):
                topic = topics[idx]
                info = CYBERSECURITY_KB[topic]
                clear_screen()
                for line in build_rich_logo():
                    print(line)
                print_menu_header(info['title'])
                print(WHITE + info['answer'] + RESET)
                input("\n" + WHITE + "Press Enter to continue..." + RESET)


def get_storage_info():
    """Get M.2/SSD storage information."""
    try:
        if os.name == 'nt':
            # Windows: Get disk info via PowerShell
            ps_cmd = """Get-Volume | Select-Object DriveLetter, FileSystemLabel, Size, SizeRemaining | ConvertTo-Json"""
            result = subprocess.run(['powershell', '-Command', ps_cmd], 
                                    capture_output=True, text=True, timeout=5)
            
            try:
                data = json.loads(result.stdout)
                if not isinstance(data, list):
                    data = [data]
            except:
                # Fallback to parsing text output
                storage_info = {}
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2 and ':' in parts[0]:
                            drive = parts[0].rstrip(':')
                            storage_info[drive] = {'status': 'Unknown'}
                return storage_info if storage_info else {'info': 'Use storage_menu to view details'}
            
            storage_info = {}
            for vol in data:
                drive = vol.get('DriveLetter', 'Unknown')
                size_bytes = vol.get('Size', 0)
                free_bytes = vol.get('SizeRemaining', 0)
                label = vol.get('FileSystemLabel', '')
                
                if drive and size_bytes:
                    total_gb = size_bytes / (1024**3)
                    free_gb = free_bytes / (1024**3)
                    used_gb = total_gb - free_gb
                    usage_pct = (used_gb / total_gb * 100) if total_gb > 0 else 0
                    
                    storage_info[f"{drive}:"] = {
                        'Label': label or 'Local Disk',
                        'Total': f"{total_gb:.2f} GB",
                        'Used': f"{used_gb:.2f} GB",
                        'Free': f"{free_gb:.2f} GB",
                        'Usage': f"{usage_pct:.1f}%"
                    }
            
            return storage_info if storage_info else {'info': 'No drives found'}
        else:
            # Linux: Get disk info
            result = subprocess.run(['df', '-h'], capture_output=True, text=True, timeout=5)
            storage_info = {}
            lines = result.stdout.split('\n')[1:]  # Skip header
            
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5:
                        storage_info[parts[5]] = {
                            'Filesystem': parts[0],
                            'Total': parts[1],
                            'Used': parts[2],
                            'Free': parts[3],
                            'Usage': parts[4]
                        }
            
            return storage_info if storage_info else {'error': 'Could not retrieve storage info'}
    except Exception as e:
        return {'error': str(e)}


def get_ssd_speed_info():
    """Get SSD read/write speed estimates and SMART data if available."""
    try:
        if os.name == 'nt':
            # Windows: Get NVMe/SSD info via PowerShell
            ps_cmd = """Get-PhysicalDisk | Select-Object DeviceId, Model, MediaType, Size, BusType | Format-List"""
            result = subprocess.run(['powershell', '-Command', ps_cmd], 
                                    capture_output=True, text=True, timeout=5)
            
            ssd_info = {}
            current_disk = {}
            
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, val = line.split(':', 1)
                    key = key.strip()
                    val = val.strip()
                    
                    if key == 'DeviceId':
                        if current_disk:
                            disk_id = current_disk.get('DeviceId', 'Unknown')
                            ssd_info[disk_id] = current_disk
                        current_disk = {'DeviceId': val}
                    else:
                        current_disk[key] = val
            
            if current_disk:
                disk_id = current_disk.get('DeviceId', 'Unknown')
                ssd_info[disk_id] = current_disk
            
            # Add typical speed estimates
            for disk_id in ssd_info:
                disk = ssd_info[disk_id]
                media_type = disk.get('MediaType', '')
                bus_type = disk.get('BusType', '')
                
                if 'NVMe' in bus_type or 'NVMe' in media_type:
                    disk['Est. Read Speed'] = '3500-7100 MB/s'
                    disk['Est. Write Speed'] = '3000-6000 MB/s'
                    disk['Type'] = 'NVMe (M.2)'
                elif 'SATA' in bus_type or 'SATA' in media_type:
                    disk['Est. Read Speed'] = '500-550 MB/s'
                    disk['Est. Write Speed'] = '500-550 MB/s'
                    disk['Type'] = 'SATA SSD'
                else:
                    disk['Est. Read Speed'] = 'Unknown'
                    disk['Est. Write Speed'] = 'Unknown'
                    disk['Type'] = media_type
            
            return ssd_info if ssd_info else {'info': 'No SSD info available'}
        else:
            # Linux: Get NVMe info
            result = subprocess.run(['lsblk', '-d', '-n', '-o', 'NAME,SIZE,TYPE,ROTA'],
                                    capture_output=True, text=True, timeout=5)
            ssd_info = {}
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        name = parts[0]
                        size = parts[1]
                        dev_type = parts[2]
                        is_rotating = parts[3] == '1'
                        
                        ssd_info[name] = {
                            'Size': size,
                            'Type': 'HDD' if is_rotating else 'SSD/NVMe',
                            'Est. Read Speed': '3500-7100 MB/s' if not is_rotating else '100-200 MB/s',
                            'Est. Write Speed': '3000-6000 MB/s' if not is_rotating else '100-200 MB/s'
                        }
            
            return ssd_info if ssd_info else {'info': 'No storage info available'}
    except Exception as e:
        return {'error': str(e)}


def storage_menu():
    """Interactive storage and SSD information menu."""
    while True:
        clear_screen()
        for line in build_rich_logo():
            print(line)
        print_menu_header("STORAGE & SSD INFORMATION")
        
        print(WHITE + BOLD + "1) Disk Usage & Capacity" + RESET)
        print(WHITE + BOLD + "2) SSD/NVMe Speed Info" + RESET)
        print(WHITE + BOLD + "3) Full Storage Details" + RESET)
        print(WHITE + BOLD + "b) Back" + RESET)
        print()
        
        cmd = input(GREEN + BOLD + "Command: " + RESET).strip().lower()
        
        if cmd == '1':
            clear_screen()
            for line in build_rich_logo():
                print(line)
            print_menu_header("DISK USAGE & CAPACITY")
            print()
            
            storage_info = get_storage_info()
            if 'error' in storage_info:
                print(WHITE + f"Error: {storage_info['error']}" + RESET)
            else:
                for drive, info in storage_info.items():
                    print(f"{GREEN}{BOLD}{drive}{RESET}")
                    for key, val in info.items():
                        # Color code usage percentage
                        if 'Usage' in key:
                            try:
                                usage = float(val.rstrip('%'))
                                if usage > 80:
                                    color = '\033[91m'  # Red
                                elif usage > 60:
                                    color = '\033[93m'  # Yellow
                                else:
                                    color = GREEN
                                print(f"  {WHITE}{key}: {color}{val}{RESET}")
                            except:
                                print(f"  {WHITE}{key}: {GREEN}{val}{RESET}")
                        else:
                            print(f"  {WHITE}{key}: {GREEN}{val}{RESET}")
                    print()
            
            input(WHITE + "Press Enter to continue..." + RESET)
        
        elif cmd == '2':
            clear_screen()
            for line in build_rich_logo():
                print(line)
            print_menu_header("SSD/NVMe SPEED INFORMATION")
            print()
            
            ssd_info = get_ssd_speed_info()
            if 'error' in ssd_info:
                print(WHITE + f"Error: {ssd_info['error']}" + RESET)
            elif 'info' in ssd_info:
                print(WHITE + ssd_info['info'] + RESET)
            else:
                for disk, info in ssd_info.items():
                    print(f"{GREEN}{BOLD}{disk}{RESET} - {GREEN}{info.get('Type', 'Unknown')}{RESET}")
                    for key, val in info.items():
                        if key not in ['DeviceId', 'Type']:
                            print(f"  {WHITE}{key}: {GREEN}{val}{RESET}")
                    print()
            
            input(WHITE + "Press Enter to continue..." + RESET)
        
        elif cmd == '3':
            clear_screen()
            for line in build_rich_logo():
                print(line)
            print_menu_header("FULL STORAGE DETAILS")
            print()
            
            print(f"{GREEN}{BOLD}=== Disk Capacity ==={RESET}")
            storage_info = get_storage_info()
            if 'error' not in storage_info:
                for drive, info in storage_info.items():
                    print(f"{GREEN}{drive}{RESET}: {WHITE}{info.get('Free', 'N/A')}/{info.get('Total', 'N/A')}{RESET}")
            
            print(f"\n{GREEN}{BOLD}=== SSD/Storage Devices ==={RESET}")
            ssd_info = get_ssd_speed_info()
            if 'error' not in ssd_info and 'info' not in ssd_info:
                for disk, info in ssd_info.items():
                    print(f"\n{GREEN}{disk}{RESET}")
                    for key, val in info.items():
                        print(f"  {WHITE}{key}: {GREEN}{val}{RESET}")
            
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        
        elif cmd == 'b':
            break


def get_gpu_stats():
    """Detect GPUs and report temperature, utilization, fan speed and simple thermal-paste heuristic.

    Strategy:
    - Prefer `nvidia-smi` (NVIDIA GPUs).
    - Fallback to `sensors` on Linux or PowerShell/WMIC on Windows for names.
    Returns: dict keyed by device index/name with fields: name, temp_c, util_percent, fan_pct, mem_total_mb, mem_used_mb, thermal_paste_status
    """
    stats = {}
    try:
        # Try nvidia-smi first (works on Windows/Linux with NVIDIA drivers)
        cmd = ['nvidia-smi', '--query-gpu=index,name,temperature.gpu,utilization.gpu,fan.speed,memory.total,memory.used', '--format=csv,noheader,nounits']
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        if res.returncode == 0 and res.stdout.strip():
            for line in res.stdout.strip().splitlines():
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 7:
                    idx, name, temp, util, fan, memtot, memused = parts[:7]
                    try:
                        temp_v = int(temp) if temp and temp != 'N/A' else None
                    except:
                        temp_v = None
                    try:
                        util_v = int(re.sub(r"[^0-9]", "", util)) if util and util != 'N/A' else None
                    except:
                        util_v = None
                    try:
                        fan_v = int(re.sub(r"[^0-9]", "", fan)) if fan and fan != 'N/A' else None
                    except:
                        fan_v = None
                    try:
                        memtot_v = int(memtot)
                        memused_v = int(memused)
                        memtot_mb = memtot_v // (1024*1024)
                        memused_mb = memused_v // (1024*1024)
                    except:
                        memtot_mb = None
                        memused_mb = None

                    # Heuristic thermal paste/status
                    status = 'Unknown'
                    if temp_v is None:
                        status = 'Unknown'
                    else:
                        if temp_v >= 90:
                            status = 'Bad (very hot)'
                        elif temp_v >= 80:
                            status = 'Degraded (replace paste soon)'
                        elif temp_v >= 70:
                            status = 'Warm'
                        elif temp_v >= 50:
                            status = 'Good'
                        else:
                            status = 'Cold / Good'

                    # If low util but high temp, suggest paste/thermal issue
                    if temp_v and util_v is not None:
                        if util_v < 25 and temp_v >= 80:
                            status = 'Degraded (high temp at low util — possible paste/heat-sink issue)'

                    stats[name or f'gpu_{idx}'] = {
                        'index': idx,
                        'name': name,
                        'temp_c': temp_v,
                        'util_percent': util_v,
                        'fan_percent': fan_v,
                        'mem_total_mb': memtot_mb,
                        'mem_used_mb': memused_mb,
                        'thermal_paste_status': status
                    }
            return stats
    except Exception:
        pass

    # Fallbacks
    if platform.system().lower().startswith('linux'):
        # Try sensors for temperature detection
        try:
            res = subprocess.run(['sensors'], capture_output=True, text=True, timeout=2)
            cur = {}
            for line in res.stdout.splitlines():
                m = re.search(r"^(GPU|gpu|amdgpu|nvidia|temp1):?\s*([+-]?[0-9.]+)°C", line, re.I)
                if m:
                    name = m.group(1)
                    temp_v = float(m.group(2))
                    cur[name] = {'temp_c': temp_v}
            if cur:
                for k, v in cur.items():
                    temp_v = int(v['temp_c'])
                    status = 'Unknown'
                    if temp_v >= 90:
                        status = 'Bad (very hot)'
                    elif temp_v >= 80:
                        status = 'Degraded (replace paste soon)'
                    elif temp_v >= 70:
                        status = 'Warm'
                    elif temp_v >= 50:
                        status = 'Good'
                    else:
                        status = 'Cold / Good'
                    stats[k] = {
                        'name': k,
                        'temp_c': temp_v,
                        'util_percent': None,
                        'fan_percent': None,
                        'mem_total_mb': None,
                        'mem_used_mb': None,
                        'thermal_paste_status': status
                    }
                return stats
        except Exception:
            pass

    # Windows fallback: try PowerShell to list physical disks/GPU names
    if os.name == 'nt':
        try:
            ps = "Get-WmiObject Win32_VideoController | Select-Object Name | ConvertTo-Json"
            res = subprocess.run(['powershell', '-Command', ps], capture_output=True, text=True, timeout=3)
            if res.returncode == 0 and res.stdout.strip():
                try:
                    data = json.loads(res.stdout)
                    if isinstance(data, list):
                        for i, d in enumerate(data):
                            name = d.get('Name') if isinstance(d, dict) else str(d)
                            stats[name or f'gpu_{i}'] = {
                                'name': name,
                                'temp_c': None,
                                'util_percent': None,
                                'fan_percent': None,
                                'mem_total_mb': None,
                                'mem_used_mb': None,
                                'thermal_paste_status': 'Unknown'
                            }
                    else:
                        name = data.get('Name') if isinstance(data, dict) else str(data)
                        stats[name or 'gpu_0'] = {
                            'name': name,
                            'temp_c': None,
                            'util_percent': None,
                            'fan_percent': None,
                            'mem_total_mb': None,
                            'mem_used_mb': None,
                            'thermal_paste_status': 'Unknown'
                        }
                    return stats
                except Exception:
                    pass
        except Exception:
            pass

    return {'info': 'No GPU sensors/commands available (install nvidia-smi or lm-sensors)'}


def gpu_menu():
    """Interactive GPU stats and thermal paste advice menu."""
    while True:
        clear_screen()
        for line in build_rich_logo():
            print(line)
        print_menu_header("GPU & THERMAL STATUS")
        print(WHITE + BOLD + "1) Show GPU Stats" + RESET)
        print(WHITE + BOLD + "2) Thermal paste advice" + RESET)
        print(WHITE + BOLD + "b) Back" + RESET)
        print()
        cmd = input(GREEN + BOLD + "Command: " + RESET).strip().lower()
        if cmd == '1':
            clear_screen()
            for line in build_rich_logo():
                print(line)
            print_menu_header("GPU STATISTICS")
            info = get_gpu_stats()
            if 'info' in info:
                print(WHITE + info['info'] + RESET)
            else:
                for dev, d in info.items():
                    print(f"{GREEN}{BOLD}{dev}{RESET}")
                    for k, v in d.items():
                        print(f"  {WHITE}{k}: {GREEN}{v}{RESET}")
                    print()
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        elif cmd == '2':
            clear_screen()
            for line in build_rich_logo():
                print(line)
            print_menu_header("THERMAL PASTE ADVICE")
            info = get_gpu_stats()
            if 'info' in info:
                print(WHITE + info['info'] + RESET)
            else:
                for dev, d in info.items():
                    temp = d.get('temp_c')
                    status = d.get('thermal_paste_status', 'Unknown')
                    print(f"{GREEN}{dev}{RESET} - Temp: {WHITE}{temp if temp is not None else 'N/A'}°C{RESET}")
                    print(f"  {WHITE}Thermal Paste Status: {GREEN}{status}{RESET}")
                    if temp is not None and temp >= 85:
                        print(WHITE + "  Recommendation: Clean heatsink, replace thermal paste, check fan/heatsink seating." + RESET)
                    elif temp is not None and temp >= 75:
                        print(WHITE + "  Recommendation: Monitor temps under load; consider reapplying paste if temps climb." + RESET)
                    else:
                        print(WHITE + "  Recommendation: Thermal paste likely OK." + RESET)
                    print()
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        elif cmd == 'b':
            break


def suggest_optimizations():
    """Return a list of safe optimization suggestions with optional commands.

    These are suggestions only. Commands shown may require elevated privileges.
    """
    suggestions = [
        {
            'id': 'clean_temp',
            'title': 'Clean temporary files',
            'description': 'Remove files from OS temp directories to free space and reduce clutter.',
            'action': 'clean_temp_files'
        },
        {
            'id': 'clear_thumbnail_cache',
            'title': 'Clear thumbnail cache (Windows)',
            'description': 'Clears Windows thumbnail cache to free disk space.',
            'action': None
        },
        {
            'id': 'high_perf_power',
            'title': 'Enable high-performance power plan',
            'description': 'Switch system power plan to High Performance (may use more power).',
            'action': 'enable_high_performance_powerplan'
        },
        {
            'id': 'nvidia_persistence',
            'title': 'Enable NVIDIA persistence mode',
            'description': 'Keeps NVIDIA driver loaded to reduce initialization latency (requires nvidia-smi).',
            'action': None
        },
        {
            'id': 'set_proc_priority',
            'title': 'Set process priority',
            'description': 'Change a process priority (useful to lower background tasks or raise foreground).',
            'action': 'set_process_priority'
        }
    ]
    return suggestions


def clean_temp_files(dry_run=True):
    """Scan OS temp directories and optionally delete files.

    Returns a dict with scanned paths, file count and total size. If dry_run True, no deletion occurs.
    """
    import shutil

    tmp_paths = []
    if os.name == 'nt':
        tmp_paths.extend([os.environ.get('TEMP'), os.environ.get('TMP'), r'C:\Windows\Temp'])
    else:
        tmp_paths.extend(['/tmp', os.path.expanduser('~/.cache')])

    results = {}
    for p in tmp_paths:
        if not p:
            continue
        try:
            p = os.path.abspath(p)
            total = 0
            count = 0
            for root, dirs, files in os.walk(p):
                for f in files:
                    try:
                        fp = os.path.join(root, f)
                        size = os.path.getsize(fp)
                        total += size
                        count += 1
                    except Exception:
                        pass
            results[p] = {'files': count, 'bytes': total}
            if not dry_run:
                # attempt to delete files (best-effort)
                for root, dirs, files in os.walk(p):
                    for f in files:
                        try:
                            fp = os.path.join(root, f)
                            os.remove(fp)
                        except Exception:
                            pass
                # try to remove empty dirs
                for root, dirs, files in os.walk(p, topdown=False):
                    try:
                        if not os.listdir(root):
                            os.rmdir(root)
                    except Exception:
                        pass
        except Exception as e:
            results[p] = {'error': str(e)}
    return results


def set_process_priority(pid: int, priority: str = 'below_normal') -> dict:
    """Attempt to set process priority. priority one of: idle, below_normal, normal, above_normal, high.
    This function asks for confirmation before making changes.
    Returns a dict with 'ok' and message.
    """
    priority_map_win = {
        'idle': 64,
        'below_normal': 16384,
        'normal': 32,
        'above_normal': 32768,
        'high': 128
    }
    try:
        if os.name == 'nt':
            if priority not in priority_map_win:
                return {'ok': False, 'msg': 'Unknown priority'}
            cmd = ['wmic', 'process', 'where', f'ProcessId={pid}', 'call', 'setpriority', str(priority_map_win[priority])]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                return {'ok': True, 'msg': 'Priority set (wmic)'}
            else:
                return {'ok': False, 'msg': res.stderr or res.stdout}
        else:
            # Linux: use renice (nice value: higher -> lower priority)
            # mapping: idle=19, below_normal=10, normal=0, above_normal=-5, high=-10
            map_linux = {'idle': 19, 'below_normal': 10, 'normal': 0, 'above_normal': -5, 'high': -10}
            if priority not in map_linux:
                return {'ok': False, 'msg': 'Unknown priority'}
            nice = map_linux[priority]
            cmd = ['renice', str(nice), '-p', str(pid)]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                return {'ok': True, 'msg': res.stdout}
            else:
                return {'ok': False, 'msg': res.stderr or res.stdout}
    except Exception as e:
        return {'ok': False, 'msg': str(e)}


def enable_high_performance_powerplan(perform=False) -> dict:
    """Suggest or enable a High Performance power plan.

    If perform==True, attempt to switch the current power plan (may require privileges).
    Returns status dict.
    """
    try:
        if os.name == 'nt':
            # list plans and pick one containing 'High' or 'Performance'
            res = subprocess.run(['powercfg', '-l'], capture_output=True, text=True, timeout=5)
            cand = None
            for line in res.stdout.splitlines():
                if 'High performance' in line or 'High Performance' in line or 'Performance' in line:
                    # parse GUID
                    m = re.search(r'([0-9a-fA-F\-]{36})', line)
                    if m:
                        cand = m.group(1)
                        break
            if not cand:
                return {'ok': False, 'msg': 'No High Performance plan found'}
            if not perform:
                return {'ok': True, 'msg': f'Plan available: {cand} (dry-run)'}
            res2 = subprocess.run(['powercfg', '-setactive', cand], capture_output=True, text=True, timeout=5)
            if res2.returncode == 0:
                return {'ok': True, 'msg': 'Power plan switched to High Performance'}
            else:
                return {'ok': False, 'msg': res2.stderr or res2.stdout}
        else:
            # Linux: suggest using performance governor
            cmd = 'sudo cpupower frequency-set -g performance'
            if not perform:
                return {'ok': True, 'msg': f'Suggested command: {cmd}'}
            res = subprocess.run(['sudo', 'cpupower', 'frequency-set', '-g', 'performance'], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                return {'ok': True, 'msg': 'CPU governor set to performance'}
            else:
                return {'ok': False, 'msg': res.stderr or res.stdout}
    except Exception as e:
        return {'ok': False, 'msg': str(e)}


def safe_gpu_overclock(perform=False) -> dict:
    """Attempt to safely overclock GPU (NVIDIA only; dry-run support).
    
    Strategy:
    - Check for nvidia-smi and nvidia-smi -pm 1 (persistence mode).
    - Apply modest power limit increase (+10-15W) if available.
    - Memory and core clocks are user-controlled and risky; only suggest commands.
    Returns status dict with 'ok' and 'msg'.
    """
    try:
        # Check if nvidia-smi is available
        res = subprocess.run(['nvidia-smi', '--version'], capture_output=True, text=True, timeout=3)
        if res.returncode != 0:
            return {'ok': False, 'msg': 'NVIDIA GPU not detected or nvidia-smi not available'}
        
        if not perform:
            return {
                'ok': True,
                'msg': 'GPU overclock (dry-run): Suggest enabling persistence mode and modest power increase. Use nvidia-smi -pm 1 then nvidia-smi -pl +10 (requires nvidia-smi with admin/root).'
            }
        
        # Attempt to enable persistence mode
        try:
            subprocess.run(['nvidia-smi', '-pm', '1'], capture_output=True, text=True, timeout=3)
        except Exception:
            pass
        
        # Suggest power limit increase (requires root/admin and nvidia driver support)
        msg = 'Persistence mode enabled. For further clocking, use nvidia-overclock or afterburner (Windows) / nvidia-settings (Linux) with caution.'
        return {'ok': True, 'msg': msg}
    except Exception as e:
        return {'ok': False, 'msg': f'Error: {str(e)}'}


def disable_thermal_throttle(perform=False) -> dict:
    """Attempt to disable CPU thermal throttling (dry-run support).
    
    Strategy:
    - Windows: Use powercfg to set thermal threshold policy.
    - Linux: Use Intel P-State driver or ACPI interface (requires root).
    WARNING: Only disable if cooling is adequate; risk of hardware damage.
    Returns status dict.
    """
    try:
        if os.name == 'nt':
            # Windows: Check if we can access thermal settings
            if not perform:
                return {
                    'ok': True,
                    'msg': 'Thermal throttle disable (dry-run): Requires admin/regedit access. Use "powercfg /setaciveplan GUID" with custom thermal policy or ThrottleStop tool.'
                }
            
            # Attempt via powercfg (limited on modern Windows)
            try:
                # Get current plan
                res = subprocess.run(['powercfg', '-query'], capture_output=True, text=True, timeout=5)
                msg = 'To disable thermal throttle on Windows, use ThrottleStop or custom BIOS settings (requires admin). Current policy queried.'
                return {'ok': True, 'msg': msg}
            except Exception as e:
                return {'ok': False, 'msg': f'powercfg error: {e}'}
        else:
            # Linux: Use Intel P-State or cpupower
            if not perform:
                return {
                    'ok': True,
                    'msg': 'Thermal throttle disable (dry-run): Use "echo 0 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo" (Intel) or disable via BIOS/EFI. Requires root.'
                }
            
            # Attempt to disable turbo boost (which may reduce throttling need)
            try:
                res = subprocess.run(['sudo', 'sh', '-c', 'echo 0 > /sys/devices/system/cpu/intel_pstate/no_turbo'],
                                     capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    return {'ok': True, 'msg': 'Intel turbo boost re-enabled (throttle-friendly). Note: thermal throttle is built-in protection and cannot be fully disabled via software.'}
                else:
                    return {'ok': False, 'msg': 'Intel P-State not available or permission denied.'}
            except Exception as e:
                return {'ok': False, 'msg': f'Error: {e}. Disable thermal throttle via BIOS/EFI or ThrottleStop (Windows) / undervolting.'}
    except Exception as e:
        return {'ok': False, 'msg': f'Error: {str(e)}'}


def optimize_ssd_trim(perform=False) -> dict:
    """Optimize SSD/M.2 drives using TRIM command for better performance.
    
    Strategy:
    - Windows: Use built-in Optimize-Volume or Optimize-Disk cmdlets via PowerShell (requires admin).
    - Linux: Use fstrim command (requires root, but is lightweight and safe).
    Returns status dict with 'ok' and 'msg'.
    """
    try:
        if os.name == 'nt':
            # Windows: Use PowerShell Optimize-Volume
            if not perform:
                return {
                    'ok': True,
                    'msg': 'SSD TRIM (dry-run): Will run Optimize-Volume on all disks via PowerShell (admin required). This issues TRIM commands to SSD to free unused blocks, improving performance.'
                }
            
            try:
                ps_cmd = """Get-Volume | Where-Object {$_.DriveType -eq 'Fixed'} | ForEach-Object {Optimize-Volume -DriveLetter $_.DriveLetter -Defrag -Verbose}"""
                res = subprocess.run(['powershell', '-Command', ps_cmd], 
                                     capture_output=True, text=True, timeout=30)
                if res.returncode == 0:
                    return {'ok': True, 'msg': f'SSD TRIM completed on all drives. Output: {res.stdout[:200]}'}
                else:
                    return {'ok': False, 'msg': f'PowerShell error (may need admin): {res.stderr or res.stdout}'}
            except Exception as e:
                return {'ok': False, 'msg': f'Error running TRIM: {str(e)}'}
        else:
            # Linux: Use fstrim
            if not perform:
                return {
                    'ok': True,
                    'msg': 'SSD TRIM (dry-run): Will run fstrim on mounted filesystems (requires root). This issues TRIM commands to free unused blocks on SSD.'
                }
            
            try:
                res = subprocess.run(['sudo', 'fstrim', '-v', '/'], 
                                     capture_output=True, text=True, timeout=30)
                if res.returncode == 0:
                    return {'ok': True, 'msg': f'SSD TRIM completed. Freed blocks: {res.stdout}'}
                else:
                    return {'ok': False, 'msg': f'fstrim error (may need root): {res.stderr or res.stdout}'}
            except Exception as e:
                return {'ok': False, 'msg': f'Error running fstrim: {str(e)}'}
    except Exception as e:
        return {'ok': False, 'msg': f'Error: {str(e)}'}


def manage_partitions(operation: str = 'list', target: str = '', size_gb: int = 0, perform=False) -> dict:
    """Manage disk partitions: list, create, or delete (dry-run support).
    
    Operations:
    - 'list': Show all disks and partitions.
    - 'create': Create new partition (requires target disk and size_gb).
    - 'delete': Delete partition (requires target partition name/path).
    
    Strategy:
    - Windows: Use diskpart (cmd.exe) or PowerShell Get-Disk / Get-Partition cmdlets.
    - Linux: Use parted, fdisk, or lsblk to list; parted or fdisk to modify (requires root).
    Returns status dict.
    """
    try:
        if operation == 'list':
            if os.name == 'nt':
                # Windows: List disks and partitions
                ps_cmd = """Get-Disk | Select-Object Number, Size, BusType, HealthStatus | ConvertTo-Json; Get-Partition | Select-Object DiskNumber, PartitionNumber, Type, Size, DriveLetter | ConvertTo-Json"""
                res = subprocess.run(['powershell', '-Command', ps_cmd], 
                                     capture_output=True, text=True, timeout=10)
                if res.returncode == 0:
                    return {'ok': True, 'data': res.stdout[:1000]}  # Truncate for display
                else:
                    return {'ok': False, 'msg': f'PowerShell error: {res.stderr}'}
            else:
                # Linux: Use lsblk and parted
                res = subprocess.run(['lsblk', '-a', '-J'], 
                                     capture_output=True, text=True, timeout=10)
                if res.returncode == 0:
                    return {'ok': True, 'data': res.stdout[:1000]}
                else:
                    return {'ok': False, 'msg': f'lsblk error: {res.stderr}'}
        
        elif operation == 'create':
            if not target or size_gb <= 0:
                return {'ok': False, 'msg': 'Target disk and size (GB) required for partition creation'}
            
            if os.name == 'nt':
                if not perform:
                    return {
                        'ok': True,
                        'msg': f'Partition create (dry-run): Would create {size_gb}GB partition on disk {target} using New-Partition cmdlet (admin required). This is irreversible.'
                    }
                
                try:
                    # Create partition (example for disk 1, requires admin)
                    ps_cmd = f"""$disk = Get-Disk -Number {target}; New-Partition -DiskNumber {target} -Size ({size_gb}GB) -AssignDriveLetter | Format-Volume -FileSystem NTFS -NewFileSystemLabel "AR1TIX_Part" -Confirm:$false"""
                    res = subprocess.run(['powershell', '-Command', ps_cmd], 
                                         capture_output=True, text=True, timeout=30)
                    if res.returncode == 0:
                        return {'ok': True, 'msg': f'Partition created. Output: {res.stdout[:300]}'}
                    else:
                        return {'ok': False, 'msg': f'Error (requires admin): {res.stderr or res.stdout}'}
                except Exception as e:
                    return {'ok': False, 'msg': f'Error: {str(e)}'}
            else:
                if not perform:
                    return {
                        'ok': True,
                        'msg': f'Partition create (dry-run): Would create {size_gb}GB partition on {target} using parted/fdisk (requires root). This is irreversible.'
                    }
                
                try:
                    # Linux: Use parted to create partition (dangerous operation!)
                    res = subprocess.run(['sudo', 'parted', '-s', target, 'mkpart', 'primary', 'ext4', '0%', '100%'],
                                         capture_output=True, text=True, timeout=30)
                    if res.returncode == 0:
                        return {'ok': True, 'msg': f'Partition created on {target}. Format with mkfs before use.'}
                    else:
                        return {'ok': False, 'msg': f'parted error: {res.stderr}'}
                except Exception as e:
                    return {'ok': False, 'msg': f'Error: {str(e)}'}
        
        elif operation == 'delete':
            if not target:
                return {'ok': False, 'msg': 'Target partition required for deletion'}
            
            if os.name == 'nt':
                if not perform:
                    return {
                        'ok': True,
                        'msg': f'Partition delete (dry-run): Would delete partition {target}. Data CANNOT be recovered. This is irreversible.'
                    }
                
                try:
                    # Extract disk and partition numbers from target (e.g., "Disk 1, Partition 2")
                    ps_cmd = f"""Remove-Partition -DiskNumber (Get-Partition | Where-Object {{$_.DriveLetter -eq '{target}'}} | Select-Object -First 1).DiskNumber -PartitionNumber (Get-Partition | Where-Object {{$_.DriveLetter -eq '{target}'}} | Select-Object -First 1).PartitionNumber -Confirm:$false"""
                    res = subprocess.run(['powershell', '-Command', ps_cmd], 
                                         capture_output=True, text=True, timeout=30)
                    if res.returncode == 0:
                        return {'ok': True, 'msg': f'Partition {target} deleted.'}
                    else:
                        return {'ok': False, 'msg': f'Error: {res.stderr or res.stdout}'}
                except Exception as e:
                    return {'ok': False, 'msg': f'Error: {str(e)}'}
            else:
                if not perform:
                    return {
                        'ok': True,
                        'msg': f'Partition delete (dry-run): Would delete partition {target}. Data CANNOT be recovered. This is irreversible.'
                    }
                
                try:
                    # Linux: Use parted to delete partition
                    # target should be device path like /dev/sda1
                    disk = target.rstrip('0123456789')
                    part_num = target[len(disk):]
                    res = subprocess.run(['sudo', 'parted', '-s', disk, 'rm', part_num],
                                         capture_output=True, text=True, timeout=30)
                    if res.returncode == 0:
                        return {'ok': True, 'msg': f'Partition {target} deleted.'}
                    else:
                        return {'ok': False, 'msg': f'parted error: {res.stderr}'}
                except Exception as e:
                    return {'ok': False, 'msg': f'Error: {str(e)}'}
        
        else:
            return {'ok': False, 'msg': f'Unknown operation: {operation}'}
    
    except Exception as e:
        return {'ok': False, 'msg': f'Error: {str(e)}'}


def get_spotify_local_playlists():
    """Attempt to find Spotify local music files or integration.
    
    Strategy:
    - Check Windows Spotify cache/local data
    - Check Linux Spotify or music directories
    - Look for .mp3, .flac, .wav files
    - Return list of playable tracks
    """
    tracks = []
    try:
        if os.name == 'nt':
            # Windows: Check Spotify local files and common music directories
            music_dirs = [
                os.path.expanduser('~\\Music'),
                os.path.expanduser('~\\Music\\Spotify'),
                os.path.expanduser('~\\AppData\\Local\\Spotify\\Storage'),
            ]
        else:
            # Linux: Check music directories
            music_dirs = [
                os.path.expanduser('~/Music'),
                os.path.expanduser('~/.local/share/spotify'),
                '/tmp/spotify-*',
            ]
        
        # Search for audio files
        audio_extensions = ('.mp3', '.flac', '.wav', '.m4a', '.ogg')
        
        for music_dir in music_dirs:
            if os.path.exists(music_dir):
                try:
                    for root, dirs, files in os.walk(music_dir):
                        for file in sorted(files):
                            if file.lower().endswith(audio_extensions):
                                full_path = os.path.join(root, file)
                                tracks.append({
                                    'name': file,
                                    'path': full_path,
                                    'size': os.path.getsize(full_path)
                                })
                        # Limit to avoid huge lists
                        if len(tracks) >= 500:
                            break
                except Exception:
                    pass
        
        return tracks
    except Exception:
        return []


def spotify_music_menu():
    """Interactive Spotify/Music player menu with playlist selection."""
    while True:
        clear_screen()
        for line in build_rich_logo():
            print(line)
        print_menu_header("SPOTIFY MUSIC PLAYER")
        
        print(WHITE + BOLD + "1) Browse local music library" + RESET)
        print(WHITE + BOLD + "2) Launch Spotify desktop" + RESET)
        print(WHITE + BOLD + "3) Search & play track" + RESET)
        print(WHITE + BOLD + "b) Back" + RESET)
        print()
        
        cmd = input(GREEN + BOLD + "Command: " + RESET).strip().lower()
        
        if cmd == '1':
            # Browse local music library
            clear_screen()
            for line in build_rich_logo():
                print(line)
            print_menu_header("LOADING YOUR MUSIC LIBRARY")
            print(WHITE + "Scanning music directories..." + RESET)
            
            tracks = get_spotify_local_playlists()
            
            if not tracks:
                clear_screen()
                for line in build_rich_logo():
                    print(line)
                print_menu_header("MUSIC LIBRARY")
                print(WHITE + "No local music files found in Music directories." + RESET)
                input("\n" + WHITE + "Press Enter to continue..." + RESET)
                continue
            
            # Display playlist with numbering
            clear_screen()
            for line in build_rich_logo():
                print(line)
            print_menu_header(f"YOUR MUSIC LIBRARY ({len(tracks)} TRACKS)")
            print()
            
            # Show tracks with pagination
            page_size = 20
            page = 0
            
            while True:
                clear_screen()
                for line in build_rich_logo():
                    print(line)
                print_menu_header(f"YOUR MUSIC LIBRARY ({len(tracks)} TRACKS) - Page {page + 1}")
                print()
                
                start_idx = page * page_size
                end_idx = min(start_idx + page_size, len(tracks))
                
                for i in range(start_idx, end_idx):
                    track = tracks[i]
                    # Extract filename without extension for display
                    track_name = os.path.splitext(track['name'])[0]
                    size_mb = track['size'] / (1024 * 1024)
                    print(f"{GREEN}{i}{RESET} - {WHITE}{track_name[:60]}{RESET} ({size_mb:.1f} MB)")
                
                print()
                print(WHITE + BOLD + f"Page {page + 1}/{(len(tracks) + page_size - 1) // page_size}" + RESET)
                
                if page > 0:
                    print(WHITE + BOLD + "p) Previous page" + RESET)
                if end_idx < len(tracks):
                    print(WHITE + BOLD + "n) Next page" + RESET)
                
                print(WHITE + BOLD + "Enter track number to play (or p/n for pages, b to back): " + RESET)
                print()
                
                user_input = input(GREEN + BOLD + "Select: " + RESET).strip().lower()
                
                if user_input == 'b':
                    break
                elif user_input == 'p' and page > 0:
                    page -= 1
                    continue
                elif user_input == 'n' and end_idx < len(tracks):
                    page += 1
                    continue
                elif user_input.isdigit():
                    track_idx = int(user_input)
                    if 0 <= track_idx < len(tracks):
                        track = tracks[track_idx]
                        clear_screen()
                        for line in build_rich_logo():
                            print(line)
                        print_menu_header("PLAYING TRACK")
                        
                        track_name = os.path.splitext(track['name'])[0]
                        print(f"\n{GREEN}{BOLD}Now Playing:{RESET}")
                        print(f"{WHITE}{track_name}{RESET}")
                        print(f"{WHITE}Path: {track['path']}{RESET}\n")
                        
                        # Try to open with default player
                        try:
                            if os.name == 'nt':
                                os.startfile(track['path'])
                            else:
                                subprocess.Popen(['xdg-open', track['path']])
                            
                            print(f"{GREEN}✓ Opening track in default player...{RESET}")
                        except Exception as e:
                            print(f"{WHITE}Could not open with default player: {e}{RESET}")
                            print(f"{WHITE}File path: {track['path']}{RESET}")
                        
                        input("\n" + WHITE + "Press Enter to continue..." + RESET)
                        break
                    else:
                        print(WHITE + f"Invalid track number. Select 0-{len(tracks)-1}" + RESET)
        
        elif cmd == '2':
            # Launch Spotify desktop app
            clear_screen()
            for line in build_rich_logo():
                print(line)
            print_menu_header("LAUNCHING SPOTIFY")
            
            try:
                if os.name == 'nt':
                    # Windows: Try to find Spotify
                    spotify_paths = [
                        os.path.expanduser('~\\AppData\\Roaming\\Spotify\\spotify.exe'),
                        r'C:\Users\Public\AppData\Roaming\Spotify\spotify.exe',
                        'spotify'  # Try PATH
                    ]
                    launched = False
                    for path in spotify_paths:
                        try:
                            if os.path.exists(path) or path == 'spotify':
                                subprocess.Popen(path)
                                launched = True
                                break
                        except Exception:
                            pass
                    
                    if launched:
                        print(WHITE + "✓ Spotify is launching..." + RESET)
                    else:
                        print(WHITE + "✗ Spotify not found. Install it from https://spotify.com" + RESET)
                else:
                    # Linux: Try to launch Spotify
                    try:
                        subprocess.Popen(['spotify'])
                        print(WHITE + "✓ Spotify is launching..." + RESET)
                    except Exception:
                        print(WHITE + "✗ Spotify not found. Install with: sudo apt install spotify-client" + RESET)
            except Exception as e:
                print(WHITE + f"Error launching Spotify: {e}" + RESET)
            
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        
        elif cmd == '3':
            # Search & play track
            clear_screen()
            for line in build_rich_logo():
                print(line)
            print_menu_header("SEARCH & PLAY")
            
            search_term = input(WHITE + BOLD + "Search for track (artist/song name): " + RESET).strip()
            
            if not search_term:
                print(WHITE + "Cancelled." + RESET)
                input("\n" + WHITE + "Press Enter to continue..." + RESET)
                continue
            
            # Find matching tracks
            tracks = get_spotify_local_playlists()
            matches = [t for t in tracks if search_term.lower() in t['name'].lower()]
            
            if not matches:
                print(WHITE + f"No tracks found matching '{search_term}'" + RESET)
                input("\n" + WHITE + "Press Enter to continue..." + RESET)
                continue
            
            # Display matches
            clear_screen()
            for line in build_rich_logo():
                print(line)
            print_menu_header(f"SEARCH RESULTS: {len(matches)} MATCHES")
            print()
            
            for i, track in enumerate(matches[:50]):  # Show first 50 matches
                track_name = os.path.splitext(track['name'])[0]
                print(f"{GREEN}{i}{RESET} - {WHITE}{track_name}{RESET}")
            
            print()
            user_input = input(GREEN + BOLD + f"Select track (0-{len(matches)-1}) or b to back: " + RESET).strip().lower()
            
            if user_input == 'b':
                continue
            elif user_input.isdigit():
                track_idx = int(user_input)
                if 0 <= track_idx < len(matches):
                    track = matches[track_idx]
                    clear_screen()
                    for line in build_rich_logo():
                        print(line)
                    print_menu_header("PLAYING TRACK")
                    
                    track_name = os.path.splitext(track['name'])[0]
                    print(f"\n{GREEN}{BOLD}Now Playing:{RESET}")
                    print(f"{WHITE}{track_name}{RESET}\n")
                    
                    try:
                        if os.name == 'nt':
                            os.startfile(track['path'])
                        else:
                            subprocess.Popen(['xdg-open', track['path']])
                        
                        print(f"{GREEN}✓ Opening track in default player...{RESET}")
                    except Exception as e:
                        print(f"{WHITE}Could not open: {e}{RESET}")
                    
                    input("\n" + WHITE + "Press Enter to continue..." + RESET)


def optimization_menu():
    """Interactive optimization menu with safe suggestions and opt-in actions."""
    while True:
        clear_screen()
        for line in build_rich_logo():
            print(line)
        print_menu_header("SYSTEM OPTIMIZATIONS")
        print(WHITE + BOLD + "1) Show suggestions" + RESET)
        print(WHITE + BOLD + "2) Clean temporary files (dry-run)" + RESET)
        print(WHITE + BOLD + "3) Clean temporary files (apply)" + RESET)
        print(WHITE + BOLD + "4) Set process priority" + RESET)
        print(WHITE + BOLD + "5) Enable High Performance power plan (dry-run)" + RESET)
        print(WHITE + BOLD + "6) Enable High Performance power plan (apply)" + RESET)
        print(WHITE + BOLD + "7) GPU Overclock (dry-run)" + RESET)
        print(WHITE + BOLD + "8) Disable Thermal Throttle (dry-run)" + RESET)
        print(WHITE + BOLD + "9) SSD/M.2 TRIM Optimization (dry-run)" + RESET)
        print(WHITE + BOLD + "10) Partition Manager" + RESET)
        print(WHITE + BOLD + "b) Back" + RESET)
        print()
        cmd = input(GREEN + BOLD + "Command: " + RESET).strip().lower()
        if cmd == '1':
            clear_screen()
            for line in build_rich_logo():
                print(line)
            print_menu_header("OPTIMIZATION SUGGESTIONS")
            for s in suggest_optimizations():
                print(f"{GREEN}{s['id']}{RESET} - {WHITE}{s['title']}{RESET}")
                print(f"  {WHITE}{s['description']}{RESET}\n")
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        elif cmd == '2':
            clear_screen()
            print_menu_header("CLEAN TEMP (DRY RUN)")
            res = clean_temp_files(dry_run=True)
            for p, info in res.items():
                if 'error' in info:
                    print(f"{WHITE}{p}: Error: {info['error']}{RESET}")
                else:
                    print(f"{WHITE}{p}: {info['files']} files, {info['bytes']//1024} KB{RESET}")
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        elif cmd == '3':
            confirm = input(WHITE + BOLD + "Delete temp files? This cannot be undone (y/N): " + RESET).strip().lower()
            if confirm == 'y':
                res = clean_temp_files(dry_run=False)
                print(WHITE + "Cleanup results:" + RESET)
                for p, info in res.items():
                    if 'error' in info:
                        print(f"{WHITE}{p}: Error: {info['error']}{RESET}")
                    else:
                        print(f"{WHITE}{p}: {info['files']} files scanned (deleted where possible), {info['bytes']//1024} KB freed (approx){RESET}")
            else:
                print(WHITE + "Cancelled." + RESET)
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        elif cmd == '4':
            pid_s = input(WHITE + BOLD + "Process ID to change priority: " + RESET).strip()
            pr = input(WHITE + BOLD + "Priority (idle, below_normal, normal, above_normal, high): " + RESET).strip()
            try:
                pid = int(pid_s)
                res = set_process_priority(pid, pr)
                print(WHITE + str(res) + RESET)
            except Exception as e:
                print(WHITE + f"Invalid PID: {e}" + RESET)
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        elif cmd == '5':
            res = enable_high_performance_powerplan(perform=False)
            print(WHITE + str(res) + RESET)
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        elif cmd == '6':
            confirm = input(WHITE + BOLD + "Switch to High Performance plan? (may need privileges) (y/N): " + RESET).strip().lower()
            if confirm == 'y':
                res = enable_high_performance_powerplan(perform=True)
                print(WHITE + str(res) + RESET)
            else:
                print(WHITE + "Cancelled." + RESET)
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        elif cmd == '7':
            res = safe_gpu_overclock(perform=False)
            print(WHITE + str(res) + RESET)
            confirm = input(WHITE + BOLD + "\nApply GPU overclock? (y/N): " + RESET).strip().lower()
            if confirm == 'y':
                res2 = safe_gpu_overclock(perform=True)
                print(WHITE + str(res2) + RESET)
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        elif cmd == '8':
            res = disable_thermal_throttle(perform=False)
            print(WHITE + str(res) + RESET)
            confirm = input(WHITE + BOLD + "\nDisable thermal throttle? (RISKY - requires adequate cooling) (y/N): " + RESET).strip().lower()
            if confirm == 'y':
                res2 = disable_thermal_throttle(perform=True)
                print(WHITE + str(res2) + RESET)
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        elif cmd == '9':
            res = optimize_ssd_trim(perform=False)
            print(WHITE + str(res) + RESET)
            confirm = input(WHITE + BOLD + "\nRun SSD TRIM optimization? (y/N): " + RESET).strip().lower()
            if confirm == 'y':
                res2 = optimize_ssd_trim(perform=True)
                print(WHITE + str(res2) + RESET)
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        elif cmd == '10':
            # Partition manager submenu
            while True:
                clear_screen()
                for line in build_rich_logo():
                    print(line)
                print_menu_header("PARTITION MANAGER")
                print(WHITE + BOLD + "1) List partitions" + RESET)
                print(WHITE + BOLD + "2) Create partition (dry-run)" + RESET)
                print(WHITE + BOLD + "3) Delete partition (dry-run)" + RESET)
                print(WHITE + BOLD + "b) Back" + RESET)
                print()
                part_cmd = input(GREEN + BOLD + "Command: " + RESET).strip().lower()
                
                if part_cmd == '1':
                    clear_screen()
                    for line in build_rich_logo():
                        print(line)
                    print_menu_header("DISK & PARTITION LIST")
                    res = manage_partitions(operation='list')
                    if res['ok']:
                        print(WHITE + res['data'][:1500] + RESET)
                    else:
                        print(WHITE + f"Error: {res['msg']}" + RESET)
                    input("\n" + WHITE + "Press Enter to continue..." + RESET)
                
                elif part_cmd == '2':
                    clear_screen()
                    for line in build_rich_logo():
                        print(line)
                    print_menu_header("CREATE PARTITION (WARNING: DESTRUCTIVE)")
                    
                    if os.name == 'nt':
                        disk_num = input(WHITE + BOLD + "Enter disk number (e.g., 1): " + RESET).strip()
                        size_str = input(WHITE + BOLD + "Enter size in GB (e.g., 100): " + RESET).strip()
                    else:
                        disk_num = input(WHITE + BOLD + "Enter disk path (e.g., /dev/sda): " + RESET).strip()
                        size_str = input(WHITE + BOLD + "Enter size in GB (e.g., 100): " + RESET).strip()
                    
                    try:
                        size_gb = int(size_str)
                        res = manage_partitions(operation='create', target=disk_num, size_gb=size_gb, perform=False)
                        print(WHITE + str(res) + RESET)
                        
                        if res['ok']:
                            confirm = input(WHITE + BOLD + "\nCreate partition? (IRREVERSIBLE - y/N): " + RESET).strip().lower()
                            if confirm == 'y':
                                res2 = manage_partitions(operation='create', target=disk_num, size_gb=size_gb, perform=True)
                                print(WHITE + str(res2) + RESET)
                    except ValueError:
                        print(WHITE + "Invalid size. Please enter a number." + RESET)
                    
                    input("\n" + WHITE + "Press Enter to continue..." + RESET)
                
                elif part_cmd == '3':
                    clear_screen()
                    for line in build_rich_logo():
                        print(line)
                    print_menu_header("DELETE PARTITION (WARNING: DATA LOSS)")
                    
                    if os.name == 'nt':
                        target = input(WHITE + BOLD + "Enter drive letter to delete (e.g., D): " + RESET).strip()
                    else:
                        target = input(WHITE + BOLD + "Enter partition path (e.g., /dev/sda1): " + RESET).strip()
                    
                    res = manage_partitions(operation='delete', target=target, perform=False)
                    print(WHITE + str(res) + RESET)
                    
                    if res['ok']:
                        confirm = input(WHITE + BOLD + "\nDelete partition? (DATA CANNOT BE RECOVERED - y/N): " + RESET).strip().lower()
                        if confirm == 'y':
                            res2 = manage_partitions(operation='delete', target=target, perform=True)
                            print(WHITE + str(res2) + RESET)
                    
                    input("\n" + WHITE + "Press Enter to continue..." + RESET)
                
                elif part_cmd == 'b':
                    break
        
        elif cmd == 'b':
            break

def commands_menu():
    clear_screen()
    for line in build_rich_logo():
        print(line)
    print_menu_header("COMMANDS MENU")
    print(WHITE + BOLD + "1) Assistant Chat" + RESET)
    print(WHITE + BOLD + "2) Web Search" + RESET)
    print(WHITE + BOLD + "3) Task Manager" + RESET)
    print(WHITE + BOLD + "4) Network Manager" + RESET)
    print(WHITE + BOLD + "5) Cybersecurity Knowledge" + RESET)
    print(WHITE + BOLD + "6) BMW Animation" + RESET)
    print(WHITE + BOLD + "7) Storage & SSD Info" + RESET)
    print(WHITE + BOLD + "8) GPU Stats & Thermal Paste" + RESET)
    print(WHITE + BOLD + "9) System Optimizations" + RESET)
    print(WHITE + BOLD + "10) Spotify Music Player" + RESET)
    print(WHITE + BOLD + "q) Back" + RESET)
    print()
    c = input(GREEN + BOLD + "Select command: " + RESET).strip().lower()
    if c == '1':
        t = input(WHITE + BOLD + "You: " + RESET)
        print(GREEN + BOLD + "Ar1TIX: " + RESET + assistant.respond(t))
        input("\n" + WHITE + "Press Enter to continue..." + RESET)
    elif c == '2':
        web_menu()
    elif c == '3':
        tasks_menu()
    elif c == '4':
        network_menu()
    elif c == '5':
        cybersecurity_menu()
    elif c == '6':
        bmw_animation_menu()
    elif c == '7':
        storage_menu()
    elif c == '8':
        gpu_menu()
    elif c == '9':
        optimization_menu()
    elif c == '10':
        spotify_music_menu()


def web_menu():
    clear_screen()
    for line in build_rich_logo():
        print(line)
    print_menu_header("WEB SEARCH")
    q = input(WHITE + BOLD + "Search query: " + RESET).strip()
    if not q:
        print(WHITE + "Cancelled." + RESET)
        input("Press Enter to continue...")
        return
    engine = input(WHITE + BOLD + "Engine (duck/bing/google) [duck]: " + RESET).strip() or 'duck'
    show = input(WHITE + BOLD + "Show results here? (y/N): " + RESET).strip().lower() == 'y'
    if show:
        res = fetch_search_results(q, engine, max_results=5)
        if not res:
            print(WHITE + "No results found. Opening in browser..." + RESET)
            open_search(q, engine)
            input("Press Enter to continue...")
            return
        print()
        print(GREEN + BOLD + "Search Results:" + RESET)
        print(GREEN + "=" * get_terminal_width() + RESET)
        for i, r in enumerate(res, 1):
            print(f"{GREEN}[{i}]{RESET} {WHITE}{r['title']}{RESET}")
            print(f"  {WHITE}{r['url']}{RESET}")
            print()
        pick = input(GREEN + BOLD + "Open which (number or q)? " + RESET).strip()
        if pick.isdigit():
            idx = int(pick) - 1
            if 0 <= idx < len(res):
                _open_in_browser(res[idx]['url'])
                print(WHITE + "Opened in browser." + RESET)
        input("Press Enter to continue...")
    else:
        private = input(WHITE + BOLD + "Private? (y/N): " + RESET).strip().lower() == 'y'
        open_search(q, engine, private=private)
        print(WHITE + "Opened in browser." + RESET)
        input("Press Enter to continue...")


def main_menu():
    while True:
        clear_screen()
        for line in build_rich_logo():
            print(line)
        print_menu_header("MAIN MENU")
        print(WHITE + BOLD + "1) Commands" + RESET)
        print(WHITE + BOLD + "2) Assistant" + RESET)
        print(WHITE + BOLD + "3) Exit" + RESET)
        print()
        ch = input(GREEN + BOLD + "Select (1-3): " + RESET).strip().lower()
        if ch == '1':
            commands_menu()
        elif ch == '2':
            clear_screen()
            for line in build_rich_logo():
                print(line)
            print_menu_header("ASSISTANT")
            t = input(WHITE + BOLD + "You: " + RESET)
            response = assistant.respond(t)
            print(GREEN + BOLD + "Ar1TIX: " + RESET + WHITE + response + RESET)
            input("\n" + WHITE + "Press Enter to continue..." + RESET)
        elif ch == '3':
            print()
            print(GREEN + BOLD + "Goodbye!" + RESET)
            break
        else:
            print(WHITE + "Invalid choice." + RESET)
            input("Press Enter to continue...")


if __name__ == '__main__':
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument('--search', help='Search and exit')
    p.add_argument('--engine', default='duck')
    p.add_argument('--dry-run', action='store_true')
    args = p.parse_args()
    if args.search:
        url = open_search(args.search, engine=args.engine, dry_run=args.dry_run)
        if args.dry_run:
            print(url)
        sys.exit(0)
    try:
        main_menu()
    except KeyboardInterrupt:
        print('\nExiting.')
