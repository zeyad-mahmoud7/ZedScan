# ZedScan

A web-based network reconnaissance platform with a live streaming dashboard.
Runs four scanners concurrently: port scan, directory brute-force, subdomain enumeration, and SMB enumeration.

---

## Features

- **Port Scan** — nmap SYN/connect scan with service and OS detection
- **Directory Scan** — gobuster dir with live streaming results
- **Subdomain Enumeration** — gobuster dns with built-in fallback
- **SMB Enumeration** — smbmap / nmap / smbclient with MS17-010 (EternalBlue) detection
- **Dual Theme** — Cyber (SOC Dashboard) and Hacker (Terminal) modes
- **Export** — download full scan results as JSON

---

## Requirements

### Python
- Python 3.10 or higher

### External Tools

| Tool | Purpose | Required |
|------|---------|----------|
| `nmap` | Port scanning, OS detection, MS17-010 | Yes |
| `gobuster` | Directory and DNS scanning | Yes |
| `smbmap` | SMB share enumeration | Optional (fallback available) |
| `smbclient` | SMB share enumeration (fallback) | Optional |

---

## Installation

### Linux / Kali (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/zeyad-mahmoud7/ZedScan.git
cd ZedScan

# 2. Install external tools
sudo apt update && sudo apt install -y nmap gobuster smbmap smbclient

# 3. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 4. Install Python dependencies
pip install -r requirements.txt

# 5. Run ZedScan (use sudo for full nmap capabilities)
sudo python3 app.py
```

Then open your browser at: **http://127.0.0.1:5000**

---

### Windows

```powershell
# 1. Clone the repository
git clone https://github.com/zeyad-mahmoud7/ZedScan.git
cd ZedScan

# 2. Install external tools:
#    - nmap:     https://nmap.org/dist/nmap-7.95-setup.exe
#    - gobuster: https://github.com/OJ/gobuster/releases
#                Extract and add the folder to your system PATH

# 3. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate

# 4. Install Python dependencies
pip install -r requirements.txt

# 5. Run ZedScan (run terminal as Administrator for full nmap capabilities)
python app.py
```

Then open your browser at: **http://127.0.0.1:5000**

---

## Wordlists

ZedScan ships with two built-in wordlists in the `wordlists/` folder:

| File | Used For |
|------|---------|
| `wordlists/common.txt` | Directory scanning |
| `wordlists/dns.txt` | Subdomain enumeration |

For more thorough scanning, install SecLists and ZedScan will automatically detect and use them:

```bash
sudo apt install seclists
```

You can also provide a custom wordlist path directly in the UI.

---

## Usage Notes

- **Private IPs / custom hostnames** — add the target to `/etc/hosts` before scanning:
  ```
  10.10.10.10   target.htb
  ```
- **Scan speed** — T1 (stealthiest) to T5 (fastest). T4 is recommended for most targets.
- **UDP scan** — optional, significantly increases scan time.
- **MS17-010** — detected automatically when SMB (port 445) is open.

---

## Disclaimer

**This tool is intended for authorized penetration testing and educational purposes only. Only use it against systems you have explicit permission to test.**


## Author

**Zeyad Mahmoud** — [github.com/zeyad-mahmoud7](https://github.com/zeyad-mahmoud7)
