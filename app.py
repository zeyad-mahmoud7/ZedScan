import os
import json
import time
import platform
import threading
import subprocess
import concurrent.futures
import queue
import logging
import socket
import ipaddress
import tempfile
import re
import uuid
from collections import Counter
from datetime import datetime
from urllib.parse import urlparse

IS_WINDOWS = platform.system() == 'Windows'

import nmap
import httpx
import dns.resolver
import dns.exception
from flask import Flask, render_template, request, Response, jsonify

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

_sessions: dict = {}
_sessions_lock = threading.Lock()

_APP_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_WORDLISTS = [
    os.path.join(_APP_DIR, 'wordlists', 'common.txt'),
    r'C:\tools\SecLists\Discovery\Web-Content\common.txt',
    r'C:\SecLists\Discovery\Web-Content\common.txt',
    r'C:\Users\Public\wordlists\common.txt',
    '/usr/share/wordlists/dirb/common.txt',
    '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt',
    '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
]

DEFAULT_DNS_WORDLISTS = [
    os.path.join(_APP_DIR, 'wordlists', 'dns.txt'),
    '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
    '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
    '/usr/share/amass/wordlists/subdomains.lst',
    r'C:\tools\SecLists\Discovery\DNS\subdomains-top1million-5000.txt',
]

# Compact built-in fallback used when no external DNS wordlist is found
_BUILTIN_SUBDOMAIN_CANDIDATES = [
    'www', 'api', 'mail', 'dev', 'beta', 'test', 'admin', 'ftp', 'smtp',
    'webmail', 'secure', 'portal', 'vpn', 'staging', 'docs', 'git', 'shop',
    'db', 'm', 'owa', 'ns1', 'ns2', 'mx', 'remote', 'cdn', 'assets',
    'static', 'dashboard', 'app', 'login', 'auth', 'support', 'blog',
    'office', 'exchange', 'autodiscover', 'sip', 'monitor', 'status',
    'cloud', 'gateway', 'proxy', 'media', 'video', 'img', 'images',
    'download', 'downloads', 'upload', 'uploads', 'store', 'shop',
    'helpdesk', 'ticket', 'jira', 'confluence', 'wiki', 'intranet',
]


HTTP_TIMEOUT     = 8.0
GOBUSTER_TIMEOUT = 300

# Ports probed concurrently when no explicit port is given in the target URL.
# Ordered by real-world frequency so the first open hit is usually the right one.
_HTTP_PROBE_PORTS:  list = [80, 8080, 8000, 8008, 8888, 8081, 3000, 9000, 9080, 5000]
_HTTPS_PROBE_PORTS: list = [443, 8443, 4443]
_HTTPS_PORT_SET:    set  = set(_HTTPS_PROBE_PORTS)

# Browser UA so WAFs / CDNs don't filter gobuster's default user-agent string
_GOBUSTER_UA = (
    'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0'
)

# Strip ANSI colour codes that some gobuster builds emit even with -q
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mGKHFJ]')

# Gobuster changed --no-error to --noerror (no hyphen) in some builds.
# Probe the help text once at startup so the right flag is always used.
def _detect_gobuster_no_err_flag() -> str:
    """
    Probe gobuster's help text to pick the right suppress-errors flag.
    - Modern gobuster (v3.1+): --no-error  (hyphenated)
    - Some older/patched builds: --noerror  (no hyphen)
    Defaults to --no-error when detection fails (correct for Kali stock builds).
    """
    try:
        r = subprocess.run(
            ['gobuster', 'dir', '--help'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            encoding='utf-8', errors='replace', timeout=6,
        )
        help_text = r.stdout or ''
        # Check hyphenated form first — it is the canonical modern flag
        if '--no-error' in help_text:
            return '--no-error'
        if '--noerror' in help_text:
            return '--noerror'
    except Exception:
        pass
    return '--no-error'   # correct default for Kali stock gobuster

_GOBUSTER_NO_ERR_FLAG = _detect_gobuster_no_err_flag()
logger.info('gobuster no-error flag detected: %s', _GOBUSTER_NO_ERR_FLAG)

# Detect whether gobuster vhost supports --append-domain (v3.2+).
# Without it we pre-build a temp wordlist with full vhost names.
def _detect_gobuster_append_domain() -> bool:
    try:
        r = subprocess.run(
            ['gobuster', 'vhost', '--help'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            encoding='utf-8', errors='replace', timeout=6,
        )
        return '--append-domain' in (r.stdout or '')
    except Exception:
        return False

_GOBUSTER_APPEND_DOMAIN = _detect_gobuster_append_domain()
logger.info('gobuster vhost --append-domain supported: %s', _GOBUSTER_APPEND_DOMAIN)

# Detect whether gobuster vhost supports --exclude-length (v3.3+).
def _detect_gobuster_exclude_length() -> bool:
    try:
        r = subprocess.run(
            ['gobuster', 'vhost', '--help'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            encoding='utf-8', errors='replace', timeout=6,
        )
        return '--exclude-length' in (r.stdout or '')
    except Exception:
        return False

_GOBUSTER_EXCLUDE_LENGTH = _detect_gobuster_exclude_length()
logger.info('gobuster vhost --exclude-length supported: %s', _GOBUSTER_EXCLUDE_LENGTH)

# Regex: gobuster dns "Found:" output line  (format stable across versions)
_GOBUSTER_FOUND_RE = re.compile(r'^Found:\s+(\S+)')

# Gobuster vhost output changed in v3.6+ — the "Found:" prefix was removed.
# Old format:  Found: staging.domain.htb (Status: 200) [Size: 3142]
# New format:  staging.domain.htb Status: 200 [Size: 3142]
# This regex matches both by making the "Found:" prefix optional.
_GOBUSTER_VHOST_RE = re.compile(
    r'^(?:Found:\s+)?(\S+\.\S+)\s+\(?Status:\s*\d+',
    re.IGNORECASE,
)

# Primary gobuster line parser.
# Modern gobuster omits the leading slash:  index.php  (Status: 200) [Size: 1234]
# Older builds include it:                 /index.php  (Status: 200) [Size: 1234]
# The pattern accepts both; path is normalised to always start with / below.
_GOBUSTER_RE = re.compile(
    r'^(/?[\S]+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?(?:\s+\[-+>\s*(\S+?)\])?'
)

_WWW_PREFIXES = ('www.', 'm.', 'mobile.', 'wap.', 'mail.', 'ftp.', 'smtp.')

PORT_LABELS: dict = {
    21: 'FTP',       22: 'SSH',        23: 'Telnet',      25: 'SMTP',
    53: 'DNS',       67: 'DHCP',       69: 'TFTP',        80: 'HTTP',
    110: 'POP3',     111: 'RPC',       119: 'NNTP',       123: 'NTP',
    135: 'MS-RPC',   137: 'NetBIOS',   138: 'NetBIOS',    139: 'NetBIOS',
    143: 'IMAP',     161: 'SNMP',      389: 'LDAP',       443: 'HTTPS',
    445: 'SMB',      465: 'SMTPS',     512: 'rExec',      513: 'rLogin',
    514: 'Syslog',   587: 'SMTP-Sub',  636: 'LDAPS',      873: 'rsync',
    993: 'IMAPS',    995: 'POP3S',     1433: 'MSSQL',     1521: 'Oracle DB',
    2049: 'NFS',     2375: 'Docker',   3306: 'MySQL',     3389: 'RDP',
    5432: 'PostgreSQL', 5900: 'VNC',   5985: 'WinRM',     6379: 'Redis',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch',
    11211: 'Memcached', 27017: 'MongoDB',
}

# OS fingerprint patterns matched against combined nmap -sV service banners.
# Ordered most-specific → most-generic so the first match per port wins.
_OS_BANNER_PATTERNS = [
    (r'microsoft|windows.*server|iis|ms-sql|netlogon|exchange', 'Windows'),
    (r'ubuntu',                       'Linux (Ubuntu)'),
    (r'debian',                       'Linux (Debian)'),
    (r'centos|red.?hat|rhel|fedora',  'Linux (CentOS/RHEL)'),
    (r'alpine',                       'Linux (Alpine)'),
    (r'freebsd',                      'FreeBSD'),
    (r'netbsd',                       'NetBSD'),
    (r'openbsd',                      'OpenBSD'),
    (r'mac.?os|darwin',               'macOS'),
    (r'cisco',                        'Cisco IOS'),
    (r'linux|openssh',                'Linux'),
]


# ══════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════

def is_ip(host: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except (OSError, AttributeError):
            pass
    return False


def normalize(target: str) -> str:
    target = target.strip()
    for pfx in ('https://', 'http://'):
        if target.startswith(pfx):
            target = target[len(pfx):]
    return target.rstrip('/')


def extract_hostname(target: str) -> str:
    host = normalize(target)
    host = host.split('/')[0].split('?')[0].split(':')[0]
    return host.lower().strip()


def strip_www(host: str) -> str:
    for pfx in _WWW_PREFIXES:
        if host.startswith(pfx):
            base = host[len(pfx):]
            if '.' in base:
                return base
    return host


def sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"


def friendly_error(exc: Exception, context: str = 'Operation') -> str:
    msg = str(exc).lower()
    if any(k in msg for k in ('connection refused', 'errno 111', 'econnrefused')):
        return 'No Website Found'
    if any(k in msg for k in ('timed out', 'timeout', 'etimedout', 'lifetime')):
        return f'{context}: Request timed out — target may be offline or rate-limiting scans.'
    if any(k in msg for k in ('name or service not known', 'nodename nor servname',
                               'no such host', 'getaddrinfo', 'failed to resolve')):
        return f'{context}: Hostname could not be resolved — check the domain name and DNS.'
    if any(k in msg for k in ('network unreachable', 'errno 101', 'enetunreach')):
        return f'{context}: Network unreachable — check your network connection.'
    if any(k in msg for k in ('permission denied', 'errno 13', 'eacces',
                               'requires root', 'you requested a scan type')):
        return f'{context}: Permission denied — run ZedScan as root for full capabilities.'
    if any(k in msg for k in ('no route to host', 'errno 113', 'ehostunreach')):
        return f'{context}: No route to host — target may be offline or behind a firewall.'
    if any(k in msg for k in ('broken pipe', 'errno 32', 'epipe')):
        return f'{context}: Connection dropped unexpectedly.'
    if any(k in msg for k in ('ssl', 'certificate', 'handshake')):
        return f'{context}: SSL/TLS negotiation failed — certificate may be invalid.'
    return f'{context}: Unexpected error — target may be unreachable or protected.'


# ── HTTP port discovery ───────────────────────────────────────────────────────

def _find_http_port(host: str, target: str) -> tuple:
    """
    Return (scheme, port) to use for web-based scanning (gobuster dir / vhost).

    Resolution order
    ────────────────
    1. Explicit port written in the target string
         http://host:8080  →  ('http', 8080)
         https://host:8443 →  ('https', 8443)
         host:8080         →  ('http', 8080)
    2. Concurrent TCP probe of common HTTP/HTTPS ports.
         First port that accepts a connection wins.
         Port ≥443-class → 'https', otherwise 'http'.
    3. Hard fallback: ('http', 80).
    """
    t = target.strip()

    # ── 1. Explicit port in URL ──────────────────────────────────────────
    for pfx, pfx_scheme in (('https://', 'https'), ('http://', 'http')):
        if t.lower().startswith(pfx):
            netloc = t[len(pfx):].split('/')[0].split('?')[0]
            if ':' in netloc and not netloc.startswith('['):   # skip IPv6
                try:
                    port = int(netloc.rsplit(':', 1)[1])
                    logger.info('HTTP scan: explicit port from URL → %s:%d', pfx_scheme, port)
                    return pfx_scheme, port
                except ValueError:
                    pass
            # Scheme present but no port → fall through to probe
            break

    # bare  host:PORT  (no scheme prefix)
    if ':' in t and '://' not in t and not t.startswith('['):
        parts = t.rsplit(':', 1)
        if parts[1].isdigit():
            port   = int(parts[1])
            scheme = 'https' if port in _HTTPS_PORT_SET else 'http'
            logger.info('HTTP scan: bare host:port → %s:%d', scheme, port)
            return scheme, port

    # ── 2. Concurrent TCP probe ──────────────────────────────────────────
    # Reorder based on scheme hint so the most-likely port is checked first
    tl = t.lower()
    if tl.startswith('https://'):
        probe_order = [443, 8443, 4443] + [p for p in _HTTP_PROBE_PORTS]
    elif tl.startswith('http://'):
        probe_order = _HTTP_PROBE_PORTS + [443, 8443]
    else:
        probe_order = [80, 8080, 443, 8443] + [
            p for p in _HTTP_PROBE_PORTS if p not in (80, 8080)
        ] + [p for p in _HTTPS_PROBE_PORTS if p not in (443, 8443)]

    def _tcp_open(port: int) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            ok = s.connect_ex((host, port)) == 0
            s.close()
            return ok
        except Exception:
            return False

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(len(probe_order), 12)) as ex:
        results = dict(zip(probe_order, ex.map(_tcp_open, probe_order)))

    for p in probe_order:
        if results.get(p):
            scheme = 'https' if p in _HTTPS_PORT_SET else 'http'
            logger.info('HTTP port probe: selected %s:%d for %s', scheme, p, host)
            return scheme, p

    # ── 3. Fallback ──────────────────────────────────────────────────────
    logger.info('HTTP port probe: nothing open on %s — defaulting to http:80', host)
    return 'http', 80


# ── OS detection from nmap -sV service banners ────────────────────────────────

def _detect_os_from_banners(nm_host) -> str | None:
    """
    Infer OS from nmap -sV product/version/extrainfo banners per open port.
    Votes are tallied per port so multiple corroborating banners win.
    Returns the top-voted OS name, or None if no pattern matched.
    """
    votes: Counter = Counter()
    for proto in nm_host.all_protocols():
        for pnum in nm_host[proto]:
            pd = nm_host[proto][pnum]
            if pd.get('state') != 'open':
                continue
            banner = ' '.join(filter(None, [
                pd.get('product',   '') or '',
                pd.get('version',   '') or '',
                pd.get('extrainfo', '') or '',
                pd.get('name',      '') or '',
            ]))
            for pattern, os_name in _OS_BANNER_PATTERNS:
                if re.search(pattern, banner, re.IGNORECASE):
                    votes[os_name] += 1
                    break
    return votes.most_common(1)[0][0] if votes else None


# ══════════════════════════════════════════════════════════════
#  SMB Helpers
# ══════════════════════════════════════════════════════════════

def _normalize_access(raw: str) -> str:
    a = raw.strip().upper()
    if 'WRITE' in a and 'READ' in a:
        return 'READ, WRITE'
    if 'WRITE' in a:
        return 'WRITE'
    if 'READ' in a:
        return 'READ ONLY'
    return 'NO ACCESS'


def _strip_share_prefix(raw_name: str) -> str:
    cleaned = re.sub(r'^[\\\/]{2}[^\\\/]+[\\\/]+', '', raw_name.strip())
    return cleaned.rstrip('\\/') or raw_name.strip()


def _check_ms17010(target: str) -> bool:
    """
    Active MS17-010 (EternalBlue) check via dedicated nmap subprocess.

    Runs exactly:  nmap -p 445 --script smb-vuln-ms17-010 -Pn -T4 <target>

    Stdout is parsed for two patterns (in priority order):
      1. 'State: VULNERABLE'  — the script's primary state-block marker
      2. 'VULNERABLE' inside the smb-vuln-ms17-010 script output block

    Returns True ONLY on confirmed vulnerability.  Silent on all other
    outcomes (port closed, inconclusive, script error, nmap not found).
    """
    cmd = ['nmap', '-p', '445', '--script', 'smb-vuln-ms17-010', '-Pn', '-T4', target]

    run_kw: dict = {
        'stdout':   subprocess.PIPE,
        'stderr':   subprocess.STDOUT,
        'encoding': 'utf-8',
        'errors':   'replace',
        'timeout':  90,
    }
    if IS_WINDOWS:
        run_kw['creationflags'] = subprocess.CREATE_NO_WINDOW

    try:
        proc   = subprocess.run(cmd, **run_kw)
        output = proc.stdout or ''

        # Primary: vulnerability state block explicitly marked VULNERABLE
        if re.search(r'State:\s*VULNERABLE', output, re.IGNORECASE):
            logger.warning('MS17-010 VULNERABLE (State: VULNERABLE) on %s', target)
            return True

        # Secondary: VULNERABLE appears within the script's output block
        block = re.search(
            r'smb-vuln-ms17-010:(.*?)(?=\n\S|\Z)',
            output, re.IGNORECASE | re.DOTALL,
        )
        if block and re.search(r'\bVULNERABLE\b', block.group(1), re.IGNORECASE):
            logger.warning('MS17-010 VULNERABLE (script block) on %s', target)
            return True

        return False

    except subprocess.TimeoutExpired:
        logger.debug('MS17-010 check timed out for %s', target)
        return False
    except FileNotFoundError:
        logger.debug('nmap not found — MS17-010 check skipped for %s', target)
        return False
    except Exception as exc:
        logger.debug('MS17-010 check error for %s: %s', target, exc)
        return False


def _run_smbmap(target: str) -> list:
    try:
        proc = subprocess.run(
            ['smbmap', '-H', target],
            capture_output=True, text=True, timeout=30,
        )
        return _parse_smbmap_output(proc.stdout + proc.stderr)
    except FileNotFoundError:
        logger.info('smbmap not installed — falling back to nmap smb-enum-shares')
        return []
    except Exception as exc:
        logger.debug('smbmap error: %s', exc)
        return []


def _parse_smbmap_output(output: str) -> list:
    """
    Parse smbmap stdout → [{'name', 'access', 'comment'}].

    smbmap tab-separated table format:
        Disk          Permissions    Comment
        ----          -----------    -------
        ADMIN$        NO ACCESS      Remote Admin
        Backup        READ ONLY
    """
    shares, in_table = [], False

    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith('['):
            continue
        if re.search(r'\bDisk\b.*\bPermissions\b.*\bComment\b', stripped, re.IGNORECASE):
            in_table = True
            continue
        if in_table and re.match(r'^-{3,}', stripped):
            continue
        if not in_table or not stripped:
            continue

        parts = (
            [p.strip() for p in line.split('\t') if p.strip()]
            if '\t' in line
            else [p.strip() for p in re.split(r'\s{3,}', stripped) if p.strip()]
        )
        if not parts:
            continue

        name    = parts[0]
        access  = parts[1] if len(parts) > 1 else 'NO ACCESS'
        comment = parts[2] if len(parts) > 2 else ''

        if ':' in name or name.startswith('['):
            continue

        shares.append({'name': name, 'access': access, 'comment': comment})

    return shares


def _parse_smb_shares(raw) -> list:
    if not raw:
        return []
    shares = []

    if isinstance(raw, dict):
        for key, val in raw.items():
            k = str(key).strip()
            if re.match(r'^[\\\/]{2}', k):
                name = _strip_share_prefix(k)
                if isinstance(val, dict):
                    anon    = str(val.get('Anonymous access')    or '').strip()
                    user    = str(val.get('Current user access') or '').strip()
                    comment = str(val.get('Comment')             or '').strip()
                    comment = '' if comment.lower() in ('', 'none', 'null') else comment
                    shares.append({'name': name, 'access': _normalize_access(anon or user),
                                   'comment': comment})
                else:
                    shares.append({'name': name, 'access': 'NO ACCESS', 'comment': ''})
    else:
        current = None
        for line in str(raw).splitlines():
            stripped = line.strip()
            if re.match(r'^[\\\/]{2}', stripped):
                if current:
                    shares.append(current)
                raw_name = stripped.split()[0]
                current  = {'name': _strip_share_prefix(raw_name),
                             'access': 'NO ACCESS', 'comment': ''}
            elif current:
                if re.search(r'access', stripped, re.IGNORECASE):
                    m = re.search(r'(READ/WRITE|READ, WRITE|WRITE|READ|NO ACCESS)',
                                  stripped, re.IGNORECASE)
                    if m:
                        current['access'] = _normalize_access(m.group(1))
                elif re.search(r'comment', stripped, re.IGNORECASE):
                    m = re.search(r'Comment[:\s]+(.+)', stripped, re.IGNORECASE)
                    if m:
                        current['comment'] = m.group(1).strip()
        if current:
            shares.append(current)

    return shares


def _smbclient_shares(target: str) -> list:
    try:
        proc = subprocess.run(
            ['smbclient', '-N', '-L', f'//{target}', '--no-pass'],
            capture_output=True, text=True, timeout=15,
        )
        shares, capture = [], False
        for line in (proc.stdout + proc.stderr).splitlines():
            stripped = line.strip()
            if re.search(r'Sharename\s+Type', stripped, re.IGNORECASE):
                capture = True
                continue
            if capture:
                m = re.match(r'\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*)', line, re.IGNORECASE)
                if m:
                    name, _, comment = m.groups()
                    shares.append({'name': name, 'access': 'NO ACCESS',
                                   'comment': comment.strip()})
                elif stripped == '' and shares:
                    break
        return shares
    except FileNotFoundError:
        return []
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════
#  Session Management
# ══════════════════════════════════════════════════════════════

def create_session(target: str, speed: str, include_udp: str, wordlist: str) -> str:
    sid = str(uuid.uuid4())
    with _sessions_lock:
        _sessions[sid] = {
            'id':          sid,
            'target':      target,
            'speed':       speed,
            'include_udp': include_udp,
            'wordlist':    wordlist,
            'started_at':  datetime.utcnow().isoformat() + 'Z',
            'status':      'running',
            'os':          None,
            'ports':       [],
            'directories': [],
            'subdomains':  [],
            'smb':         {},
            'tool_status': {t: 'pending' for t in ('nmap', 'gobuster', 'subdomain', 'smb')},
            '_q':          queue.Queue(),
            '_lock':       threading.Lock(),
        }
    return sid


def get_session(sid: str) -> dict | None:
    with _sessions_lock:
        return _sessions.get(sid)


def s_append(sess: dict, key: str, val) -> None:
    with sess['_lock']:
        sess[key].append(val)


def s_set(sess: dict, key: str, val) -> None:
    with sess['_lock']:
        sess[key] = val


def emit(sess: dict, payload: dict) -> None:
    sess['_q'].put(payload)


# ══════════════════════════════════════════════════════════════
#  Scanners
# ══════════════════════════════════════════════════════════════

def scan_nmap(sess: dict) -> bool:
    target = sess['target']
    sess['tool_status']['nmap'] = 'running'
    emit(sess, {'type': 'tool_status', 'tool': 'nmap', 'status': 'running',
                'msg': 'Port scan in progress...'})
    logger.info('Port scan: %s  T%s  udp=%s', target, sess['speed'], sess['include_udp'])

    try:
        nm = nmap.PortScanner()
        if IS_WINDOWS:
            args = f"-sT -sC -sV -Pn -T{sess['speed']}"
        else:
            args = f"-sS -sC -sV -Pn -O -T{sess['speed']}"
        if sess['include_udp'] == 'yes':
            args += ' -sU --top-ports 100'

        nm.scan(hosts=target, arguments=args)
        ports, detected_os, smb_found = [], 'Unknown', False

        for host in nm.all_hosts():
            os_matches = nm[host].get('osmatch') or []
            if os_matches:
                detected_os = os_matches[0]['name']

            for proto in nm[host].all_protocols():
                for pnum in sorted(nm[host][proto]):
                    pd = nm[host][proto][pnum]
                    if pd.get('state') != 'open':
                        continue
                    # ── Clean service name ──────────────────────────────
                    raw_svc = (pd.get('name') or '').strip().lower()
                    if raw_svc in ('tcpwrapped', 'unknown', ''):
                        # tcpwrapped = port open but service didn't respond;
                        # fall back to our label map, then generic 'Open Port'
                        service_name = PORT_LABELS.get(pnum, 'Open Port')
                    else:
                        service_name = raw_svc.upper() if len(raw_svc) <= 5 else raw_svc.title()

                    # ── Clean version banner ─────────────────────────────
                    product = (pd.get('product') or '').strip()
                    version = (pd.get('version') or '').strip()
                    extra   = (pd.get('extrainfo') or '').strip()
                    parts   = [p for p in [product, version] if p]
                    if extra and extra not in ('tcpwrapped',):
                        parts.append(f'({extra})')
                    banner = ' '.join(parts)

                    entry  = {
                        'port':       pnum,
                        'proto':      proto.upper(),
                        'label':      f'{pnum}/{proto.upper()}',
                        'service':    service_name,
                        'version':    banner,
                        'port_label': PORT_LABELS.get(pnum, ''),
                    }
                    ports.append(entry)
                    s_append(sess, 'ports', entry)
                    if proto == 'tcp' and pnum in {139, 445}:
                        smb_found = True

            # Fallback: infer OS from -sV banners when -O is unavailable
            if detected_os == 'Unknown' and ports:
                banner_os = _detect_os_from_banners(nm[host])
                if banner_os:
                    detected_os = banner_os

        s_set(sess, 'os', detected_os)
        sess['tool_status']['nmap'] = 'completed'
        emit(sess, {'type': 'ports', 'data': ports, 'os': detected_os})
        emit(sess, {'type': 'tool_status', 'tool': 'nmap', 'status': 'completed',
                    'msg': f'{len(ports)} open port(s) discovered'})
        logger.info('Port scan done: %d ports  OS=%s  SMB=%s', len(ports), detected_os, smb_found)
        return smb_found

    except Exception as exc:
        logger.exception('Port scan failed')
        sess['tool_status']['nmap'] = 'error'
        emit(sess, {'type': 'tool_status', 'tool': 'nmap', 'status': 'error',
                    'msg': friendly_error(exc, 'Port scan')})
        return False


def resolve_gobuster_url(scheme: str, host: str, port: int = 0) -> tuple:
    """
    Follow HTTP redirects to resolve the real scan base URL before launching
    gobuster, so the scanner always targets the correct final hostname.

    port=0 means 'use the scheme default (80/443)'.
    Non-default ports are written explicitly into the URL (e.g. http://host:8080).

    Returns (final_url: str, reachable: bool).
    reachable=False means a connection-refused error — no web server present.
    """
    default_port = 443 if scheme == 'https' else 80
    if port and port != default_port:
        base = f'{scheme}://{host}:{port}'
    else:
        base = f'{scheme}://{host}'
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT, verify=False,
                          follow_redirects=True) as c:
            r     = c.head(base)
            final = str(r.url).rstrip('/')
            if final != base:
                logger.info('Dir scan: redirect %s → %s', base, final)
            return final, True
    except httpx.ConnectError:
        return base, False
    except Exception:
        return base, True


def scan_gobuster(sess: dict) -> None:
    target = sess['target']
    sess['tool_status']['gobuster'] = 'running'
    emit(sess, {'type': 'tool_status', 'tool': 'gobuster', 'status': 'running',
                'msg': 'Detecting HTTP port...'})

    host          = extract_hostname(target)
    scheme, port  = _find_http_port(host, target)

    port_display  = f':{port}' if port not in (80, 443) else ''
    emit(sess, {'type': 'tool_status', 'tool': 'gobuster', 'status': 'running',
                'msg': f'Directory brute-force on {scheme}://{host}{port_display}...'})

    base_url, reachable = resolve_gobuster_url(scheme, host, port)
    if not reachable:
        sess['tool_status']['gobuster'] = 'error'
        emit(sess, {'type': 'tool_status', 'tool': 'gobuster', 'status': 'error',
                    'msg': 'No Website Found'})
        return

    # Gobuster outputs paths from the URL root (e.g. /admin), not relative to
    # any sub-path in base_url.  Extract just scheme+host for link construction
    # so that /admin always resolves to http://host/admin even after redirects.
    _p        = urlparse(base_url)
    link_root = f"{_p.scheme}://{_p.netloc}"

    custom_wl = sess.get('wordlist', '')
    wordlist  = (custom_wl if custom_wl and os.path.exists(custom_wl)
                 else next((p for p in DEFAULT_WORDLISTS if os.path.exists(p)), None))

    if not wordlist:
        sess['tool_status']['gobuster'] = 'error'
        emit(sess, {'type': 'tool_status', 'tool': 'gobuster', 'status': 'error',
                    'msg': 'Default wordlist not found — please add your wordlist path in the Wordlist field'})
        return

    cmd = [
        'gobuster', 'dir',
        '-u', base_url,
        '-w', wordlist,
        '-a', _GOBUSTER_UA,
        '-q',                   # quiet — no progress bars
        '-k',                   # skip TLS verify (self-signed certs are common)
        '-t', '50',             # 50 threads for throughput
        '--timeout', '10s',     # per-request HTTP timeout
        _GOBUSTER_NO_ERR_FLAG,  # --noerror or --no-error depending on version
        '--follow-redirect',    # record redirected paths too
    ]

    # On Windows: explicit UTF-8 encoding avoids cp1252 decode errors from
    # gobuster output; CREATE_NO_WINDOW keeps the terminal hidden in GUI mode.
    popen_kwargs: dict = {
        'stdout':   subprocess.PIPE,
        'stderr':   subprocess.STDOUT,
        'encoding': 'utf-8',
        'errors':   'replace',
        'bufsize':  1,
    }
    if IS_WINDOWS:
        popen_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW

    count = 0
    proc  = None

    try:
        proc = subprocess.Popen(cmd, **popen_kwargs)

        for raw in proc.stdout:
            line = _ANSI_RE.sub('', raw).strip()
            if not line:
                continue

            m = _GOBUSTER_RE.match(line)
            if m:
                path, status, size, redir = m.groups()
                path = path.rstrip('/')
                if not path.startswith('/'):
                    path = '/' + path
                entry = {
                    'path':     path,
                    'status':   int(status),
                    'size':     int(size) if size else None,
                    'redirect': redir or '',
                    'url':      f'{link_root}{path}',
                }
            elif re.search(r'\(Status:\s*\d+\)', line):
                # Fallback for non-standard gobuster output formats
                status_m = re.search(r'\(Status:\s*(\d+)\)', line)
                path = line.split('(')[0].strip().rstrip('/')
                if not path.startswith('/'):
                    path = '/' + path
                entry = {
                    'path':     path,
                    'status':   int(status_m.group(1)),
                    'size':     None,
                    'redirect': '',
                    'url':      f'{link_root}{path}',
                }
            else:
                # Banners, error lines, progress output — skip
                logger.debug('Dir scan non-result line: %s', line[:200])
                continue

            count += 1
            s_append(sess, 'directories', entry)
            emit(sess, {'type': 'directory', 'data': entry})

        proc.wait(timeout=GOBUSTER_TIMEOUT)
        sess['tool_status']['gobuster'] = 'completed'
        noun = 'directory' if count == 1 else 'directories'
        emit(sess, {'type': 'tool_status', 'tool': 'gobuster', 'status': 'completed',
                    'msg': f'{count} {noun} discovered'})
        logger.info('Dir scan done: %d paths', count)

    except FileNotFoundError:
        sess['tool_status']['gobuster'] = 'error'
        emit(sess, {'type': 'tool_status', 'tool': 'gobuster', 'status': 'error',
                    'msg': 'gobuster is not installed — run: apt install gobuster'})
    except subprocess.TimeoutExpired:
        if proc:
            proc.kill()
        sess['tool_status']['gobuster'] = 'error'
        emit(sess, {'type': 'tool_status', 'tool': 'gobuster', 'status': 'error',
                    'msg': f'Directory scan timed out after {GOBUSTER_TIMEOUT}s'})
    except Exception as exc:
        logger.exception('Dir scan failed')
        sess['tool_status']['gobuster'] = 'error'
        emit(sess, {'type': 'tool_status', 'tool': 'gobuster', 'status': 'error',
                    'msg': friendly_error(exc, 'Directory scan')})


def _resolve_ips(hostname: str) -> list:
    """
    Resolve hostname → IP list using the SYSTEM resolver (respects /etc/hosts).
    Falls back to empty list on any error.
    """
    try:
        results = socket.getaddrinfo(hostname, None)
        seen, ips = set(), []
        for r in results:
            ip = r[4][0]
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
        return ips
    except Exception:
        return []


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _domain_resolves_private(host: str) -> tuple:
    """
    Resolve host via system resolver (honours /etc/hosts).
    Returns (is_private: bool, first_ip: str).
    """
    ips = _resolve_ips(host)
    if not ips:
        return False, ''
    return _is_private_ip(ips[0]), ips[0]


def _gobuster_popen_kw() -> dict:
    kw = {
        'stdout':   subprocess.PIPE,
        'stderr':   subprocess.STDOUT,
        'encoding': 'utf-8',
        'errors':   'replace',
        'bufsize':  1,
    }
    if IS_WINDOWS:
        kw['creationflags'] = subprocess.CREATE_NO_WINDOW
    return kw


def _vhost_baseline_size(base_url: str, domain: str) -> int | None:
    """
    Measure the response size for a random non-existent vhost so we can
    pass --exclude-length to gobuster and filter out false-positive matches.
    Returns body size in bytes, or None if the probe fails.
    """
    fake_host = f'nonexistent{uuid.uuid4().hex[:8]}.{domain}'
    try:
        with httpx.Client(timeout=8, verify=False, follow_redirects=False) as c:
            resp = c.get(base_url, headers={'Host': fake_host})
            # Prefer the declared Content-Length; fall back to actual body length
            cl = resp.headers.get('content-length', '')
            if cl.isdigit():
                return int(cl)
            return len(resp.content)
    except Exception as exc:
        logger.info('Vhost baseline probe failed: %s', exc)
        return None


def _scan_subdomains_vhost(sess: dict, domain: str, base_ip: str, wordlist: str,
                            http_scheme: str = 'http', http_port: int = 80) -> int:
    """
    Virtual host enumeration via gobuster vhost.
    Sends HTTP requests with Host: <candidate>.<domain> headers.
    Works for private / CTF / HackTheBox targets that rely on /etc/hosts.

    http_scheme / http_port are determined by _find_http_port() before this
    function is called, so we already know which port the web server listens on.

    Returns count found, or -1 if gobuster is unavailable.
    """
    # ── 1. Build base URL with the correct port ───────────────────────────
    default_port = 443 if http_scheme == 'https' else 80
    if http_port != default_port:
        base_url = f'{http_scheme}://{domain}:{http_port}'
    else:
        base_url = f'{http_scheme}://{domain}'
    logger.info('Vhost scan: base URL → %s', base_url)

    # ── 2. Baseline probe — measure "not found" response size ────────────
    baseline_size = _vhost_baseline_size(base_url, domain)
    logger.info('Vhost baseline (non-existent vhost) response size: %s', baseline_size)

    # ── 3. Build gobuster command ─────────────────────────────────────────
    tmp_path = None

    base_cmd = [
        'gobuster', 'vhost',
        '-u', base_url,
        '-q',               # suppress progress bars
        '-k',               # skip TLS verification (self-signed certs)
        '-t', '30',         # threads — keep modest for CTF targets
        '--timeout', '10s', # per-request timeout
    ]

    # Add --exclude-length to filter responses that look like "not found"
    if baseline_size is not None and _GOBUSTER_EXCLUDE_LENGTH:
        base_cmd.extend(['--exclude-length', str(baseline_size)])
        logger.info('Vhost: filtering responses of size %d (baseline)', baseline_size)

    if _GOBUSTER_APPEND_DOMAIN:
        cmd = base_cmd + ['-w', wordlist, '--append-domain']
    else:
        # Older gobuster — pre-build a temp wordlist with full vhost names
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        try:
            with open(wordlist, encoding='utf-8', errors='replace') as wl:
                for line in wl:
                    word = line.strip()
                    if word and not word.startswith('#'):
                        tmp.write(f'{word}.{domain}\n')
        finally:
            tmp.flush()
            tmp_path = tmp.name
            tmp.close()
        cmd = base_cmd + ['-w', tmp_path]

    logger.info('Vhost command: %s', ' '.join(cmd))

    # ── 4. Run gobuster and stream results ────────────────────────────────
    found = 0
    proc  = None
    try:
        proc = subprocess.Popen(cmd, **_gobuster_popen_kw())
        for raw in proc.stdout:
            line = _ANSI_RE.sub('', raw).strip()
            if not line:
                continue
            # Log every output line at INFO so we can diagnose issues
            logger.info('Vhost gobuster output: %s', line[:200])
            m = _GOBUSTER_VHOST_RE.match(line)
            if not m:
                continue
            vhost = m.group(1).rstrip('.,')
            ips   = _resolve_ips(vhost) or ([base_ip] if base_ip else [])
            entry = {'subdomain': vhost, 'addresses': ips}
            found += 1
            s_append(sess, 'subdomains', entry)
            emit(sess, {'type': 'subdomain', 'data': entry})
            logger.info('Vhost found: %s → %s', vhost, ips)
        proc.wait(timeout=300)
        logger.info('Vhost scan complete: %d found', found)
    except FileNotFoundError:
        logger.info('gobuster not found — vhost scan skipped')
        return -1
    except Exception as exc:
        logger.info('Vhost scan error: %s', exc)
        if proc:
            proc.kill()
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
    return found


def _scan_subdomains_dns(sess: dict, domain: str, wordlist: str) -> int:
    """
    DNS subdomain brute-force via gobuster dns.
    Used for public internet-facing targets where DNS records exist.
    Returns count found, or -1 if gobuster is unavailable.
    """
    cmd = [
        'gobuster', 'dns',
        '-d', domain,
        '-w', wordlist,
        '-q',
        _GOBUSTER_NO_ERR_FLAG,
        '-t', '50',
        '--timeout', '5s',
    ]
    found = 0
    proc  = None
    try:
        proc = subprocess.Popen(cmd, **_gobuster_popen_kw())
        for raw in proc.stdout:
            line = _ANSI_RE.sub('', raw).strip()
            if not line:
                continue
            m = _GOBUSTER_FOUND_RE.match(line)
            if not m:
                logger.debug('DNS scan non-result: %s', line[:120])
                continue
            subdomain = m.group(1).rstrip('.')
            ips       = _resolve_ips(subdomain)
            entry     = {'subdomain': subdomain, 'addresses': ips}
            found    += 1
            s_append(sess, 'subdomains', entry)
            emit(sess, {'type': 'subdomain', 'data': entry})
            logger.info('Subdomain found: %s → %s', subdomain, ips)
        proc.wait(timeout=300)
    except FileNotFoundError:
        logger.info('gobuster not found — DNS scan skipped')
        return -1
    except Exception as exc:
        logger.debug('Gobuster DNS error: %s', exc)
        if proc:
            proc.kill()
    return found


def _scan_subdomains_builtin(sess: dict, domain: str) -> int:
    """
    Fallback: DNS brute-force via dnspython + built-in candidate list.
    Used when gobuster is unavailable or no wordlist exists.
    """
    resolver          = dns.resolver.Resolver()
    resolver.timeout  = 3
    resolver.lifetime = 6
    found = 0
    for name in _BUILTIN_SUBDOMAIN_CANDIDATES:
        hostname = f'{name}.{domain}'
        try:
            answers = resolver.resolve(hostname, 'A')
            ips     = [r.to_text() for r in answers]
            entry   = {'subdomain': hostname, 'addresses': ips}
            found  += 1
            s_append(sess, 'subdomains', entry)
            emit(sess, {'type': 'subdomain', 'data': entry})
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception as exc:
            logger.debug('Subdomain lookup %s: %s', hostname, exc)
    return found


def scan_subdomains(sess: dict) -> None:
    target = sess['target']
    sess['tool_status']['subdomain'] = 'running'
    emit(sess, {'type': 'tool_status', 'tool': 'subdomain', 'status': 'running',
                'msg': 'Subdomain enumeration running...'})

    host = extract_hostname(target)

    if is_ip(host):
        # Try reverse lookup via system resolver — picks up /etc/hosts entries.
        # e.g. 10.129.2.229 → pilgrimage.htb lets us run vhost enumeration.
        try:
            resolved_hostname = socket.gethostbyaddr(host)[0]
        except Exception:
            resolved_hostname = ''

        if resolved_hostname and not is_ip(resolved_hostname):
            logger.info('Subdomain: raw IP %s reverse-resolved to %s via /etc/hosts — '
                        'proceeding with vhost enumeration', host, resolved_hostname)
            emit(sess, {'type': 'tool_status', 'tool': 'subdomain', 'status': 'running',
                        'msg': f'Reverse lookup: {host} → {resolved_hostname}. '
                               f'Detecting HTTP port...'})
            host = resolved_hostname
        else:
            # No hostname mapping — nothing to enumerate
            sess['tool_status']['subdomain'] = 'completed'
            emit(sess, {'type': 'tool_status', 'tool': 'subdomain', 'status': 'completed',
                        'msg': 'Raw IP with no hostname mapping — add to /etc/hosts to enable vhost scan'})
            emit(sess, {'type': 'subdomain_none'})
            return

    base_domain  = strip_www(host)
    dns_wordlist = next((p for p in DEFAULT_DNS_WORDLISTS if os.path.exists(p)), None)

    # Resolve domain using system resolver (honours /etc/hosts)
    is_private, resolved_ip = _domain_resolves_private(base_domain)

    if is_private:
        # Private / CTF target — use virtual host enumeration (HTTP Host header fuzzing)
        logger.info('Subdomain: %s resolves to private IP %s → vhost mode',
                    base_domain, resolved_ip)
        # Detect the actual HTTP port before launching gobuster vhost
        vhost_scheme, vhost_port = _find_http_port(base_domain, target)
        logger.info('Subdomain: vhost will use %s:%d for %s', vhost_scheme, vhost_port, base_domain)
        port_display = f':{vhost_port}' if vhost_port not in (80, 443) else ''
        emit(sess, {'type': 'tool_status', 'tool': 'subdomain', 'status': 'running',
                    'msg': f'Virtual host enumeration on {vhost_scheme}://{base_domain}{port_display}...'})
        if dns_wordlist:
            found = _scan_subdomains_vhost(sess, base_domain, resolved_ip, dns_wordlist,
                                            http_scheme=vhost_scheme, http_port=vhost_port)
            if found == -1:
                found = _scan_subdomains_builtin(sess, base_domain)
        else:
            found = _scan_subdomains_builtin(sess, base_domain)
    else:
        # Public / internet-facing target — use DNS brute-force
        logger.info('Subdomain: %s → DNS mode  (resolved: %s)', base_domain, resolved_ip)
        if dns_wordlist:
            found = _scan_subdomains_dns(sess, base_domain, dns_wordlist)
            if found == -1:
                found = _scan_subdomains_builtin(sess, base_domain)
        else:
            found = _scan_subdomains_builtin(sess, base_domain)

    sess['tool_status']['subdomain'] = 'completed'
    emit(sess, {'type': 'tool_status', 'tool': 'subdomain', 'status': 'completed',
                'msg': f'{found} subdomain(s) found'})
    if found == 0:
        emit(sess, {'type': 'subdomain_none'})


def scan_smb(sess: dict) -> None:
    """
    SMB enumeration — two phases:

    Phase 1 — MS17-010 active check (nmap smb-vuln-ms17-010):
      smb['ms17010'] = True only on confirmed VULNERABLE output.

    Phase 2 — share enumeration:
      smbmap (primary) → nmap smb-enum-shares → smbclient (fallbacks).
      All paths normalise shares to {'name', 'access', 'comment'}.

    Runs concurrently with all other scanners.  A fast TCP probe on
    ports 445 and 139 gates the heavy enumeration so non-SMB targets
    skip immediately rather than waiting for nmap script timeouts.
    """
    target = sess['target']
    host   = extract_hostname(target)

    sess['tool_status']['smb'] = 'running'
    emit(sess, {'type': 'tool_status', 'tool': 'smb', 'status': 'running',
                'msg': 'Probing SMB ports...'})

    # Fast TCP probe — skip full enumeration if neither SMB port answers
    smb_reachable = False
    for port in (445, 139):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            smb_reachable = (sock.connect_ex((host, port)) == 0)
            sock.close()
            if smb_reachable:
                break
        except Exception:
            pass

    if not smb_reachable:
        sess['tool_status']['smb'] = 'skipped'
        emit(sess, {'type': 'tool_status', 'tool': 'smb', 'status': 'skipped',
                    'msg': 'No SMB service detected on target'})
        emit(sess, {'type': 'smb', 'data': {'enabled': False, 'ms17010': False, 'shares': []}})
        return

    emit(sess, {'type': 'tool_status', 'tool': 'smb', 'status': 'running',
                'msg': 'SMB enumeration running...'})

    try:
        smb = {'enabled': True, 'ms17010': False, 'shares': []}

        smb['ms17010'] = _check_ms17010(target)

        shares = _run_smbmap(target)

        if not shares:
            logger.info('SMB: smbmap empty — trying nmap smb-enum-shares')
            nm2 = nmap.PortScanner()
            nm2.scan(hosts=target,
                     arguments='-p 139,445 --script smb-enum-shares -Pn -T4')
            for host in nm2.all_hosts():
                tcp = nm2[host].get('tcp', {})
                for port in (445, 139):
                    pd = tcp.get(port)
                    if pd and pd.get('state') == 'open':
                        raw    = (pd.get('script') or {}).get('smb-enum-shares')
                        shares = _parse_smb_shares(raw)
                        if shares:
                            break

        if not shares:
            logger.info('SMB: nmap empty — trying smbclient fallback')
            shares = _smbclient_shares(target)

        smb['shares'] = shares
        s_set(sess, 'smb', smb)
        sess['tool_status']['smb'] = 'completed'
        emit(sess, {'type': 'smb', 'data': smb})

        label = 'SMB enumeration complete'
        if smb['ms17010']:
            label += ' — MS17-010 VULNERABLE'
        emit(sess, {'type': 'tool_status', 'tool': 'smb', 'status': 'completed',
                    'msg': label})
        logger.info('SMB done: ms17010=%s  shares=%d', smb['ms17010'], len(smb['shares']))

    except Exception as exc:
        logger.exception('SMB enumeration failed')
        sess['tool_status']['smb'] = 'error'
        emit(sess, {'type': 'tool_status', 'tool': 'smb', 'status': 'error',
                    'msg': friendly_error(exc, 'SMB enumeration')})


# ══════════════════════════════════════════════════════════════
#  Orchestrator
# ══════════════════════════════════════════════════════════════

def orchestrate(sess: dict):
    """
    Fire all four scanners simultaneously in a thread pool.
    scan_smb self-gates via a fast TCP probe so it exits immediately
    on non-SMB targets without needing nmap results first.
    """
    q = sess['_q']
    emit(sess, {'type': 'status', 'phase': 'scanning',
                'msg': f"Scan initialised → {sess['target']}"})

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futures = {
            'nmap':      pool.submit(scan_nmap,       sess),
            'gobuster':  pool.submit(scan_gobuster,   sess),
            'subdomain': pool.submit(scan_subdomains, sess),
            'smb':       pool.submit(scan_smb,        sess),
        }

        while True:
            while not q.empty():
                try:
                    yield sse(q.get_nowait())
                except queue.Empty:
                    break

            if all(f.done() for f in futures.values()) and q.empty():
                break

            time.sleep(0.05)

        while not q.empty():
            yield sse(q.get_nowait())

    s_set(sess, 'status', 'completed')
    yield sse({'type': 'complete', 'scan_id': sess['id']})


# ══════════════════════════════════════════════════════════════
#  Routes
# ══════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/start_scan', methods=['POST'])
def api_start_scan():
    body     = request.get_json(force=True, silent=True) or {}
    target   = (body.get('target')      or '').strip()
    speed    = (body.get('speed')       or '4').strip()
    udp      = (body.get('include_udp') or 'no').strip().lower()
    wordlist = (body.get('wordlist')    or '').strip()

    if not target:
        return jsonify({'error': 'A target host is required to start a scan.'}), 400
    if speed not in {'1', '2', '3', '4', '5'}:
        speed = '4'
    if udp not in {'yes', 'no'}:
        udp = 'no'

    sid = create_session(target, speed, udp, wordlist)
    logger.info('Session %s created — target=%s  T%s  udp=%s', sid, target, speed, udp)
    return jsonify({'scan_id': sid, 'target': target})


@app.route('/api/stream/<scan_id>')
def api_stream(scan_id: str):
    sess = get_session(scan_id)
    if not sess:
        return jsonify({'error': 'Scan session not found — please start a new scan.'}), 404

    return Response(
        orchestrate(sess),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )


@app.route('/api/export/<scan_id>')
def api_export(scan_id: str):
    sess = get_session(scan_id)
    if not sess:
        return jsonify({'error': 'Scan session not found.'}), 404
    return jsonify({k: sess[k] for k in
                    ('id', 'target', 'started_at', 'status', 'os',
                     'ports', 'directories', 'subdomains', 'smb')})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
