#!/usr/bin/env python3
"""
scanner.py - Cross-platform Python network scanner.

A Python reimplementation of scanner.sh for cross-OS compatibility.
Works on Linux, macOS, and Windows.

Dependencies (standard library only for core functionality):
    - Python 3.7+
    - External tools: ping, traceroute/tracert (OS-provided)

Optional:
    - tcpdump (Linux/macOS) or tshark (Windows) for packet capture
    - curl for enhanced HTTP probing (falls back to urllib)

Usage:
    python3 scanner.py
    python scanner.py                    # Windows
    python3 scanner.py --no-capture      # Skip packet capture
    python3 scanner.py -i domains.txt    # Custom input file
    python3 scanner.py -o results.txt    # Custom output file
"""

import sys
import os
import re
import json
import math
import time
import socket
import platform
import subprocess
import shutil
import argparse
import signal
from datetime import datetime
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import quote

# ─── Constants ───────────────────────────────────────────────────────────────

SYSTEM = platform.system()  # 'Linux', 'Darwin', 'Windows'
IS_WINDOWS = SYSTEM == "Windows"
IS_MAC = SYSTEM == "Darwin"

INPUT_FILE = "domains.txt"
DEFAULT_LOG = "scan_results.txt"
IP_API_URL = "http://ip-api.com/json/"
IP_API_BATCH_URL = "http://ip-api.com/batch?fields=query,city,country,isp,lat,lon"
PRIVATE_IP_RE = re.compile(
    r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)"
)
IPV4_RE = re.compile(r"\d+\.\d+\.\d+\.\d+")

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


# ─── Utility Functions ──────────────────────────────────────────────────────

class TeeWriter:
    """Write output to both stdout and a log file simultaneously."""

    def __init__(self, log_path):
        self.terminal = sys.stdout
        self.log_file = open(log_path, "w", encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        self.log_file.write(message)

    def flush(self):
        self.terminal.flush()
        self.log_file.flush()

    def close(self):
        self.log_file.close()


def run_cmd(cmd, timeout=30, capture=True, shell=False, sudo=False):
    """Run a command cross-platform and return (returncode, stdout, stderr)."""
    if sudo and not IS_WINDOWS:
        if isinstance(cmd, list):
            cmd = ["sudo"] + cmd
        else:
            cmd = "sudo " + cmd
            shell = True

    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
            shell=shell,
        )
        return result.returncode, result.stdout or "", result.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0] if isinstance(cmd, list) else cmd}"
    except Exception as e:
        return -1, "", str(e)


def run_cmd_live(cmd, timeout=120, sudo=False):
    """Run a command with live output streaming. Returns (returncode, full_output)."""
    if sudo and not IS_WINDOWS:
        if isinstance(cmd, list):
            cmd = ["sudo"] + cmd
        else:
            cmd = "sudo " + cmd

    shell = isinstance(cmd, str)
    lines = []
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=shell,
        )
        start = time.time()
        for line in proc.stdout:
            line = line.rstrip("\n")
            print(line)
            lines.append(line)
            if timeout and (time.time() - start) > timeout:
                proc.kill()
                break
        proc.wait(timeout=10)
        return proc.returncode, "\n".join(lines)
    except Exception as e:
        return -1, str(e)


def has_command(name):
    """Check if a command is available on the system PATH."""
    return shutil.which(name) is not None


def http_get_json(url, timeout=10):
    """Fetch JSON from a URL using urllib (no external deps)."""
    req = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return {}


def http_post_json(url, data, timeout=10):
    """POST JSON data and return parsed response."""
    req = Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return []


# ─── Network Calculation (from net_calc.py) ──────────────────────────────────

def calc_distance(lat1, lon1, lat2, lon2):
    """Calculate great-circle distance using the Haversine formula (km)."""
    lat1_r, lon1_r = math.radians(lat1), math.radians(lon1)
    lat2_r, lon2_r = math.radians(lat2), math.radians(lon2)
    dlat = lat2_r - lat1_r
    dlon = lon2_r - lon1_r
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(lat1_r) * math.cos(lat2_r) * math.sin(dlon / 2) ** 2
    )
    return 6371.0 * 2 * math.asin(math.sqrt(a))


def print_net_calc(ping_rtt, my_data, target_data):
    """Print distance and RTT calculations (replaces net_calc.py call)."""
    try:
        my_lat, my_lon = my_data["lat"], my_data["lon"]
        my_city = my_data.get("city", "Unknown")
        t_lat, t_lon = target_data["lat"], target_data["lon"]
        t_city = f"{target_data.get('city', 'Unknown')}, {target_data.get('country', 'Unknown')}"

        distance = calc_distance(my_lat, my_lon, t_lat, t_lon)
        # Speed of light in fibre ~200,000 km/s
        theoretical_rtt = (distance / 200000.0) * 2 * 1000  # ms

        print(f"   [+] Origin:          {my_city}")
        print(f"   [+] Destination:     {t_city}")
        print(f"   [+] Coordinates:     {t_lat}, {t_lon}")
        print(f"   [+] Distance:        {distance:.2f} km")
        print(f"   ------------------------------------------------")
        print(f"   [+] Theoretical RTT: {theoretical_rtt:.2f} ms")
        if ping_rtt is not None:
            print(f"   [+] Measured Ping:   {ping_rtt:.2f} ms")
        else:
            print(f"   [+] Measured Ping:   N/A (ping failed)")
    except Exception as e:
        print(f"   [!] Calculation Error: {e}")


# ─── Map Generation (from gen_map.py) ────────────────────────────────────────

MAP_HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>Route Map: {domain}</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        body {{ margin: 0; font-family: Arial, sans-serif; }}
        #map {{ height: 100vh; width: 100%; }}
        .info-panel {{
            position: absolute; top: 10px; right: 10px; z-index: 1000;
            background: white; padding: 15px; border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3); max-width: 300px;
        }}
        .info-panel h3 {{ margin: 0 0 8px 0; color: #333; }}
        .info-panel p {{ margin: 4px 0; font-size: 13px; color: #666; }}
        .legend {{ margin-top: 10px; }}
        .legend-item {{ display: flex; align-items: center; margin: 4px 0; font-size: 12px; }}
        .legend-dot {{ width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }}
    </style>
</head>
<body>
    <div id="map"></div>
    <div class="info-panel">
        <h3>Route: {domain}</h3>
        <p><strong>From:</strong> {origin_city}</p>
        <p><strong>To:</strong> {dest_city}</p>
        <p><strong>Hops:</strong> {hop_count}</p>
        <div class="legend">
            <div class="legend-item"><div class="legend-dot" style="background:#2ecc71;"></div> Origin</div>
            <div class="legend-item"><div class="legend-dot" style="background:#3498db;"></div> Router Hop</div>
            <div class="legend-item"><div class="legend-dot" style="background:#e74c3c;"></div> Destination</div>
        </div>
    </div>
    <script>
        var points = {points_json};
        var map = L.map('map').setView([20, 0], 2);
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            attribution: '&copy; OpenStreetMap contributors',
            maxZoom: 18
        }}).addTo(map);

        var colors = {{ start: '#2ecc71', hop: '#3498db', end: '#e74c3c' }};
        var sizes = {{ start: 10, hop: 7, end: 10 }};
        var routeCoords = [];

        points.forEach(function(p) {{
            routeCoords.push([p.lat, p.lon]);
            L.circleMarker([p.lat, p.lon], {{
                radius: sizes[p.type], fillColor: colors[p.type],
                color: '#fff', weight: 2, opacity: 1, fillOpacity: 0.9
            }}).addTo(map).bindPopup('<b>' + p.label + '</b><br>' + p.popup);
        }});

        L.polyline(routeCoords, {{
            color: '#3498db', weight: 3, opacity: 0.7, dashArray: '10, 5'
        }}).addTo(map);

        if (routeCoords.length > 1) {{
            map.fitBounds(routeCoords, {{ padding: [50, 50] }});
        }}
    </script>
</body>
</html>"""


def generate_map(output_file, domain, origin_city, dest_city, hops):
    """Generate an HTML Leaflet.js route map file."""
    hop_count = sum(1 for h in hops if h.get("type") == "hop")
    html = MAP_HTML_TEMPLATE.format(
        domain=domain,
        origin_city=origin_city,
        dest_city=dest_city,
        hop_count=hop_count,
        points_json=json.dumps(hops),
    )
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"   Route map saved to: {output_file}")


# ─── DNS Resolution ─────────────────────────────────────────────────────────

def resolve_domain(domain):
    """Resolve a domain to its first IPv4 address using Python's socket."""
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        if results:
            return results[0][4][0]
    except socket.gaierror:
        pass

    # Fallback: try nslookup (cross-platform)
    rc, out, _ = run_cmd(["nslookup", domain], timeout=10)
    if rc == 0:
        ips = IPV4_RE.findall(out)
        # Skip the DNS server IP (usually the first one)
        for ip in ips:
            if not ip.startswith("127."):
                return ip
    return None


# ─── Ping ────────────────────────────────────────────────────────────────────

def ping_domain(domain, count=4):
    """
    Ping a domain cross-platform.
    Returns (success: bool, output: str, avg_rtt: float|None).
    """
    if IS_WINDOWS:
        cmd = ["ping", "-n", str(count), domain]
    else:
        cmd = ["ping", "-c", str(count), domain]

    rc, stdout, stderr = run_cmd(cmd, timeout=30)
    output = stdout + stderr

    avg_rtt = None
    if rc == 0:
        if IS_WINDOWS:
            # Windows: "Average = 42ms"
            m = re.search(r"Average\s*=\s*(\d+)\s*ms", output)
            if m:
                avg_rtt = float(m.group(1))
        else:
            # Linux/macOS: "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms"
            m = re.search(r"rtt [^=]+=\s*[\d.]+/([\d.]+)/", output)
            if not m:
                # macOS alternate: "round-trip min/avg/max/stddev = ..."
                m = re.search(r"round-trip [^=]+=\s*[\d.]+/([\d.]+)/", output)
            if m:
                avg_rtt = float(m.group(1))

    return rc == 0, output, avg_rtt


# ─── Traceroute ──────────────────────────────────────────────────────────────

def traceroute_domain(domain):
    """
    Run traceroute cross-platform.
    Returns list of public hop IPs found.
    """
    if IS_WINDOWS:
        cmd = ["tracert", "-d", "-h", "20", "-w", "3000", domain]
        sudo = False
    elif IS_MAC:
        cmd = ["traceroute", "-m", "20", "-w", "3", domain]
        sudo = True
    else:
        # Linux: prefer ICMP mode if available
        if has_command("traceroute"):
            cmd = ["traceroute", "--icmp", "-w", "3", "--max-hop=20", domain]
            sudo = True
        else:
            print("   Warning: traceroute not found. Skipping.")
            return []

    print(f"Running traceroute to {domain}...")
    rc, output = run_cmd_live(cmd, timeout=120, sudo=sudo)

    hop_ips = []
    lines = output.splitlines()
    for i, line in enumerate(lines):
        # Skip the header line
        if i == 0 and ("traceroute to" in line.lower() or "tracing route" in line.lower()):
            continue
        ips = IPV4_RE.findall(line)
        if ips:
            ip = ips[0]
            if not PRIVATE_IP_RE.match(ip):
                hop_ips.append(ip)

    return hop_ips


# ─── HTTP Probing ────────────────────────────────────────────────────────────

def probe_http(domain):
    """
    Probe a domain with HTTP/HTTPS. Uses curl if available for detailed
    timing info, otherwise falls back to urllib.
    """
    if has_command("curl"):
        return _probe_with_curl(domain)
    else:
        return _probe_with_urllib(domain)


def _probe_with_curl(domain):
    """Probe using curl for detailed connection timing."""
    fmt = (
        "HTTP Code: %{http_code}\\n"
        "Redirect URL: %{redirect_url}\\n"
        "Remote IP: %{remote_ip}:%{remote_port}\\n"
        "TLS Version: %{ssl_verify_result} (%{scheme})\\n"
        "Time DNS: %{time_namelookup}s\\n"
        "Time Connect: %{time_connect}s\\n"
        "Time TLS: %{time_appconnect}s\\n"
        "Time First Byte: %{time_starttransfer}s\\n"
        "Time Total: %{time_total}s\\n"
        "Bytes Downloaded: %{size_download}"
    )
    headers = [
        "-H", f"User-Agent: {USER_AGENT}",
        "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "-H", "Accept-Language: en-US,en;q=0.5",
        "-H", "Accept-Encoding: gzip, deflate, br",
        "-H", "Connection: keep-alive",
        "-H", "Upgrade-Insecure-Requests: 1",
    ]

    # Try HTTPS first
    cmd = [
        "curl", "-s", "-o", os.devnull, "-w", fmt,
        "-L", "--max-time", "15", "--max-redirs", "5",
    ] + headers + [f"https://{domain}"]

    rc, stdout, stderr = run_cmd(cmd, timeout=20)
    output = stdout

    # If HTTPS failed (HTTP Code: 000), try HTTP
    if "HTTP Code: 000" in output:
        print("   HTTPS failed, trying HTTP...")
        cmd[-1] = f"http://{domain}"
        rc, stdout, stderr = run_cmd(cmd, timeout=20)
        output = stdout

    return output


def _probe_with_urllib(domain):
    """Fallback HTTP probe using Python's urllib."""
    results = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        req = Request(url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        })
        start = time.time()
        try:
            with urlopen(req, timeout=15) as resp:
                elapsed = time.time() - start
                size = len(resp.read())
                results.append(
                    f"HTTP Code: {resp.status}\n"
                    f"URL: {resp.url}\n"
                    f"Time Total: {elapsed:.3f}s\n"
                    f"Bytes Downloaded: {size}"
                )
                return "\n".join(results)
        except HTTPError as e:
            elapsed = time.time() - start
            results.append(
                f"HTTP Code: {e.code}\n"
                f"Time Total: {elapsed:.3f}s"
            )
            return "\n".join(results)
        except URLError:
            if scheme == "https":
                print("   HTTPS failed, trying HTTP...")
                continue
            results.append("HTTP Code: 000 (Connection failed)")
        except Exception as e:
            results.append(f"Error: {e}")

    return "\n".join(results) if results else "Connection failed"


# ─── Packet Capture ──────────────────────────────────────────────────────────

def start_capture(pcap_file):
    """
    Start packet capture in background.
    Uses tcpdump on Linux/macOS, tshark on Windows.
    Returns (process, tool_name) or (None, None) if unavailable.
    """
    if IS_WINDOWS:
        if has_command("tshark"):
            cmd = ["tshark", "-w", pcap_file, "-q"]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return proc, "tshark"
        elif has_command("dumpcap"):
            cmd = ["dumpcap", "-w", pcap_file, "-q"]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return proc, "dumpcap"
    else:
        if has_command("tcpdump"):
            cmd = ["sudo", "tcpdump", "-i", "any", "-w", pcap_file, "-q"]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return proc, "tcpdump"

    return None, None


def stop_capture(proc, tool_name, pcap_file):
    """Stop a background packet capture process."""
    if proc is None:
        return
    try:
        if IS_WINDOWS:
            proc.terminate()
        else:
            # tcpdump needs SIGTERM via sudo
            subprocess.run(
                ["sudo", "kill", str(proc.pid)],
                capture_output=True, timeout=5,
            )
        proc.wait(timeout=10)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

    # Fix ownership on Linux/macOS
    if not IS_WINDOWS and os.path.exists(pcap_file):
        user = os.environ.get("USER", "")
        if user:
            subprocess.run(
                ["sudo", "chown", f"{user}:{user}", pcap_file],
                capture_output=True, timeout=5,
            )

    if os.path.exists(pcap_file):
        size = os.path.getsize(pcap_file)
        if size > 1024 * 1024:
            size_str = f"{size / (1024 * 1024):.1f}M"
        elif size > 1024:
            size_str = f"{size / 1024:.1f}K"
        else:
            size_str = f"{size}B"
        print(f"\n   Packet capture saved: {pcap_file} ({size_str})")
        if has_command("tcpdump"):
            print(f"   Analyze with: tcpdump -r {pcap_file} | head -20")
        elif has_command("tshark"):
            print(f"   Analyze with: tshark -r {pcap_file}")


# ─── Dependency Check ────────────────────────────────────────────────────────

def check_dependencies():
    """Check and report on required/optional tool availability."""
    required = []
    if IS_WINDOWS:
        required.append(("ping", True))
        required.append(("tracert", True))
        required.append(("nslookup", True))
    else:
        required.append(("ping", True))
        required.append(("traceroute", True))

    optional = []
    optional.append(("curl", "enhanced HTTP probing with timing details"))
    if IS_WINDOWS:
        optional.append(("tshark", "packet capture (install Wireshark)"))
    else:
        optional.append(("tcpdump", "packet capture"))

    missing_required = []
    for cmd, is_required in required:
        if not has_command(cmd):
            missing_required.append(cmd)

    if missing_required:
        print(f"Error: Required tools not found: {', '.join(missing_required)}")
        if not IS_WINDOWS:
            print("Install with:")
            print(f"  sudo apt-get install -y {' '.join(missing_required)}  # Debian/Ubuntu")
            print(f"  sudo yum install -y {' '.join(missing_required)}      # RHEL/CentOS")
            print(f"  brew install {' '.join(missing_required)}              # macOS")
        return False

    for cmd, purpose in optional:
        if not has_command(cmd):
            print(f"Note: '{cmd}' not found - {purpose} will be unavailable")

    return True


# ─── Sudo Prompt (Linux/macOS) ───────────────────────────────────────────────

def ensure_sudo():
    """Prompt for sudo password upfront so background commands don't block."""
    if IS_WINDOWS:
        return True
    rc, _, _ = run_cmd(["sudo", "-v"], timeout=30)
    if rc != 0:
        print("Error: sudo access required for traceroute and packet capture.")
        return False
    return True


# ─── Main Scanner ────────────────────────────────────────────────────────────

def choose_log_file(default_log):
    """Ask user for output file preference."""
    if os.path.isfile(default_log):
        print(f"Previous results file found: {default_log}")
        print("  1) Overwrite it")
        print("  2) Enter a custom name")
        try:
            choice = input("Choose [1/2] (default: 1): ").strip()
        except (EOFError, KeyboardInterrupt):
            choice = "1"

        if choice == "2":
            try:
                custom = input("Enter results filename: ").strip()
            except (EOFError, KeyboardInterrupt):
                custom = ""
            if not custom:
                custom = default_log
            if not custom.endswith(".txt"):
                custom += ".txt"
            return custom
    return default_log


def scan_domain(domain, my_loc, my_lat, my_lon, my_city):
    """Scan a single domain: HTTP probe, ping, traceroute, geolocate, map."""
    print("-----------------------------")
    print(f"Scanning {domain}...")
    print("-----------------------------")
    print()

    # ── Resolve domain ──
    domain_ip = resolve_domain(domain)
    if domain_ip:
        print(f"Resolved {domain} -> {domain_ip}")
        loc_json = http_get_json(f"{IP_API_URL}{domain_ip}")
    else:
        print(f"Warning: Could not resolve {domain} to IP. Trying hostname...")
        loc_json = http_get_json(f"{IP_API_URL}{domain}")

    city = loc_json.get("city", "")
    dest_lat = loc_json.get("lat")
    dest_lon = loc_json.get("lon")

    if not city or dest_lat is None or dest_lon is None:
        print(f"Warning: Could not geolocate {domain}. Skipping...")
        print("-----------------------------")
        print()
        return

    print(f"Location: {city} ({dest_lat}, {dest_lon})")
    print("-----------------------------")
    print()

    # ── HTTP probe ──
    print(f"Fetching {domain} (browser emulation)...")
    http_output = probe_http(domain)
    for line in http_output.splitlines():
        print(f"   {line}")
    print("-----------------------------")
    print()

    # ── Ping ──
    print(f"Pinging {domain}...")
    ping_ok, ping_output, ping_avg = ping_domain(domain)
    if ping_ok:
        print("Ping successful!")
        # Print last 2 lines of ping output (summary)
        for line in ping_output.strip().splitlines()[-2:]:
            print(line)
    else:
        print("Ping failed.")
    print("-----------------------------")
    print()

    # ── Distance / RTT calculation ──
    print_net_calc(ping_avg, my_loc, loc_json)

    print()

    # ── Traceroute ──
    hop_ips = traceroute_domain(domain)

    if hop_ips:
        # Batch geolocate hop IPs
        batch_result = http_post_json(IP_API_BATCH_URL, hop_ips)

        # Build lookup
        lookup = {}
        for entry in batch_result:
            if isinstance(entry, dict):
                lookup[entry.get("query", "")] = entry

        print()
        print("Physical Path Mapping:")
        print("-----------------------------")
        print("Hop | IP Address       | City             | Country          | ISP")
        print("----|------------------|------------------|------------------|--------------------")

        map_points = [
            {
                "lat": my_lat,
                "lon": my_lon,
                "label": "Origin",
                "popup": f"{my_city} (Origin)",
                "type": "start",
            }
        ]

        for i, ip in enumerate(hop_ips, 1):
            entry = lookup.get(ip, {})
            ip_city = entry.get("city", "Unknown") or "Unknown"
            ip_country = entry.get("country", "Unknown") or "Unknown"
            ip_isp = entry.get("isp", "Unknown") or "Unknown"
            ip_lat = entry.get("lat")
            ip_lon = entry.get("lon")

            print(f"{i:<4}| {ip:<17}| {ip_city:<17}| {ip_country:<17}| {ip_isp}")

            if ip_lat is not None and ip_lon is not None:
                map_points.append({
                    "lat": ip_lat,
                    "lon": ip_lon,
                    "label": ip,
                    "popup": f"Hop {i}: {ip}<br>{ip_city}, {ip_country}<br>ISP: {ip_isp}",
                    "type": "hop",
                })

        # Add destination
        map_points.append({
            "lat": dest_lat,
            "lon": dest_lon,
            "label": domain,
            "popup": f"{city} (Destination)<br>{domain}",
            "type": "end",
        })

        print()
        print(f"Route: {my_city} --> [{len(hop_ips)} hops] --> {city}")

        # Generate HTML map
        safe_domain = re.sub(r"[^a-zA-Z0-9._-]", "_", domain)
        map_file = f"route_maps/route_{safe_domain}.html"
        generate_map(map_file, domain, my_city, city, map_points)
    else:
        print("No public IPs found in traceroute.")

    print()
    print("-----------------------------")
    print(f"Finished scanning {domain}.")
    print("Waiting before next scan...")
    time.sleep(3)


def main():
    parser = argparse.ArgumentParser(
        description="Cross-platform network scanner"
    )
    parser.add_argument(
        "-i", "--input", default=INPUT_FILE,
        help=f"Input domains file (default: {INPUT_FILE})",
    )
    parser.add_argument(
        "-o", "--output", default=None,
        help="Output results file (overrides interactive prompt)",
    )
    parser.add_argument(
        "--no-capture", action="store_true",
        help="Skip packet capture",
    )
    args = parser.parse_args()

    input_file = args.input

    print("Networking Practical Session 1")
    print("-----------------------------")
    print()

    # Check input file
    if not os.path.isfile(input_file):
        print(f"Error: {input_file} not found!")
        sys.exit(1)

    # Check dependencies
    if not check_dependencies():
        sys.exit(1)

    # Choose output file
    if args.output:
        log_file = args.output
        if not log_file.endswith(".txt"):
            log_file += ".txt"
    else:
        log_file = choose_log_file(DEFAULT_LOG)

    # Set up tee-style logging
    tee = TeeWriter(log_file)
    sys.stdout = tee

    # Re-print header to log
    print("Networking Practical Session 1")
    print("-----------------------------")
    print()

    # Sudo check (Linux/macOS)
    if not IS_WINDOWS:
        if not ensure_sudo():
            sys.exit(1)

    # Create output directories
    os.makedirs("route_maps", exist_ok=True)
    os.makedirs("captures", exist_ok=True)

    # ── Start packet capture ──
    capture_proc = None
    capture_tool = None
    pcap_file = None

    if not args.no_capture:
        pcap_file = f"captures/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        capture_proc, capture_tool = start_capture(pcap_file)
        if capture_proc:
            time.sleep(1)
            print(f"Packet capture started -> {pcap_file}")
        else:
            print(
                "Warning: No packet capture tool available. "
                "Continuing without capture."
            )
            if IS_WINDOWS:
                print("  Install Wireshark for tshark/dumpcap support.")
            else:
                print("  Install tcpdump: sudo apt-get install tcpdump")
    print("-----------------------------")
    print()

    # ── Get current location ──
    print("Getting current location...")
    my_loc = http_get_json(IP_API_URL)
    my_city = my_loc.get("city", "Unknown")
    my_lat = my_loc.get("lat", 0)
    my_lon = my_loc.get("lon", 0)
    print(f"Origin detected: {my_city} ({my_lat}, {my_lon})")
    print("-------------------------------------------")
    print()
    time.sleep(2)

    # ── Read domains and scan ──
    with open(input_file, "r", encoding="utf-8") as f:
        domains = f.readlines()

    for raw_line in domains:
        domain = raw_line.strip()
        if not domain or domain.startswith("#"):
            continue
        scan_domain(domain, my_loc, my_lat, my_lon, my_city)

    # ── Stop capture ──
    if capture_proc:
        stop_capture(capture_proc, capture_tool, pcap_file)

    print()
    print("   ANALYSIS COMPLETE")
    print(f"   Results saved to: {log_file}")
    print(f"   Route maps saved to: route_maps/")
    print(f"   Packet captures saved to: captures/")

    # Restore stdout and close log
    sys.stdout = tee.terminal
    tee.close()


if __name__ == "__main__":
    main()
