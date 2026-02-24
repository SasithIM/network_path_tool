# Network Scanner & Route Mapper

This project was developed for the **EN2150 – Communication Network Engineering – Practical Session #1** assignment.

It automates network analysis across multiple domains: geolocating servers, measuring latency, tracing packet routes, capturing traffic, and visualizing the physical network path on an interactive map.

## Features

- **DNS Resolution & IP Geolocation** — Resolves each domain to an IP and identifies its city, country, and ISP using the ip-api.com API
- **Ping & RTT Measurement** — Sends ICMP echo requests and measures round-trip time
- **Distance & Theoretical RTT Calculation** — Computes the Haversine distance between origin and destination, and compares theoretical (speed-of-light-in-fiber) RTT against measured ping
- **Traceroute with Hop Geolocation** — Traces the packet route and geolocates each intermediate router, identifying the ISP at every hop
- **Route Visualization** — Generates interactive Leaflet.js HTML maps showing the physical path packets take from origin to destination
- **Browser-Emulated HTTP Requests** — Fetches each site with full browser headers (Chrome User-Agent, Accept, TLS) and reports HTTP status, timing breakdown, and connection details
- **Packet Capture** — Runs `tcpdump` for the entire scan session, saving all traffic to a single `.pcap` file for later analysis in Wireshark or similar tools

## Project Structure

```
scanner.sh        # Main script — orchestrates the full scan
net_calc.py       # Haversine distance & RTT calculator
gen_map.py        # Leaflet.js route map generator
parse_batch.py    # Batch API JSON parser
domains.txt       # Input file — list of domains to scan
.gitignore        # Ignores output files

# Generated outputs (git-ignored):
scan_results.txt  # Full scan log
route_maps/       # Interactive HTML route maps (one per domain)
captures/         # Packet capture (.pcap) files
```

## Requirements

### System

- Linux (tested on Ubuntu 24.04)
- Bash 4+
- Python 3.6+
- Internet connection

### Tools (auto-installed if missing)

| Tool | Purpose |
|------|---------|
| `curl` | HTTP requests & API calls |
| `traceroute` | Route tracing (inetutils-traceroute) |
| `tcpdump` | Packet capture |
| `dig` / `host` | DNS resolution (usually pre-installed) |
| `ping` | ICMP echo (usually pre-installed) |

### External APIs

- [ip-api.com](http://ip-api.com) (free tier, 45 requests/minute) — IP geolocation and ISP lookup

## Usage

### 1. Add domains to scan

Edit `domains.txt` with one domain per line. Lines starting with `#` are comments.

```
www.ruh.ac.lk
www.uoregon.edu
www.keio.ac.jp
www.cam.ac.uk
www5.usp.br
www.unimelb.edu.au
```

### 2. Run the scanner

```bash
bash scanner.sh
```

The script will prompt for your `sudo` password (needed for `traceroute --icmp` and `tcpdump`).

### 3. View outputs

- **Terminal / Log** — Full results are printed live and saved to `scan_results.txt`
- **Route Maps** — Open any `route_maps/route_*.html` in a browser to see the interactive map
- **Packet Capture** — Analyze with:
  ```bash
  tcpdump -r captures/scan_*.pcap | head -50
  ```
  Or open in Wireshark:
  ```bash
  wireshark captures/scan_*.pcap
  ```

## Sample Output

```
Scanning www.cam.ac.uk...
Resolved www.cam.ac.uk -> 131.111.150.25
Location: Cambridge (52.2053, 0.1218)

Fetching www.cam.ac.uk (browser emulation)...
   HTTP Code: 200
   Time Total: 0.812s

Ping successful!
rtt min/avg/max/mdev = 180.2/195.4/210.8/12.3 ms

   [+] Distance:        8590.32 km
   [+] Theoretical RTT: 85.90 ms
   [+] Measured Ping:   195.40 ms

Physical Path Mapping:
Hop | IP Address       | City             | Country          | ISP
----|------------------|------------------|------------------|--------------------
1   | 103.21.167.2     | Colombo          | Sri Lanka        | Hutchison Telecom
2   | 103.87.125.41    | Colombo          | Sri Lanka        | Sri Lanka Telecom
...
Route: Colombo --> [6 hops] --> Cambridge
   Route map saved to: route_maps/route_www.cam.ac.uk.html
```

## Notes

- The free ip-api.com tier allows **45 requests per minute**. The script uses batch requests and delays between domains to stay within this limit.
- IP geolocation for intermediate routers is approximate — routers often geolocate to the ISP's headquarters rather than the physical device location.
- Some routers silently drop traceroute probes, appearing as `* * *` in the output. ICMP mode is used to maximize responses.
