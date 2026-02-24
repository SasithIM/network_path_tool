#!/usr/bin/env python3
"""
parse_batch.py - Parse ip-api.com batch JSON response.

Reads batch JSON from stdin.
For each IP passed as arguments, outputs a line:
    ip|city|country|isp|lat|lon

Usage:
    echo "$batch_json" | python3 parse_batch.py ip1 ip2 ip3 ...
"""

import sys
import json


def main():
    ips = sys.argv[1:]
    if not ips:
        return

    try:
        batch = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        # Output unknown for all IPs if parsing fails
        for ip in ips:
            print(f"{ip}|Unknown|Unknown|Unknown||")
        return

    # Build lookup by query IP
    lookup = {}
    for entry in batch:
        if isinstance(entry, dict):
            lookup[entry.get("query", "")] = entry

    for ip in ips:
        entry = lookup.get(ip, {})
        city = entry.get("city", "Unknown") or "Unknown"
        country = entry.get("country", "Unknown") or "Unknown"
        isp = entry.get("isp", "Unknown") or "Unknown"
        lat = entry.get("lat", "")
        lon = entry.get("lon", "")
        print(f"{ip}|{city}|{country}|{isp}|{lat}|{lon}")


if __name__ == "__main__":
    main()
