#!/usr/bin/env python3
"""
gen_map.py - Generate a Leaflet.js HTML route map from traceroute hop data.

Usage:
    python3 gen_map.py <output_file> <domain> <origin_city> <dest_city> <hops_json>

    hops_json: JSON array of hop objects:
        [
            {"lat": 6.9, "lon": 79.8, "label": "Origin", "popup": "Colombo (Origin)", "type": "start"},
            {"lat": 35.6, "lon": 139.7, "label": "1.2.3.4", "popup": "Hop 1: ...", "type": "hop"},
            {"lat": 40.7, "lon": -74.0, "label": "example.com", "popup": "New York (Dest)", "type": "end"}
        ]
"""

import sys
import json
import os

HTML_TEMPLATE = """<!DOCTYPE html>
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
    """Generate an HTML route map file.

    Args:
        output_file: Path to write the HTML file.
        domain: Target domain name.
        origin_city: Name of the origin city.
        dest_city: Name of the destination city.
        hops: List of dicts with keys: lat, lon, label, popup, type.
    """
    # Count only intermediate hops (not origin/destination)
    hop_count = sum(1 for h in hops if h.get("type") == "hop")

    html = HTML_TEMPLATE.format(
        domain=domain,
        origin_city=origin_city,
        dest_city=dest_city,
        hop_count=hop_count,
        points_json=json.dumps(hops),
    )

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w") as f:
        f.write(html)

    print(f"   Route map saved to: {output_file}")


if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python3 gen_map.py <output_file> <domain> <origin_city> <dest_city> <hops_json>")
        sys.exit(1)

    output_file = sys.argv[1]
    domain = sys.argv[2]
    origin_city = sys.argv[3]
    dest_city = sys.argv[4]
    hops = json.loads(sys.argv[5])

    generate_map(output_file, domain, origin_city, dest_city, hops)
