import sys
import json
import math

def calc_distance(lat1, lon1, lat2, lon2):
    # Convert latitude and longitude from degrees to radians
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)

    # Haversine formula
    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad
    a = math.sin(dlat / 2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2)**2
    c = 2 * math.asin(math.sqrt(a))

    # Radius of Earth in kilometers (mean radius)
    R = 6371.0
    distance = R * c
    return distance

try:
    ping_rtt = float(sys.argv[1])
    my_data = json.loads(sys.argv[2])
    target_data = json.loads(sys.argv[3])

    my_lat = my_data['lat']
    my_lon = my_data['lon']
    my_city = my_data.get('city', 'Unknown')

    target_lat = target_data['lat']
    target_lon = target_data['lon']
    target_city = f"{target_data.get('city', 'Unknown')}, {target_data.get('country', 'Unknown')}"

    distance = calc_distance(my_lat, my_lon, target_lat, target_lon)
    c_fiber = 200000.0  # Speed of light in fiber in km/s
    theoretical_rtt = (distance / c_fiber) * 2 * 1000  # RTT in milliseconds

    print(f"   [+] Origin:          {my_city}")
    print(f"   [+] Destination:     {target_city}")
    print(f"   [+] Coordinates:     {target_lat}, {target_lon}")
    print(f"   [+] Distance:        {distance:.2f} km")
    print(f"   ------------------------------------------------")
    print(f"   [+] Theoretical RTT: {theoretical_rtt:.2f} ms")
    print(f"   [+] Measured Ping:   {ping_rtt:.2f} ms")


except Exception as e:
    print(f"   [!] Python Calculation Error: {e}")