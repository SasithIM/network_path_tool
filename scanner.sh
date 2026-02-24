#! /bin/bash
INPUT_FILE="domains.txt"
LOG_FILE="scan_results.txt"

exec > >(tee -a "$LOG_FILE") 2>&1

echo "Networking Practical Session 1"
echo "-----------------------------"
echo ""

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: $INPUT_FILE not found!"
    exit 1
fi

if ! command -v curl &> /dev/null; then
    sudo apt-get update
    sudo apt-get install -y curl
fi

if ! command -v traceroute &> /dev/null; then
    sudo apt-get update
    sudo apt-get install -y traceroute
fi


# Create maps output directory
mkdir -p route_maps

echo "Getting current location..."
MY_LOC_JSON=$(curl -s "http://ip-api.com/json/")
MY_CITY=$(echo "$MY_LOC_JSON" | grep -oP '"city":"\K[^"]+')
MY_LAT=$(echo "$MY_LOC_JSON" | grep -oP '"lat":\K[0-9.\-]+')
MY_LON=$(echo "$MY_LOC_JSON" | grep -oP '"lon":\K[0-9.\-]+')

echo "Origin detected: $MY_CITY ($MY_LAT, $MY_LON)"
echo "-------------------------------------------"
echo ""

while IFS= read -r domain || [ -n "$domain" ]; do
    if [[ "$domain" == \#* ]] || [[ -z "$domain" ]]; then
        continue
    fi

    domain=$(echo "$domain" | xargs)

    echo "-----------------------------"
    echo "Scanning $domain..."
    echo "-----------------------------"
    echo ""

    # Resolve domain to IP first (API sometimes can't resolve hostnames directly)
    domain_ip=$(dig +short "$domain" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
    if [[ -z "$domain_ip" ]]; then
        domain_ip=$(host "$domain" 2>/dev/null | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
    fi

    if [[ -n "$domain_ip" ]]; then
        echo "Resolved $domain -> $domain_ip"
        LOC_JSON=$(curl -s "http://ip-api.com/json/$domain_ip")
    else
        echo "Warning: Could not resolve $domain to IP. Trying hostname..."
        LOC_JSON=$(curl -s "http://ip-api.com/json/$domain")
    fi

    CITY=$(echo "$LOC_JSON" | grep -oP '"city":"\K[^"]+')
    DEST_LAT=$(echo "$LOC_JSON" | grep -oP '"lat":\K[0-9.\-]+')
    DEST_LON=$(echo "$LOC_JSON" | grep -oP '"lon":\K[0-9.\-]+')

    if [[ -z "$CITY" || -z "$DEST_LAT" || -z "$DEST_LON" ]]; then
        echo "Warning: Could not geolocate $domain. Skipping..."
        echo "-----------------------------"
        echo ""
        continue
    fi

    echo "Location: $CITY ($DEST_LAT, $DEST_LON)"
    echo "-----------------------------"
    echo ""
    echo "Pinging $domain..."

    ping_output=$(ping -c 4 "$domain" 2>&1)
    ping_exit=$?

    if [ "$ping_exit" -eq 0 ]; then
        echo "Ping successful!"
        echo "$ping_output" | tail -2
    else
        echo "Ping failed."
    fi
    echo "-----------------------------"
    echo ""

    ping_avg=$(echo "$ping_output" | grep 'rtt' | cut -d '/' -f 5)

    python3 net_calc.py "$ping_avg" "$MY_LOC_JSON" "$LOC_JSON"

    echo "Running traceroute to $domain..."
    # Stream output live while also saving to temp file for parsing
    traceroute_tmp=$(mktemp)
    traceroute -w 3 --max-hop=30 "$domain" 2>&1 | tee "$traceroute_tmp"

    hop_ips=()
    while IFS= read -r line; do
        hop_ip=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
        if [[ -n "$hop_ip" ]] && ! [[ "$hop_ip" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]]; then
            hop_ips+=("$hop_ip")
        fi
    done < "$traceroute_tmp"
    rm -f "$traceroute_tmp"

    batch_json="["
    for i in "${!hop_ips[@]}"; do
        if [ "$i" -gt 0 ]; then
            batch_json+=","
        fi
        batch_json+="\"${hop_ips[$i]}\""
    done
    batch_json+="]"

    if [ "${#hop_ips[@]}" -gt 0 ]; then
        batch_result=$(curl -s -X POST "http://ip-api.com/batch?fields=query,city,country,isp,lat,lon" -H "Content-Type: application/json" -d "$batch_json")

        echo ""
        echo "Physical Path Mapping:"
        echo "-----------------------------"
        echo "Hop | IP Address       | City             | Country          | ISP"
        echo "----|------------------|------------------|------------------|--------------------"

        # Collect coordinates for map visualization
        map_json="[{\"lat\":$MY_LAT,\"lon\":$MY_LON,\"label\":\"Origin\",\"popup\":\"$MY_CITY (Origin)\",\"type\":\"start\"}"

        hop_count=1
        for ip in "${hop_ips[@]}"; do
            # Parse this IP's data from the batch result
            ip_city=$(echo "$batch_result" | grep -oP "\"query\":\"$ip\"[^}]*\"city\":\"\\K[^\"]+")
            ip_country=$(echo "$batch_result" | grep -oP "\"query\":\"$ip\"[^}]*\"country\":\"\\K[^\"]+")
            ip_isp=$(echo "$batch_result" | grep -oP "\"query\":\"$ip\"[^}]*\"isp\":\"\\K[^\"]+")
            ip_lat=$(echo "$batch_result" | grep -oP "\"query\":\"$ip\"[^}]*\"lat\":\\K[0-9.\\-]+")
            ip_lon=$(echo "$batch_result" | grep -oP "\"query\":\"$ip\"[^}]*\"lon\":\\K[0-9.\\-]+")

            # If grep order varies, try reverse match
            if [[ -z "$ip_city" ]]; then
                ip_city=$(echo "$batch_result" | grep -oP "\"city\":\"[^\"]*\"[^}]*\"query\":\"$ip\"" | grep -oP '"city":"\K[^"]+')
            fi
            if [[ -z "$ip_country" ]]; then
                ip_country=$(echo "$batch_result" | grep -oP "\"country\":\"[^\"]*\"[^}]*\"query\":\"$ip\"" | grep -oP '"country":"\K[^"]+')
            fi
            if [[ -z "$ip_isp" ]]; then
                ip_isp=$(echo "$batch_result" | grep -oP "\"isp\":\"[^\"]*\"[^}]*\"query\":\"$ip\"" | grep -oP '"isp":"\K[^"]+')
            fi
            if [[ -z "$ip_lat" ]]; then
                ip_lat=$(echo "$batch_result" | grep -oP "\"lat\":[0-9.\-]*[^}]*\"query\":\"$ip\"" | grep -oP '"lat":\K[0-9.\-]+')
            fi
            if [[ -z "$ip_lon" ]]; then
                ip_lon=$(echo "$batch_result" | grep -oP "\"lon\":[0-9.\-]*[^}]*\"query\":\"$ip\"" | grep -oP '"lon":\K[0-9.\-]+')
            fi

            printf "%-4s| %-17s| %-17s| %-17s| %s\n" \
                "$hop_count" "$ip" "${ip_city:-Unknown}" "${ip_country:-Unknown}" "${ip_isp:-Unknown}"

            # Add to map data if we have coordinates
            if [[ -n "$ip_lat" && -n "$ip_lon" ]]; then
                map_json+=",{\"lat\":$ip_lat,\"lon\":$ip_lon,\"label\":\"$ip\",\"popup\":\"Hop $hop_count: $ip<br>${ip_city:-Unknown}, ${ip_country:-Unknown}<br>ISP: ${ip_isp:-Unknown}\",\"type\":\"hop\"}"
            fi

            hop_count=$((hop_count + 1))
        done

        # Add destination point
        map_json+=",{\"lat\":$DEST_LAT,\"lon\":$DEST_LON,\"label\":\"$domain\",\"popup\":\"$CITY (Destination)<br>$domain\",\"type\":\"end\"}]"

        echo ""
        echo "Route: $MY_CITY --> [${#hop_ips[@]} hops] --> $CITY"

        # Generate HTML map using separate module
        safe_domain=$(echo "$domain" | sed 's/[^a-zA-Z0-9._-]/_/g')
        map_file="route_maps/route_${safe_domain}.html"
        python3 gen_map.py "$map_file" "$domain" "$MY_CITY" "$CITY" "$map_json"
    else
        echo "No public IPs found in traceroute."
    fi

    echo ""
    echo "-----------------------------"
    echo "Finished scanning $domain."
    echo "Waiting before next scan..."
    sleep 3

done < "$INPUT_FILE" 

echo ""
echo "   ANALYSIS COMPLETE"
echo "   Results saved to: $LOG_FILE"
echo "   Route maps saved to: route_maps/"