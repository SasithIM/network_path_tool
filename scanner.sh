#! /bin/bash
INPUT_FILE="domains.txt"
DEFAULT_LOG="scan_results.txt"

# Ask user for output file preference
if [ -f "$DEFAULT_LOG" ]; then
    echo "Previous results file found: $DEFAULT_LOG"
    echo "  1) Overwrite it"
    echo "  2) Enter a custom name"
    read -rp "Choose [1/2] (default: 1): " choice
    case "$choice" in
        2)
            read -rp "Enter results filename: " custom_name
            custom_name="${custom_name:=$DEFAULT_LOG}"
            # Add .txt extension if missing
            [[ "$custom_name" != *.txt ]] && custom_name="${custom_name}.txt"
            LOG_FILE="$custom_name"
            ;;
        *)
            LOG_FILE="$DEFAULT_LOG"
            ;;
    esac
else
    LOG_FILE="$DEFAULT_LOG"
fi

# Overwrite (not append) the results file
: > "$LOG_FILE"
exec > >(tee "$LOG_FILE") 2>&1

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

if ! command -v tcpdump &> /dev/null; then
    sudo apt-get update
    sudo apt-get install -y tcpdump
fi


# Prompt for sudo password upfront so background commands don't block
sudo -v || { echo "Error: sudo access required."; exit 1; }

# Create output directories
mkdir -p route_maps
mkdir -p captures

# --- Start single packet capture for entire scan ---
PCAP_FILE="captures/scan_$(date +%Y%m%d_%H%M%S).pcap"
sudo tcpdump -i any -w "$PCAP_FILE" -q 2>/dev/null &
TCPDUMP_PID=$!
sleep 1
echo "Packet capture started -> $PCAP_FILE"
echo "-----------------------------"
echo ""

echo "Getting current location..."
MY_LOC_JSON=$(curl -s "http://ip-api.com/json/")
MY_CITY=$(echo "$MY_LOC_JSON" | grep -oP '"city":"\K[^"]+')
MY_LAT=$(echo "$MY_LOC_JSON" | grep -oP '"lat":\K[0-9.\-]+')
MY_LON=$(echo "$MY_LOC_JSON" | grep -oP '"lon":\K[0-9.\-]+')

echo "Origin detected: $MY_CITY ($MY_LAT, $MY_LON)"
echo "-------------------------------------------"
echo ""
sleep 2

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

    # --- Browser-emulated HTTP request ---
    echo "Fetching $domain (browser emulation)..."
    curl_output=$(curl -s -o /dev/null -w \
        "HTTP Code: %{http_code}\nRedirect URL: %{redirect_url}\nRemote IP: %{remote_ip}:%{remote_port}\nTLS Version: %{ssl_verify_result} (%{scheme})\nTime DNS: %{time_namelookup}s\nTime Connect: %{time_connect}s\nTime TLS: %{time_appconnect}s\nTime First Byte: %{time_starttransfer}s\nTime Total: %{time_total}s\nBytes Downloaded: %{size_download}" \
        -L --max-time 15 --max-redirs 5 \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" \
        -H "Accept-Language: en-US,en;q=0.5" \
        -H "Accept-Encoding: gzip, deflate, br" \
        -H "Connection: keep-alive" \
        -H "Upgrade-Insecure-Requests: 1" \
        "https://$domain" 2>&1)

    # If HTTPS fails, try HTTP
    if echo "$curl_output" | grep -q "HTTP Code: 000"; then
        echo "   HTTPS failed, trying HTTP..."
        curl_output=$(curl -s -o /dev/null -w \
            "HTTP Code: %{http_code}\nRedirect URL: %{redirect_url}\nRemote IP: %{remote_ip}:%{remote_port}\nTLS Version: %{ssl_verify_result} (%{scheme})\nTime DNS: %{time_namelookup}s\nTime Connect: %{time_connect}s\nTime TLS: %{time_appconnect}s\nTime First Byte: %{time_starttransfer}s\nTime Total: %{time_total}s\nBytes Downloaded: %{size_download}" \
            -L --max-time 15 --max-redirs 5 \
            -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
            -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" \
            -H "Accept-Language: en-US,en;q=0.5" \
            -H "Accept-Encoding: gzip, deflate, br" \
            -H "Connection: keep-alive" \
            -H "Upgrade-Insecure-Requests: 1" \
            "http://$domain" 2>&1)
    fi

    echo "   $curl_output" | sed 's/^/   /'
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
    
    echo ""
    echo "Running traceroute to $domain..."
    # Stream output live while also saving to temp file for parsing
    # Use ICMP mode which often gets more responses from routers
    # Only traceroute needs sudo (for raw sockets), not the whole script
    traceroute_tmp=$(mktemp)
    sudo traceroute --icmp -w 3 --max-hop=20 "$domain" 2>&1 | tee "$traceroute_tmp"

    hop_ips=()
    first_line=true
    while IFS= read -r line; do
        # Skip the header line (e.g. "traceroute to example.com (1.2.3.4), 30 hops max")
        if $first_line; then
            first_line=false
            continue
        fi
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

        # Parse batch JSON reliably using Python
        parsed_lines=$(echo "$batch_result" | python3 parse_batch.py "${hop_ips[@]}")

        echo ""
        echo "Physical Path Mapping:"
        echo "-----------------------------"
        echo "Hop | IP Address       | City             | Country          | ISP"
        echo "----|------------------|------------------|------------------|--------------------"

        # Build map JSON using Python-parsed data
        map_json="[{\"lat\":$MY_LAT,\"lon\":$MY_LON,\"label\":\"Origin\",\"popup\":\"$MY_CITY (Origin)\",\"type\":\"start\"}"

        hop_count=1
        while IFS='|' read -r ip ip_city ip_country ip_isp ip_lat ip_lon; do
            printf "%-4s| %-17s| %-17s| %-17s| %s\n" \
                "$hop_count" "$ip" "$ip_city" "$ip_country" "$ip_isp"

            # Add to map data if we have coordinates
            if [[ -n "$ip_lat" && -n "$ip_lon" ]]; then
                map_json+=",{\"lat\":$ip_lat,\"lon\":$ip_lon,\"label\":\"$ip\",\"popup\":\"Hop $hop_count: $ip<br>$ip_city, $ip_country<br>ISP: $ip_isp\",\"type\":\"hop\"}"
            fi

            hop_count=$((hop_count + 1))
        done <<< "$parsed_lines"

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

# --- Stop packet capture ---
if [[ -n "$TCPDUMP_PID" ]] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    sudo kill "$TCPDUMP_PID" 2>/dev/null
    wait "$TCPDUMP_PID" 2>/dev/null
    sudo chown "$USER:$USER" "$PCAP_FILE" 2>/dev/null
    pcap_size=$(du -h "$PCAP_FILE" 2>/dev/null | cut -f1)
    echo ""
    echo "   Packet capture saved: $PCAP_FILE ($pcap_size)"
    echo "   Analyze with: tcpdump -r $PCAP_FILE | head -20"
fi

echo ""
echo "   ANALYSIS COMPLETE"
echo "   Results saved to: $LOG_FILE"
echo "   Route maps saved to: route_maps/"
echo "   Packet captures saved to: captures/"