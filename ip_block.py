#!/usr/bin/env python3
import requests
import json
import time
import subprocess
import re
import os
import ipaddress
from collections import defaultdict

# Configuration - REPLACE "1" WITH YOUR TEAM NUMBER
TEAM_NUMBER = "1"
IPINFO_API = f"http://ipinfo.team{TEAM_NUMBER}"
CACHE_FILE = "/root/trafficwars/ip_cache.json"
LOG_FILE = "/var/log/nginx/access.log"
SUSPICIOUS_THRESHOLD =60  # Requests per minute

# Setup simple cache
ip_cache = {}
ip_counters = defaultdict(list)
suspicious_ips = set()

# Initialize the cache
try:
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            ip_cache = json.load(f)
        print(f"Loaded {len(ip_cache)} IPs from cache")
except:
    print("Starting with empty cache")

# Rate limiting
last_api_call = 0
api_call_count = 0

def get_ip_metadata(ip):
    """Get IP metadata, using cache if available"""
    global last_api_call, api_call_count
    
    # Check cache first
    if ip in ip_cache:
        if ip_cache[ip].get("confidence") != "low":  # Don't count low confidence hits
            return ip_cache[ip]
    
    # Check if we can infer from subnet
    subnet = get_subnet(ip)
    for cached_ip in ip_cache:
        if get_subnet(cached_ip) == subnet and "inferred_from_subnet" not in ip_cache[cached_ip]:
            # Create a copy of the metadata with lower confidence
            metadata = ip_cache[cached_ip].copy()
            metadata["confidence"] = "medium"
            metadata["inferred_from_subnet"] = True
            ip_cache[ip] = metadata
            save_cache()
            print(f"Inferred data for {ip} from subnet {subnet}")
            return metadata
    
    # Rate limit API calls
    current_time = time.time()
    if current_time - last_api_call < 1:  # At most 1 call per second
        time.sleep(1 - (current_time - last_api_call))
    
    # Call API
    try:
        print(f"Calling API for {ip}")
        response = requests.get(f"{IPINFO_API}/ips/{ip}", timeout=5)
        last_api_call = time.time()
        api_call_count += 1
        
        if response.status_code == 200:
            metadata = response.json()
            metadata["timestamp"] = int(time.time())
            metadata["confidence"] = "high"
            ip_cache[ip] = metadata
            save_cache()
            return metadata
        elif response.status_code == 429:
            print(f"Rate limited by API, waiting...")
            time.sleep(2)  # Back off for 2 seconds
            return {"error": "rate_limited", "ip": ip}
        else:
            print(f"API error: {response.status_code}")
            return {"error": f"api_error_{response.status_code}", "ip": ip}
    except Exception as e:
        print(f"Exception calling API: {e}")
        return {"error": "exception", "ip": ip}

def get_subnet(ip, mask=24):
    """Get the subnet of an IP address"""
    try:
        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return str(network.network_address)
    except:
        return None

def save_cache():
    """Save the cache to disk"""
    try:
        # Only save the most recent 1000 entries to keep the file size reasonable
        if len(ip_cache) > 1000:
            # Sort by timestamp and keep the most recent
            sorted_ips = sorted(ip_cache.items(), 
                               key=lambda x: x[1].get("timestamp", 0), 
                               reverse=True)
            # Convert back to dict, keeping only the top 1000
            ip_cache_trimmed = {ip: data for ip, data in sorted_ips[:1000]}
        else:
            ip_cache_trimmed = ip_cache
            
        with open(CACHE_FILE, 'w') as f:
            json.dump(ip_cache_trimmed, f)
    except Exception as e:
        print(f"Error saving cache: {e}")

def block_ip(ip):
    """Block an IP using ipset"""
    try:
        # Ensure ipset exists
        result = subprocess.run(["ipset", "list", "threat"], 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE)
        if result.returncode != 0:
            # Create ipset
            subprocess.run([
                "ipset", "create", "threat", "hash:ip", 
                "timeout", "3600"  # Auto-expire IPs after 1 hour
            ])
            
            # Add iptables rule
            subprocess.run([
                "iptables", "-A", "INPUT", "-m", "set", 
                "--match-set", "threat", "src", "-j", "DROP"
            ])
        
        # Block the IP
        subprocess.run(["ipset", "add", "threat", ip])
        print(f"BLOCKED IP: {ip}")
        return True
    except Exception as e:
        print(f"Error blocking IP {ip}: {e}")
        return False

def analyze_log_line(line):
    """Analyze a NGINX log line"""
    # Parse the line
    match = re.search(r'(\d+\.\d+\.\d+\.\d+) .* \[(.*?)\] "(.*?)" (\d+)', line)
    if not match:
        return
    
    ip, timestamp_str, request, status_code = match.groups()
    
    # Update request count
    current_time = time.time()
    ip_counters[ip].append(current_time)
    
    # Clean up old requests (older than 60 seconds)
    ip_counters[ip] = [t for t in ip_counters[ip] if current_time - t < 60]
    
    # Check request rate
    request_count = len(ip_counters[ip])
    
    # Get IP metadata
    if request_count > 5 and ip not in ip_cache:  # Only lookup IPs with multiple requests
        metadata = get_ip_metadata(ip)
    elif ip in ip_cache:
        metadata = ip_cache[ip]
    else:
        return
    
    # Check for suspicious behavior
    is_vpn = metadata.get("privacy", {}).get("vpn", False)
    country_code = metadata.get("countryCode", "Unknown")
    asn_type = metadata.get("asn", {}).get("type")
    is_hosting = asn_type == "hosting"
    
    # Determine if IP is suspicious
    is_suspicious = False
    
    if is_vpn:
        is_suspicious = True
        reason = "VPN detected"
    elif is_hosting and request_count > SUSPICIOUS_THRESHOLD / 2:
        is_suspicious = True
        reason = f"Hosting provider with high request rate ({request_count}/min)"
    elif request_count > SUSPICIOUS_THRESHOLD:
        is_suspicious = True
        reason = f"High request rate ({request_count}/min)"
    
    # Block suspicious IPs
    if is_suspicious and ip not in suspicious_ips:
        suspicious_ips.add(ip)
        print(f"\n[!] Suspicious IP detected: {ip} ({country_code}) - {reason}")
        
        # Block the IP if it's clearly malicious
        if request_count > SUSPICIOUS_THRESHOLD * 1.5 or is_vpn:
            block_ip(ip)

def tail_and_analyze():
    """Tail the NGINX log file and analyze lines in real-time"""
    # Start tailing the log file
    process = subprocess.Popen(
        ["tail", "-f", LOG_FILE], 
        stdout=subprocess.PIPE, 
        universal_newlines=True
    )
    
    print(f"Starting IP analysis of NGINX logs...")
    print("Press Ctrl+C to stop.")
    
    start_time = time.time()
    lines_processed = 0
    
    try:
        for line in process.stdout:
            analyze_log_line(line)
            lines_processed += 1
            
            # Print stats periodically
            if lines_processed % 100 == 0:
                elapsed = time.time() - start_time
                print(f"\nStats: {lines_processed} lines processed in {elapsed:.1f}s")
                print(f"Active IPs: {len(ip_counters)}, Cache size: {len(ip_cache)}")
                print(f"Suspicious IPs: {len(suspicious_ips)}, API calls: {api_call_count}")
                
                # Show top IPs by request count
                top_ips = sorted(
                    [(ip, len(times)) for ip, times in ip_counters.items()],
                    key=lambda x: x[1],
                    reverse=True
                )[:5]
                
                if top_ips:
                    print("\nTop IPs by request rate:")
                    for ip, count in top_ips:
                        metadata = ip_cache.get(ip, {})
                        country = metadata.get("countryCode", "?")
                        is_vpn = metadata.get("privacy", {}).get("vpn", False)
                        vpn_str = " (VPN)" if is_vpn else ""
                        print(f"  {ip} ({country}){vpn_str}: {count} requests/min")
                
                # Save cache periodically
                save_cache()
    except KeyboardInterrupt:
        print("\nStopping IP analysis...")
        process.terminate()
    
    save_cache()
    print("Analysis complete.")

def lookup_ip(ip):
    """Look up a specific IP"""
    metadata = get_ip_metadata(ip)
    print(json.dumps(metadata, indent=2))

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "lookup" and len(sys.argv) > 2:
            lookup_ip(sys.argv[2])
        elif sys.argv[1] == "block" and len(sys.argv) > 2:
            block_ip(sys.argv[2])
        else:
            print("Usage:")
            print("  python3 simple_defender.py             - Start monitoring NGINX logs")
            print("  python3 simple_defender.py lookup IP   - Look up an IP address")
            print("  python3 simple_defender.py block IP    - Block an IP address")
    else:
        tail_and_analyze()
