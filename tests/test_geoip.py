from utils.geoip_helper import get_location_from_ip

# Test IPs: Google DNS, Localhost, and an example IP
ips = ["8.8.8.8", "127.0.0.1", "1.1.1.1"]

print("--- GeoIP Test ---")
for ip in ips:
    loc = get_location_from_ip(ip)
    print(f"IP: {ip} -> {loc}")

if get_location_from_ip("8.8.8.8"):
    print("\nSUCCESS: GeoIP API is working.")
else:
    print("\nFAIL: GeoIP API failed or blocked.")
