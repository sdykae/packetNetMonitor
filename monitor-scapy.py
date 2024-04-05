from scapy.all import sniff
import requests

API_KEY = 'b16c4e2226847a5422010ad3274c9b9c479418eab38d8cd110f0c26a8621bdac6654f66d3fcb454e'
API_URL = 'https://api.abuseipdb.com/api/v2/check'

def handle_packet(packet):
    """
    This function will be called for each captured packet.
    """
    if packet.haslayer('IP'):
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst
        
        # Here you can filter for specific IPs or perform additional checks
        print(f"Packet: {ip_src} -> {ip_dst}")
        
        # Optionally, check the IP against AbuseIPDB (rate limits may apply)
        #check_ip(ip_src)
        check_ip(ip_dst)

def check_ip(ip):
    """
    Check if an IP is malicious according to AbuseIPDB.
    """
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY,
    }
    response = requests.get(API_URL, headers=headers, params={'ipAddress': ip, 'maxAgeInDays': '90'})
    if response.status_code == 200:
        result = response.json()
        score = result['data']['abuseConfidenceScore']
        if score > 0:
            print(f"Malicious connection detected: {ip} (Confidence Score: {score})")
        else:
            # Log as safe if the confidence score is 0
            print(f"Safe connection detected: {ip} (Confidence Score: {score})")
    else:
        print(f"Failed to check IP {ip}. Status Code: {response.status_code}")


# Start sniffing packets. Adjust the iface parameter as needed.
sniff(prn=handle_packet, filter="ip", store=False)
