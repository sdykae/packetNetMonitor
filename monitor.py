import psutil
import requests

# Your AbuseIPDB API key
API_KEY = 'b16c4e2226847a5422010ad3274c9b9c479418eab38d8cd110f0c26a8621bdac6654f66d3fcb454e'

# Base URL for the AbuseIPDB API
API_URL = 'https://api.abuseipdb.com/api/v2/check'

headers = {
    'Accept': 'application/json',
    'Key': API_KEY,
}

def check_ip(ip):
    """
    Check if an IP is malicious according to AbuseIPDB.
    """
    response = requests.get(API_URL, headers=headers, params={'ipAddress': ip, 'maxAgeInDays': '90'})
    if response.status_code == 200:
        result = response.json()
        if result['data']['abuseConfidenceScore'] > 0:
            print(f"Malicious connection detected: {ip} (Confidence Score: {result['data']['abuseConfidenceScore']})")
    else:
        print(f"Failed to check IP {ip}. Status Code: {response.status_code}")

def monitor_connections():
    """
    Monitor active connections and check each IP against AbuseIPDB.
    """
    for conn in psutil.net_connections(kind='inet'):
        # Filtering out local and established connections
        if conn.laddr and conn.status == 'ESTABLISHED':
            ip = conn.raddr[0]
            check_ip(ip)

if __name__ == "__main__":
    monitor_connections()
