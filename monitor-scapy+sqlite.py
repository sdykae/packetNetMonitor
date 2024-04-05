import sqlite3
import datetime
from scapy.all import sniff
import requests

API_KEY = 'b16c4e2226847a5422010ad3274c9b9c479418eab38d8cd110f0c26a8621bdac6654f66d3fcb454e'
API_URL = 'https://api.abuseipdb.com/api/v2/check'

# Initialize and set up the database
conn = sqlite3.connect('ip_checks.sqlite')
cursor = conn.cursor()

# Create table
cursor.execute('''
CREATE TABLE IF NOT EXISTS ip_checks (
    ip_address TEXT PRIMARY KEY,
    abuse_confidence_score INTEGER,
    last_checked TEXT
)
''')
conn.commit()


def check_ip_in_db(ip):
    """
    Check if an IP address exists in the database and is up-to-date.
    Returns None if not found or outdated, otherwise the abuse confidence score.
    """
    cursor.execute('SELECT abuse_confidence_score, last_checked FROM ip_checks WHERE ip_address = ?', (ip,))
    row = cursor.fetchone()
    if row:
        score, last_checked_str = row
        last_checked = datetime.datetime.strptime(last_checked_str, '%Y-%m-%d %H:%M:%S')
        if datetime.datetime.now() - last_checked < datetime.timedelta(days=30):  # Re-check if older than 30 days
            return score
    return None

def update_db_with_ip(ip, score):
    """
    Update the database with the IP check result.
    """
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('REPLACE INTO ip_checks (ip_address, abuse_confidence_score, last_checked) VALUES (?, ?, ?)',
                   (ip, score, now))
    conn.commit()


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

    score = check_ip_in_db(ip)

    if score is None:  # If not in DB or outdated, make a new request
      headers = {
          'Accept': 'application/json',
          'Key': API_KEY,
      }
      response = requests.get(API_URL, headers=headers, params={'ipAddress': ip, 'maxAgeInDays': '90'})
      if response.status_code == 200:
          result = response.json()
          score = result['data']['abuseConfidenceScore']
          update_db_with_ip(ip, score)
          if score > 0:
              print(f"Malicious connection detected: {ip} (Confidence Score: {score})")
          else:
              # Log as safe if the confidence score is 0
              print(f"Safe connection detected: {ip} (Confidence Score: {score})")
      else:
          print(f"Failed to check IP {ip}. Status Code: {response.status_code}")
          return

# Start sniffing packets. Adjust the iface parameter as needed.
sniff(prn=handle_packet, filter="ip", store=False)
