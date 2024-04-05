from queue import Queue
import sqlite3
import datetime
from scapy.all import sniff
import tkinter as tk

from threading import Thread
import threading
import requests

API_KEY = 'b16c4e2226847a5422010ad3274c9b9c479418eab38d8cd110f0c26a8621bdac6654f66d3fcb454e'
API_URL = 'https://api.abuseipdb.com/api/v2/check'

# Initialize Tkinter in a thread-safe manner
def init_gui_queue(gui_queue):
    while True:
        try:
            ip, message_type, score, now = gui_queue.get_nowait()  # Unpack the IP and message
            # Pass both to the update function
            update_alert_window(ip, message_type, score, now)
        except:
            root.after(100, init_gui_queue, gui_queue)  # Re-check after 100ms
            return


# Adjusted update_alert_window function to handle IP state
ip_message_map = {}  # Global dictionary to track messages for IPs

def update_alert_window(ip, message, score, last_checked):
    """
    Update the alert window with a new message formatted as a table row,
    or update an existing one for the IP.
    """
    # Formatting the message as a table row
    formatted_message = f"{message:<30}{ip:<20}{score:<10}{last_checked:<20}\n"

    alert_text.config(state=tk.NORMAL)
    if ip in ip_message_map:
        # If the IP exists, calculate where to update the message
        start_index = f"{ip_message_map[ip]}.0"
        end_index = f"{ip_message_map[ip] + 1}.0"
        
        # Deleting the old message
        alert_text.delete(start_index, end_index)
        
        # Inserting the updated message at the same position
        alert_text.insert(start_index, formatted_message)
    else:
        # If the IP doesn't exist, append the new message
        alert_text.insert(tk.END, formatted_message)
        
        # Calculating and saving the new message's line number
        line_number = int(alert_text.index('end-2c').split('.')[0])
        ip_message_map[ip] = line_number

    alert_text.config(state=tk.DISABLED)
    
    if not alert_window.winfo_viewable():
        alert_window.deiconify()  # Show window if not already visible


root = tk.Tk()
root.withdraw()  # Hide the main Tk window

# Create a persistent alert window
alert_window = tk.Toplevel()
alert_window.title("Connection Alerts")
alert_window.geometry("800x400")

# Hide instead of close
alert_window.protocol("WM_DELETE_WINDOW", alert_window.withdraw)


# Add a Text widget to the alert window
alert_text = tk.Text(alert_window, state=tk.DISABLED, wrap=tk.WORD)
alert_text.pack(expand=True, fill=tk.BOTH)
alert_text.config(state=tk.NORMAL)
header = f"{'Message':<30}{'IP':<20}{'Score':<10}{'Last Checked':<20}\n" + "-"*80 + "\n"
alert_text.insert(tk.END, header)
alert_text.config(state=tk.DISABLED)



# Initialize your GUI update queue and start the GUI loop
gui_queue = Queue()
root.after(100, init_gui_queue, gui_queue)


thread_local = threading.local()


def get_db():
    """
    Returns a separate SQLite connection for each thread.
    Ensures the database and required table are initialized for each connection.
    """
    if not hasattr(thread_local, "connection"):
        thread_local.connection = sqlite3.connect(
            'ip_checks.db', check_same_thread=False)
        # Move the table creation logic here
        cursor = thread_local.connection.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_checks (
                ip_address TEXT PRIMARY KEY,
                abuse_confidence_score INTEGER,
                last_checked TEXT
            )
        ''')
        thread_local.connection.commit()
    return thread_local.connection


def check_ip_in_db(ip):
    """
    Check if an IP address exists in the database and is up-to-date.
    Returns None if not found or outdated, otherwise the abuse confidence score.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT abuse_confidence_score, last_checked FROM ip_checks WHERE ip_address = ?', (ip,))
    row = cursor.fetchone()
    if row:
        score, last_checked_str = row
        last_checked = datetime.datetime.strptime(
            last_checked_str, '%Y-%m-%d %H:%M:%S')
        if datetime.datetime.now() - last_checked < datetime.timedelta(days=30):  # Re-check if older than 30 days
            return score
    return None


def update_db_with_ip(ip, score):
    """
    Update the database with the IP check result.
    """
    conn = get_db()  # Use thread-local connection
    cursor = conn.cursor()
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
        # check the IP against AbuseIPDB
        # check_ip(ip_src)
        check_ip(ip_dst)


def check_ip(ip):
    now = datetime.datetime.now().strftime(
        '%Y-%m-%d %H:%M:%S')  # Get current timestamp
    score = check_ip_in_db(ip)
    if score is None:  # If not in DB or outdated, make a new request
        headers = {
            'Accept': 'application/json',
            'Key': API_KEY,
        }
        response = requests.get(API_URL, headers=headers, params={
                                'ipAddress': ip, 'maxAgeInDays': '90'})
        if response.status_code == 200:
            result = response.json()
            score = result['data']['abuseConfidenceScore']
            update_db_with_ip(ip, score)
        else:
            print(f"Failed to check IP {ip}. Status Code: {
                  response.status_code}")
            return

    if score > 0:
        message_type = "Malicious connection detected"
        alert_message = f"{message_type}: {ip} (Score: {score}) - Last checked: {now}"

        print(alert_message)
        gui_queue.put((ip, message_type, score, now))


    else:
        print(f"Safe connection detected: {ip} (Confidence Score: {score})")


# Start sniffing packets in a separate thread to keep the GUI responsive
def start_sniffing():
    sniff(prn=handle_packet, filter="ip", store=False)


sniff_thread = Thread(target=start_sniffing)
sniff_thread.daemon = True
sniff_thread.start()

# Start the Tkinter event loop
root.mainloop()
