import time
import scapy.all as scapy
import json
import random
import threading
from common import *
iface = "eth0"
json_file = "/home/pi/dhcp_starver/spoofed_hosts.json"

# DHCP Server's IP and MAC address
dhcp_server_ip = "192.168.1.1"
dhcp_server_mac = "30:B5:C2:51:01:13"


# Define a semaphore for .log/.json file access without collision
file_semaphore = threading.Semaphore()

def release_all_ips(host_dict):
    """
    Sends a DHCP Release for every fake host with an IP address linked
    """
    print(f"Releasing all spoofed IP addresses:")
    #global spoofed_ip_dict
    for ip, host in host_dict.items():
        #if host.is_spoofed:
        send_release(host.mac_address, ip)
        # Updating spoofed host's dict
        host_dict[ip].is_spoofed = False
        time.sleep(0.25)
    print(f"All IP addresses have been released!")


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
    print(f"Releasing IP address {ip_address} from {host_mac}")


def main():

    try:
        spoofed_hosts_dict = load_from_json(json_file, file_semaphore)
        release_all_ips(spoofed_hosts_dict)
        save_to_json(spoofed_hosts_dict, json_file, file_semaphore)
    
    except Exception as e:

        print(e)
        

    finally:
        
        print(f"Service terminated")
    

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        print(f"Service manually terminated")