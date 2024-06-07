import time
import scapy.all as scapy
import random
import threading
from common import *

iface = "eth0"
json_file = "/home/pi/dhcp_starver/spoofed_hosts.json"

# DHCP Server's IP and MAC address
dhcp_server_ip = "192.168.1.25"
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
        print(f"Releasing IP address {ip} from {host.mac_address}")
        send_release(host.mac_address, ip, 0.25, dhcp_server_ip, dhcp_server_mac, iface)
        # Updating spoofed host's dict
        host_dict[ip].is_spoofed = False

    print(f"All IP addresses have been released!")


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