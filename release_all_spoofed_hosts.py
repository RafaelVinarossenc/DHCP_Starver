from common import *
from utils import file_semaphore

iface = "eth0"
json_file = "/home/pi/dhcp_starver/bogus_hosts.json"

#dhcp_server_ip = "192.168.1.25"
#dhcp_server_mac = "30:B5:C2:51:01:13"


def release_all_ips(host_dict):
    """
    Sends a DHCP Release for every fake host with an IP address linked
    """
    print(f"Releasing all spoofed IP addresses:")
    for ip, host in host_dict.items():
        print(f"Releasing IP address {ip} from {host.mac_address}")
        send_release(host.mac_address, ip, 0.1, dhcp_server_ip, dhcp_server_mac, iface)
        # Updating spoofed host's dict
        host_dict[ip].is_spoofed = False
        update_json_file(host_dict, hosts_file, file_semaphore)

    print(f"All IP addresses have been released!")


def find_dhcp_server():
    """
    Check and find DHCP server on known router JSON file
    """
    try:
        with file_semaphore:
            with open(router_file, 'r') as file:
                data = json.load(file)
        
        dhcp_server_dict = {ip: dhcp_server.from_dict(host_data) for ip, host_data in data.items()}

    except FileNotFoundError as e:
        write_to_log(f"File not found: {router_file}")
        dhcp_server_dict = {}
    except json.JSONDecodeError as e:
        write_to_log(f"Error decoding JSON file: {e}")
        dhcp_server_dict = {}
    except Exception as e:
        write_to_log(f"Unknown error during file read: {e}")
        dhcp_server_dict = {}

    for server_data in dhcp_server_dict.values():

        return server_data.ip_address, server_data.mac_address
    
    return None, None


def main():

    try:
        global dhcp_server_ip, dhcp_server_mac
        dhcp_server_ip, dhcp_server_mac = find_dhcp_server()
        #dhcp_server_ip = "192.168.1.25"
        #dhcp_server_mac = "30:B5:C2:51:01:13"
        
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