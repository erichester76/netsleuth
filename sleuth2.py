import scapy.all as scapy
import pynetbox
import socket
from mac_vendor_lookup import MacLookup
from pyp0f import p0f
from scapy.layers.dhcp import DHCP
from scapy.layers.mdns import DNS
from scapy.layers.l2 import ARP
from scapy.layers.upnp import UPnP
from scapy.layers.inet import IP
from concurrent.futures import ThreadPoolExecutor
import json
import threading

# NetBox API settings
NETBOX_API_URL = "http://<netbox_url>/"
NETBOX_API_TOKEN = "<your_netbox_api_token>"

# Initialize pynetbox API client
nb = pynetbox.api(NETBOX_API_URL, token=NETBOX_API_TOKEN)

def send_to_netbox(data):
    """Send inventory data to NetBox."""
    try:
        print(f"[Debug] Would send to NetBox: {data}")
    except Exception as e:
        print(f"[Debug] Failed to prepare data for NetBox: {e}")

def get_hostname(ip):
    """Attempt to resolve the hostname via reverse DNS."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def arping_to_get_mac(ip):
    """Send ARP request to get the MAC address for the given IP."""
    try:
        answered, _ = scapy.arping(ip, verbose=0)
        for sent, received in answered:
            return received.hwsrc
    except Exception as e:
        print(f"Error in ARPing for IP {ip}: {e}")
        return None

def create_device_from_dhcp(dhcp_info, mac):
    """Create a device in NetBox using DHCP attributes."""
    if not mac and "dhcp_server" in dhcp_info:
        mac = arping_to_get_mac(dhcp_info["dhcp_server"])

    vendor = MacLookup().lookup(mac) if mac else "Unknown"
    primary_ip = dhcp_info.get("dhcp_server", "Unknown")
    device_role = "DHCP Server" if "dhcp_server" in dhcp_info else "Endpoint"
    hostname = dhcp_info.get("hostname", "DHCP Device")

    device_data = {
        "name": hostname,
        "mac_address": mac,
        "manufacturer": vendor,
        "primary_ip": primary_ip,
        "device_role": device_role,
    }
    send_to_netbox(device_data)

    # Create additional devices for other attributes
    if "router" in dhcp_info:
        router_mac = arping_to_get_mac(dhcp_info["router"])
        router_vendor = MacLookup().lookup(router_mac) if router_mac else "Unknown"
        router_data = {
            "name": f"Router-{dhcp_info['router']}",
            "mac_address": router_mac,
            "manufacturer": router_vendor,
            "primary_ip": dhcp_info["router"],
            "device_role": "Router",
        }
        send_to_netbox(router_data)

    if "dns_servers" in dhcp_info:
        for dns in dhcp_info["dns_servers"]:
            dns_mac = arping_to_get_mac(dns)
            dns_vendor = MacLookup().lookup(dns_mac) if dns_mac else "Unknown"
            dns_data = {
                "name": f"DNS-{dns}",
                "mac_address": dns_mac,
                "manufacturer": dns_vendor,
                "primary_ip": dns,
                "device_role": "DNS Server",
            }
            send_to_netbox(dns_data)

    if "ntp_servers" in dhcp_info:
        for ntp in dhcp_info["ntp_servers"]:
            ntp_mac = arping_to_get_mac(ntp)
            ntp_vendor = MacLookup().lookup(ntp_mac) if ntp_mac else "Unknown"
            ntp_data = {
                "name": f"NTP-{ntp}",
                "mac_address": ntp_mac,
                "manufacturer": ntp_vendor,
                "primary_ip": ntp,
                "device_role": "NTP Server",
            }
            send_to_netbox(ntp_data)

def process_packet(packet):
    """Process captured packets for device information."""
    try:
        if ARP in packet and packet[ARP].op == 1:  # ARP Request
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            hostname = get_hostname(ip) or "Unknown"
            vendor = MacLookup().lookup(mac)

            device_data = {
                "name": hostname,
                "mac_address": mac,
                "manufacturer": vendor,
                "primary_ip": ip,
                "device_role": "Server" if vendor in ["VMware", "Microsoft"] else "Endpoint",
            }
            send_to_netbox(device_data)

        elif DHCP in packet and packet[DHCP].op == 2:  # DHCP Offer/ACK
            mac = packet.src  # Source MAC address from the packet
            dhcp_info = {}
            for option in packet[DHCP].options:
                if isinstance(option, tuple):
                    key = option[0]
                    value = option[1]
                    if key == "server_id":
                        dhcp_info["dhcp_server"] = value
                    elif key == "hostname":
                        dhcp_info["hostname"] = value
                    elif key == "domain":
                        dhcp_info["domain"] = value
                    elif key == "router":
                        dhcp_info["router"] = value
                    elif key == "name_server":
                        dhcp_info.setdefault("dns_servers", []).append(value)
                    elif key == "ntp_server":
                        dhcp_info.setdefault("ntp_servers", []).append(value)

            if dhcp_info:
                print(f"DHCP Info: {dhcp_info}")
                create_device_from_dhcp(dhcp_info, mac)

        elif DNS in packet and packet[DNS].qdcount > 0:  # mDNS/Bonjour
            mac = packet.src  # Source MAC address from the packet
            query_name = packet[DNS].qd.qname.decode('utf-8')
            dns_info = {
                "query_name": query_name,
                "query_type": packet[DNS].qd.qtype
            }
            print(f"mDNS Query: {dns_info}")
            vendor = MacLookup().lookup(mac)
            device_data = {
                "name": query_name.split('.')[0],
                "mac_address": mac,
                "manufacturer": vendor,
                "primary_ip": packet[IP].src if IP in packet else "Unknown",
                "device_role": "mDNS Device",
            }
            send_to_netbox(device_data)

        elif UPnP in packet:  # UPnP discovery
            mac = packet.src  # Source MAC address from the packet
            print("UPnP packet detected.")
            if IP in packet:
                vendor = MacLookup().lookup(mac)
                device_data = {
                    "name": "UPnP Device",
                    "mac_address": mac,
                    "manufacturer": vendor,
                    "primary_ip": packet[IP].src,
                    "device_role": "UPnP Device",
                }
                send_to_netbox(device_data)

        # Add pyp0f fingerprinting here if applicable
        # Example: p0f_client = p0f() - requires configuration

    except Exception as e:
        print(f"Error processing packet: {e}")

def monitor_interfaces():
    """Start monitoring all network interfaces."""
    print("Starting packet capture on all interfaces...")
    scapy.sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    monitor_interfaces()
