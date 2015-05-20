from scapy.all import *

filter_ip = '192.168.2.119'

def arp_monitor_callback(pkt):
  if ARP in pkt and pkt[ARP].op in (1, 2):
    if pkt[ARP].pdst == filter_ip or pkt[ARP].psrc == filter_ip:
      return pkt.sprintf(("who-has" if pkt[ARP].op == 1 else "is-at")+" from %ARP.psrc%(%ARP.hwsrc%) to %ARP.pdst%(%ARP.hwdst%)")

sniff(prn=arp_monitor_callback, filter="arp", store=0)

