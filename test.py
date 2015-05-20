from scapy.all import *

def add(n1, n2):
  return n1+n2

"""
ip = ping = Ether()/IP(dst='8.8.8.8')/ICMP()
ip.show()
(r1, r2) = srp(ip)
r1.show()
"""

"""
dns = IP(dst='10.104.2.10')/UDP()/DNS(rd=1, qd=DNSQR(qname="www.perdu.com"))
#dns.show()
(r1, r2) = sr(dns)
r1.show()
r2.show()
"""
"""
def arpoison(targetIp, spoofIp):
  p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", psrc=spoofIp, pdst=targetIp)
  srp(p)
  return
  p = Ether(dst=target)/ARP(op="who-has", psrc='10.102.26.1', pdst=spoofIp, inter=RandNum(10, 40), loop=1)
  return p
  #send(


arpoison('10.102.26.103', '10.102.26.100')
#"""

"""
p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", psrc='10.102.26.94', pdst='10.102.26.103')
p.show()
#srp(p)
#"""

mlist = []
mlist.append(1)
mlist.append(2)
print mlist

