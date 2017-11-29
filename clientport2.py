from scapy.all import *
import time
from random import randint
import threading
from threading import Thread
from multiprocessing import Pool, Process
import os
import signal
import atexit

'''The Internet Assigned Numbers Authority (IANA) suggests the range 49152 to 65535
(2e15+2e14 to 2e16-1) for dynamic or private ports. Many Linux kernels use the port
range 32768 to 61000. FreeBSD has used the IANA port range since release 4.6.'''

targetIP = '192.168.1.100'
my_ip = '192.168.1.250'

_countAns = 0
_countUnans = 0

list_size = 10
pkt_list = []
i = 0

def incrAns(n):
 global _countAns
 _countAns = _countAns + n

def incrUnans(n):
 global _countUnans
 _countUnans = _countUnans + n

def savecounter(signal,frame):
 print "\n\n\n\n\n\n Experiment has been finished!!! \n\n\n\n\n\n"
 open("client_summary.txt", "w").write("Total sent packets: %d\nTotal unanswered packets: %d " % (_countAns, _countUnans))
 sys.exit(0)

signal.signal(signal.SIGINT, savecounter)
#atexit.register(savecounter)

def send_while(pkt,port):
 #while True:
 for i in range(10):
  now = time.time()
  ans, unans = sr(pkt, timeout=10)
  elapsed = time.time() - now
    
  if ans:
   print "Has been answered 1 packets for client", port, "in:", elapsed,"seconds."
   incrAns(1)
   open("client_tts.txt", "a").write("%d %.3f SUCC\n" % (port, elapsed)) 
  if unans:
   print "Has been unanswered 1 packets in:", elapsed,"seconds."
   open("client_tts.txt", "a").write("%d %.3f FAIL\n" % (port, elapsed))
   incrUnans(1)
  
  #time.sleep(randint(1,3))


#49912==760
#49952==800
open("client_tts.txt", "w").write("Port TTS(secs) Status\n")

#t_end = time.time() + 60 * 1
#while time.time() < t_end:

for port in range(50000,50200):
 spoofed_pkt = IP(src=my_ip,dst=targetIP) / TCP(sport=port,dport=80) / "GET /index.html HTTP/1.1 \n"
 #Thread(target=send_while, args=(spoofed_pkt,port,)).start()
 t = threading.Thread(target=send_while,args=(spoofed_pkt,port,))
 t.daemon = True
 t.start()
 time.sleep(randint(5,10))

print "\n\n\n\n\n\n All clients have been created! \n\n\n\n\n\n"
time.sleep(10)
print "\n\n\n\n\n\n TIME TO FINISH!! \n\n\n\n\n\n"
#sys.exit(0)
os.kill(os.getpid(), signal.SIGINT)
#os._exit(1)
