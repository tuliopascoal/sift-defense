# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# v 1.0
# Copyright (C) 2016 LAR
# Author: Tulio Pascoal

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu import utils
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp
import collections
from datetime import datetime, timedelta
from random import random, uniform
import threading
import thread
import time
from ryu.lib import hub
import atexit
import logging
import ryu.app.ofctl.api

_countfull = 0
_countbuffer = 0
_countflowmod = 0
_countin = 0
_countinR = 0

def incrcounterF(n):
 global _countfull
 _countfull = _countfull + n
 
def incrcounterB(n):
 global _countbuffer
 _countbuffer = _countbuffer + n

def incrcounterFlowMod(n):
 global _countflowmod
 _countflowmod = _countflowmod + n
 
def incrcounterIn(n):
 global _countin
 _countin = _countin + n

def incrcounterInR(n):
 global _countinR
 _countinR = _countinR + n 

def savecounter():
 open("counters", "w").write("Table Full Messages: %d\nBuffer Unknow Messages: %d\nFlow Mod Messages: %d\nPacket-In Messages: %d\nPacket-InR Messages: %d " % (_countfull, _countbuffer, _countflowmod, _countin, _countinR))
 #open("counters", "w").write("\nBuffer Unknow Messages: %d" % _countbuffer)
 #open("counters", "w").write("\nPacket In Messages: %d" % _countflowmod)
 #open("counterB", "w").write("%d" % _countbuffer)
 #open("counterB", "w").write("%d" % _countbuffer)

atexit.register(savecounter)

Flow = collections.namedtuple('Flow', 'src, dst, tcp_src, tcp_dst, time_in, match')
IDLE_TIME = 10
HARD_TIME = 0
#TIME = IDLE_TIME + 0.5
PMOD = 1500
buffer = 1500

pmod = 1500
round = 0.1
flow_list = list()
lock = threading.Lock()

class SimpleSwitch13(app_manager.RyuApp):
 OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

 def __init__(self, *args, **kwargs):
  super(SimpleSwitch13, self).__init__(*args, **kwargs)
  self.mac_to_port = {}
  try:
   thread.start_new_thread(self.reset_round, ( round,))
  except:
   print "Unable to start Thread for reset_round"
 
 @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
 def switch_features_handler(self,ev):
  datapath = ev.msg.datapath
  ofproto = datapath.ofproto
  parser = datapath.ofproto_parser

  match = parser.OFPMatch()
  actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER)]
  self.add_Cflow(datapath, 0, match, actions)

 def reset_round(self, round):

  global pmod

  while True:
   pmod = PMOD
   #print 'NEW PMOD:', pmod
   time.sleep(round)

 def clean_by_timeout(self, time):

  global flow_list

  while True:
   i=0

   while i < len(flow_list):
    time_now = datetime.now()
    diff = time_now - flow_list[i].time_in
    if ( diff.seconds >= IDLE_TIME | diff.seconds >= HARD_TIME ):
     print "timeout esgotado para:", flow_list[i]
     del flow_list[i]
   time.sleep(time)

 def check_flow(self, new_flow):

  global flow_list
  global lock
  
  lock.acquire()
  try:
   i=0
   while (i < len(flow_list)):
    if ( (new_flow.src == flow_list[i].src) and (new_flow.dst == flow_list[i].dst) and (new_flow.tcp_src == flow_list[i].tcp_src) and (new_flow.tcp_dst == flow_list[i].tcp_dst) ):
     #print "flow already created:", flow_list[i]
     return True
    else:
     i = i +1
   return False
  finally:
   lock.release()
   
 def check_pair(self, flow, datapath):

  global flow_list
  global lock
  
  lock.acquire()
  try:
   i=0
   while (i < len(flow_list)):
    if ( (flow.src == flow_list[i].dst) and (flow.dst == flow_list[i].src) and (flow.tcp_src == flow_list[i].tcp_dst) and (flow.tcp_dst == flow_list[i].tcp_src) ):
     print "pair flow found:", flow_list[i]
     flow_removed = flow_list.pop(i)
     match_del = flow_removed.match
     self.remove_flow(datapath, match_del)
     #print "List initial size:", len(flow_list)
     print "PAIR FLOW REMOVED!!!!!:", match_del
     #print "List final size:", len(flow_list)
     return True
    else:
     i = i +1
   return False
  finally:
   lock.release()

 def check_pair2(self, ip_src, ip_dst, tcp_src, tcp_dst, datapath):

  global flow_list
  global lock
  #print ip_src, ip_dst, tcp_src, tcp_dst
  
  lock.acquire()
  try:
   i=0
   while (i < len(flow_list)):
    if ( (ip_src == flow_list[i].dst) and (ip_dst == flow_list[i].src) and (tcp_src == flow_list[i].tcp_dst) and (tcp_dst == flow_list[i].tcp_src) ):
     print "pair flow found:", flow_list[i]
     flow_removed = flow_list.pop(i)
     match_del = flow_removed.match
     self.remove_flow(datapath, match_del)
     #print "List initial size:", len(flow_list)
     print "PAIR FLOW REMOVED!!!!!:", match_del
     #print "List final size:", len(flow_list)
     return True
    else:
     i = i +1
   return False
  finally:
   lock.release()
   
 def remove_flow_list(self, src, dst):

  global flow_list
  global lock
  
  lock.acquire()
  try:
  #print "List initial size into remove_flow_list:", len(flow_list)
   i=0
   while (i < len(flow_list)):
    if ( (src == flow_list[i].src) and (dst == flow_list[i].dst)):
     #print flow_list[i]
     del flow_list[i]
     #print "List final size into remove_flow_list:", len(flow_list)
   
    else:
     i = i + 1
  finally:
   lock.release()

 def add_Cflow(self, datapath, priority, match, actions, buffer_id=None):
        
        global flow_list
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info("controller flow created")
 
 def add_flow(self, datapath, priority, match, actions, pkt_ip=None,pkt_ethernet=None, pkt_tcp=None, idle_timeout=None, hard_timeout=None, buffer_id=None):

  if pkt_tcp is None:
   print 'NAO eh TCP (add_flow)!!!'
   return

  global flow_list
  global pmod
  global lock
  
  ofproto = datapath.ofproto
  parser = datapath.ofproto_parser
  source_ip = pkt_ip.src
  destination_ip = pkt_ip.dst
  tcp_src = pkt_tcp.src_port
  tcp_dst = pkt_tcp.dst_port

  new_flow = Flow(src=source_ip, dst=destination_ip, tcp_src=tcp_src, tcp_dst=tcp_dst, time_in=datetime.now(), match=match)
  
  '''found = self.check_flow(new_flow) 
  if (found == True):
   print "List final size:", len(flow_list)
   return'''

  inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
  
  if buffer_id:
   mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                        priority=priority, match=match,
                                        idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                        instructions=inst, flags=ofproto.OFPFF_SEND_FLOW_REM)
  else:
   mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                        match=match, instructions=inst, flags=ofproto.OFPFF_SEND_FLOW_REM)

  datapath.send_msg(mod)
  incrcounterFlowMod(1)
  
  '''lock.acquire()
  try:
   flow_list.append(new_flow)
   self.logger.info("flow created and added to the list (add_flow)")
   print "List final size:", len(flow_list)
  finally:
   lock.release()'''
  
  found = self.check_flow(new_flow)
  
  lock.acquire()
  try:
   if (found == False):
    flow_list.append(new_flow)
    #self.logger.info("flow created and added to the list")
    #print "Match: ", new_flow.match
   #print "List final size:", len(flow_list) 
  finally:
   lock.release()
   
 def caracterizar_flow(self, datapath, in_port, out_port, actions, pkt_ip, pkt_ethernet, pkt_tcp=None, buffer_id=None):

  if pkt_tcp is None:
   return

  parser = datapath.ofproto_parser

  ipv4_src = pkt_ip.src
  ipv4_dst = pkt_ip.dst

  eth_dst = pkt_ethernet.dst
  eth_src = pkt_ethernet.src

  tcp_src = pkt_tcp.src_port
  tcp_dst = pkt_tcp.dst_port
  
  match = parser.OFPMatch(in_port=in_port,
        eth_type=ether.ETH_TYPE_IP,
        ip_proto=inet.IPPROTO_TCP,
        eth_dst=eth_dst,
        ipv4_src=ipv4_src,
        ipv4_dst=ipv4_dst,
        tcp_src=tcp_src,
        tcp_dst=tcp_dst)

  '''actions = [parser.OFPActionSetField(ipv4_src=ipv4_src),     #[parser.OFPActionSetField(eth_dst=eth_dst),
       parser.OFPActionSetField(ipv4_dst=ipv4_dst),
       parser.OFPActionSetField(tcp_src=tcp_src),
       parser.OFPActionSetField(tcp_dst=tcp_dst),
       parser.OFPActionOutput(out_port)]'''
       
  if buffer_id:
   self.add_flow(datapath, 1, match, actions, pkt_ip, pkt_ethernet, pkt_tcp, IDLE_TIME, HARD_TIME, buffer_id)
  else:
   self.add_flow(datapath, 1, match, actions, pkt_ip, pkt_ethernet, pkt_tcp, IDLE_TIME, HARD_TIME)
  #self.add_flow(datapath, 1, match, actions, pkt_ip, pkt_ethernet, pkt_tcp, IDLE_TIME, HARD_TIME)
   
  return actions

 def remove_flow(self, datapath, match_del):

  #self.logger.info("into remove_flow")
  instructions = []

  ofproto = datapath.ofproto

  flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0,
               0,
               ofproto.OFPFC_DELETE,
               0,
               0,
               1,
               ofproto.OFPCML_NO_BUFFER,
               ofproto.OFPP_ANY,
               ofproto.OFPG_ANY, 0,
               match_del, instructions)

  #self.logger.info("before remove flow_mod")
  datapath.send_msg(flow_mod)
  #self.logger.info("flow removed from the controller")

 @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
 def _packet_in_handler(self, ev):
  if ev.msg.msg_len < ev.msg.total_len:
   self.logger.info("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)

  incrcounterIn(1)
  msg = ev.msg
  datapath = msg.datapath
  ofproto = datapath.ofproto
  parser = datapath.ofproto_parser
  in_port = msg.match['in_port']

  pkt = packet.Packet(msg.data)
  eth = pkt.get_protocols(ethernet.ethernet)[0]
  
  dst = eth.dst
  src = eth.src
  
  pkt_ip = pkt.get_protocol(ipv4.ipv4)
  pkt_tcp = pkt.get_protocol(tcp.tcp)
    
  dpid = datapath.id  
  self.mac_to_port.setdefault(dpid, {})

  self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
  # learn a mac address to avoid FLOOD next time.
  self.mac_to_port[dpid][src] = in_port
  
  if dst in self.mac_to_port[dpid]:
   out_port = self.mac_to_port[dpid][dst]
  else:
   out_port = ofproto.OFPP_FLOOD

  actions = [parser.OFPActionOutput(out_port)]
  
  if out_port != ofproto.OFPP_FLOOD:
   match = parser.OFPMatch(in_port=in_port,eth_dst=dst)
   if pkt_tcp is not None:
    #self.logger.info("Teste 2 - tcp packet")
    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
     incrcounterInR(1)
     self.logger.info("Existe buffer_id %s", msg.buffer_id)
     self.caracterizar_flow(datapath, in_port, out_port, actions, pkt_ip,
             eth, pkt_tcp=pkt_tcp, buffer_id = msg.buffer_id)
     return
    else:
     incrcounterInR(1)
     self.logger.info("Nao existe buffer_id")
     self.caracterizar_flow(datapath, in_port, out_port, actions, pkt_ip,
             eth, pkt_tcp=pkt_tcp)
  
  data = None
  if msg.buffer_id == ofproto.OFP_NO_BUFFER:
   print "buffer_id == OFP_NO_BUFFER"
   data = msg.data

  out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
          in_port=in_port, actions=actions, data=data)
  if out is None:
   self.logger.info("out is None")
  else:
   self.logger.info("out is not None")
  
  datapath.send_msg(out)
  #self.logger.info("after send_msg in packet in")

 @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
 def flow_removed_handler(self, ev):
  
  global flow_list
  
  msg = ev.msg
  dp = msg.datapath
  ofp = dp.ofproto

  ip_src = msg.match['ipv4_src']
  ip_dst = msg.match['ipv4_dst']

  if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
   reason = 'IDLE TIMEOUT'
  elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
   reason = 'HARD TIMEOUT'
  elif msg.reason == ofp.OFPRR_DELETE:
   reason = 'DELETE'
  elif msg.reason == ofp.OFPRR_GROUP_DELETE:
   reason = 'GROUP DELETE'
  else:
   reason = 'unknown'

  print "Deletado: ", reason
  print "Match: ", msg.match
  
  if ( (reason == 'IDLE TIMEOUT') or (reason == 'HARD TIMEOUT') ):
   self.remove_flow_list(ip_src, ip_dst)
   #print 'Deletado da lista!'

 def send_table_stats_request(self, datapath):
  ofp_parser = datapath.ofproto_parser

  req = ofp_parser.OFPTableStatsRequest(datapath, 0)
  datapath.send_msg(req)

 @set_ev_cls(ofp_event.EventOFPTableStatsReply, MAIN_DISPATCHER)
 def table_stats_reply_handler(self, ev):
  #tables = []
  
  table_id = ev.msg.body[0].table_id
  active_count = ev.msg.body[0].active_count

  self.logger.info("table_id: %d", table_id)
  self.logger.info("active_count: %d", active_count)
  
 #Recebe evento de erro
 @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
 def error_msg_handler(self, ev):
  
  global flow_list
  global pmod
  global lock
  
  msg = ev.msg
  self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x '
        'message=%s',
        msg.type, msg.code, utils.hex_array(msg.data))
  if (msg.type == 1):
   if (msg.code == 8):
    print "BUFFER UNKNOW - SATURATION ATTACK"
    incrcounterB(1)
  if (msg.type == 5):
   if (msg.code == 1):
    print "TABLE IS FULL!!!!!!!!!!!!!!"
    incrcounterF(1)
    self.flows_request_stats(msg.datapath)
    #self.send_table_stats_request(msg.datapath)
    
 def flows_request_stats(self, datapath):
  self.logger.debug('send stats request: %016x', datapath.id)
  ofproto = datapath.ofproto
  parser = datapath.ofproto_parser

  req = parser.OFPFlowStatsRequest(datapath)
  datapath.send_msg(req)

  req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
  datapath.send_msg(req)

 @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
 def _flow_stats_reply_handler(self, ev):
  body = ev.msg.body
  sorted_list = sorted([flow for flow in body if flow.priority == 1],
                     key=lambda flow: (flow.byte_count))
  ''' print sorted_list[0]
  print sorted_list[0].match['ipv4_src']
  print sorted_list[0].match['ipv4_dst']
  print sorted_list[0].match['tcp_src']
  print sorted_list[0].match['tcp_dst']'''
  self.check_pair2(sorted_list[0].match['ipv4_src'], sorted_list[0].match['ipv4_dst'],
                     sorted_list[0].match['tcp_src'], sorted_list[0].match['tcp_dst'],
                     ev.msg.datapath)
  self.remove_flow(ev.msg.datapath, sorted_list[0].match)

'''    
 def send_port_stats_request(self, datapath):
  ofp = datapath.ofproto
  ofp_parser = datapath.ofproto_parser

  req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
  datapath.send_msg(req)

 @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
 def port_stats_reply_handler(self, ev):
  ports = []
  for stat in ev.msg.body:
   ports.append('port_no=%d '
            'rx_packets=%d tx_packets=%d '
            'rx_bytes=%d tx_bytes=%d '
            'rx_dropped=%d tx_dropped=%d '
            'rx_errors=%d tx_errors=%d '
            'rx_frame_err=%d rx_over_err=%d rx_crc_err=%d '
            'collisions=%d duration_sec=%d duration_nsec=%d' %
            (stat.port_no,
            stat.rx_packets, stat.tx_packets,
            stat.rx_bytes, stat.tx_bytes,
            stat.rx_dropped, stat.tx_dropped,
            stat.rx_errors, stat.tx_errors,
            stat.rx_frame_err, stat.rx_over_err,
            stat.rx_crc_err, stat.collisions,
            stat.duration_sec, stat.duration_nsec))

  self.logger.info('PortStats: %s', ports)
'''