#!/bin/bash

# SCRIPT:  cpu_mem_log.sh

# PURPOSE: Get cpu and memory consumption of python ryu controller.

echo "t(s) mem(Kb) CPU(%)" > cpu_mem.txt
t=0

while true; do

 #ovs-ofctl -O OpenFlow13 dump-tables s1 | head -3 >> active_count.txt
 #echo "1 secs" >> cpu_mem.txt
 psres1=``;
 psres2=;
 echo "$t $psres" >> cpu_mem.txt;
 sleep 1;
 ((t++))
 done

