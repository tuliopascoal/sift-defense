#!/bin/bash

# SCRIPT:  active_count2.sh

# PURPOSE: Get active_count from switch´s table flow every 1 seconds.

echo " " > activecount_log.txt
echo "t(s) active_count" > activecount_log.txt
t=0

#1060
while true; do
 
 #ovs-ofctl -O OpenFlow13 dump-tables s1 | head -3 >> active_count2.txt
 #echo "1 sec" >> active_count2.txt
 psres=`ovs-ofctl -O OpenFlow13 dump-tables s1 | head -3 | tail -n 1 | sed "s/.*active=\([0-9]*\).*/\\1/g"`;
 echo "$t $psres" >> activecount_log.txt;
 sleep 1;
 ((t++))
 #done
done
