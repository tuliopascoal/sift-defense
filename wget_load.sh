#!/bin/bash

# SCRIPT:  wload.sh

# PURPOSE: Load testing with wget.

if [[ $# < 1 ]]; then
        echo "Usage: wload #processes(eg. 1000)"
        exit
fi

#SECONDS=0
tst=$(date +%s%N)
failures=0

for ((i=1; i<=$1; i++))
do
  ts=$(date +%s%N)
  #wget -o /dev/null -q -O /dev/null -i 192.168.1.100
  wget -q -O /dev/null --tries=1 --timeout=5 192.168.1.100 &
  wait
  ttm=$((($(date +%s%N) - $ts)/1000000))
  echo "Response to client $i lasted $ttm milliseconds"
  if [ "$ttm" -ge 1000 ]; then
  	((failures++))
  fi
done
wait

ttmt=$((($(date +%s%N) - $tst)/1000000))
#echo "It took $SECONDS seconds and $ttmt milliseconds seconds"
printf "%s " `hostname` had $1 tries with $failures failures and lasted a total of $ttmt milliseconds.
#printf $failures
