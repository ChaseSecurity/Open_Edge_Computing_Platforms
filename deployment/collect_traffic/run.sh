#!/bin/bash

#Run when start a new server.
#This script will initialize a new docker for the chosen OECP.
bash requirments.sh $1 $2 $3

#Tcpdump starts.
bash tcpdump.sh $1 $2

#Recording stat starts.
bash get_stat.sh $1 $2

#Record log of wxedge.
if [ $1 = "wxedge" ]; then
  if [ -n $2 ]; then
    bash record_log.sh $2
    #Get url from server log.
    bash get_url_fromlog.sh $2
  else
    echo "Second argument path required. Example: bash ./run.sh wxedge /EC"
    exit 0
  fi
fi
