#!/bin/bash

time_interval=3600
timeout_interval=86400
currDate=$(date +"%Y%m%d")
# Enable the backup, and set up $your_public_ip into your OECP node ip.
enable_backup="disable"
# your_public_ip=""

if [ -n $1 ]; then
  node_name=$1
else
  echo "Argument wxedge or tiptime required. Example: bash ./run.sh wxedge /EC"
  exit 0
fi

if [ -n $2 ]; then
  root_dir=$2
else
  echo "Second argument path required. Example: bash ./run.sh wxedge /EC"
  exit 0
fi

logs_dir=${root_dir}/tcpdump/${currDate}/${node_name}/logs_files
pcap_dir=${root_dir}/tcpdump/${currDate}/${node_name}/pcap_files

if [ ! -d $pcap_dir ]; then
    mkdir -p $pcap_dir
fi
if [ ! -d $logs_dir ]; then
    mkdir -p $logs_dir
fi

echo "$node_name start tcpdump $currDate $(date +"%H%M")" >>${logs_dir}/logs

if [ $enable_backup = "enable" ]; then
  timeout $timeout_interval tcpdump -i any "(not host $your_public_ip)" -G $time_interval -s0 -Z root -w ${pcap_dir}/%m%d_%H%M.pcap >>${logs_dir}/logs &
fi

