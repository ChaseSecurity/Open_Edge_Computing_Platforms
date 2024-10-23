#!/bin/bash
currDate=$(date +"%Y%m%d")
node_name="wxedge"
logs_dir=$1/tcpdump/${currDate}/${node_name}/logs_files

if [ ! -d $logs_dir ]; then
  mkdir -p $logs_dir
fi
if [ -f ${logs_dir}/logList.txt ]; then
	rm ${logs_dir}/logList.txt
fi

docker exec wxedge ls /tmp/ | grep "log" > ${logs_dir}/logList.txt

while read log_name || [ -n "${log_name}" ];
do
  file_name=$(docker exec wxedge cat /tmp/${log_name} | head -n 1 | awk '{print $1}' | sed 's/^.*2022-//g' | sed 's/+08.*$//g')_$(docker exec wxedge cat /tmp/${log_name} | tail -n 1 | awk '{print $1}' | sed 's/^.*T//g' | sed 's/+08.*$//g')
  docker exec wxedge cat /tmp/${log_name} > ${logs_dir}/${file_name}"_"${log_name}
  echo "$currDate $(date +"%H%M") save log files $file_name _ $log_name" >>${logs_dir}/logs
done < ${logs_dir}/logList.txt
