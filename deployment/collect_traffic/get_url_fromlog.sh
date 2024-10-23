#!/bin/bash
currDate=$(date +"%Y%m%d")
node_name="wxedge"
dir_name="bae5a079ee6d7ac69ea2ac8cec142662_0"
logs_dir=$1/tcpdump/${currDate}/${node_name}/logs_files
root_dir=$1

if [ ! -d ${logs_dir}/serverlog ]; then
    mkdir -p ${logs_dir}/serverlog
fi

if [ -f ${logs_dir}/serverlog/serverLogList.txt ]; then
	rm ${logs_dir}/serverlog/serverLogList.txt
fi
if [ -f ${logs_dir}/serverlog/urlList.txt ]; then
	rm ${logs_dir}/serverlog/urlList.txt
fi

# Fetch server.log.
ls ${root_dir}/docker_space/wxedge/containers/.onething_data/task/${dir_name}/logs/ > serverLogList.txt

while read log_name || [ -n "${log_name}" ];
do
	cp ${root_dir}/docker_space/wxedge/containers/.onething_data/task/${dir_name}/logs/${log_name} ${logs_dir}/serverlog/${log_name}
	echo "Save ${log_name}"
	# Save links from each log files.
	cat ${root_dir}/docker_space/wxedge/containers/.onething_data/task/${dir_name}/logs/${log_name} | grep "\[DPM\]\[PeerTask" | sed "s/^.*\[DPM\]\[PeerTask//g" | sed "s/\]\ Download.*$//g" > ${logs_dir}/serverlog/urlList.txt
done < serverLogList.txt
echo "$currDate $(date +"%H%M") save server files" >> ${logs_dir}/logs
echo "Got urls in urlList.txt"
rm serverLogList.txt
