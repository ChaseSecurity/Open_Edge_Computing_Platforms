time_interval=10 #Record every 10 seconds.
num=$((86400/${time_interval}))
currDate=$(date +"%m%d")
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

stat_dir=$2/stat_files/${currDate}
if [ ! -d $stat_dir ]; then
    mkdir -p $stat_dir
fi

for (( i = 0; i < ${num}; i++ )); do
	currDate=$(date +"%m%d")
	currHour=$(date +"%H")
	docker stats ${node_name} --no-stream --format "{{ json . }}" >> ${stat_dir}/${currDate}_${currHour}.log
	sleep ${time_interval}
done
