#!/bin/bash
root_dir=$1
remote_server_file=$2
backup_date=$3
currDate=$(date +"%Y%m%d")
base_result_dir=~/backup/
src_dir_to_sync=${root_dir}/tcpdump/${backup_date}/
cache_dir=${root_dir}/docker_space/

if [ $backup_date = $currDate ]; then
  echo "Tcpdump of the day hasn't finished!"
  exit 0
fi

while read server || [ -n "$server" ];
do
    echo "Backup server $server"
    if [ ! -d ${base_result_dir}/${server}/tcpdump ];then
      mkdir -p ${base_result_dir}/${server}/tcpdump
    fi
    backup_dir=${base_result_dir}/${server}/tcpdump/${backup_date}/
    echo "$currDate rsync -azvv --remove-source-files --exclude $currDate -e \'ssh -i ~/.ssh/id_rsa\' root@${server}:${src_dir_to_sync} $backup_dir" >> ${base_result_dir}/logs
    # --remove-source-files Delete the files on OECP nodes.
    rsync -azvv --remove-source-files --exclude $currDate -e 'ssh -i ~/.ssh/id_rsa' root@${server}:${src_dir_to_sync} $backup_dir
    if [[ ! -d $backup_dir ]];then
        echo "Backup dir $backup_dir doesn't exit, skip freeing up the original dir"
        continue
    fi
    du -hs $backup_dir
    echo "ssh -n -i ~/.ssh/id_rsa root@$server \"find ${src_dir_to_sync} -type d -empty -delete\""
    # -n prevents ssh from reading the stdin
    ssh -n -i ~/.ssh/id_rsa root@$server "find ${src_dir_to_sync} -type d -empty -delete"

    echo "Backup cache of $server"
    backup_dir=${base_result_dir}/${server}/caches
    echo "$currDate rsync -azvv -e \'ssh -i ~/.ssh/id_rsa\' root@${server}:${cache_dir} $backup_dir" >> ${base_result_dir}/logs
    rsync -azvv -e 'ssh -i ~/.ssh/id_rsa' root@${server}:${cache_dir} $backup_dir
done < $remote_server_file
exit 0

