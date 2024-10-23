#!/bin/bash
#Run when start a new server.

#Update.
sudo apt-get update -y
sudo apt-get upgrade -y

if [ -n $2 ]; then
  root_dir=$2
else
  echo "Second argument path required. Example: bash ./run.sh wxedge /EC"
  exit 0
fi

#Install docker.
curl -sSL https://get.daocloud.io/docker | sh
#curl -L https://get.daocloud.io/docker/compose/releases/download/1.25.4/docker-compose-`uname -s`-`uname -m` > /usr/local/bin/docker-compose

if [ $1 = "wxedge" ]; then
  if [ -z $3 ]; then
    docker pull onething1/wxedge
    docker run -d --name=wxedge --restart=always --privileged --net=host --tmpfs /run --tmpfs /tmp -v ${root_dir}/docker_space/wxedge/containers:/storage:rw  onething1/wxedge
  else
    echo "Go to the file requirements.sh to open the miniupnp setting."
    # echo "start upnp setting for public IP address."
    # bash config_miniupnp.sh $3
  fi
elif [ $1 = "tiptime" ]; then
  docker pull registry.cn-hangzhou.aliyuncs.com/tiptime/ttnode:latest
  docker run -d --name=ttnode --restart=always --privileged --net=host -v ${root_dir}/docker_space/tiptime/mnt/mmcblk0p1:/mnt/data/ttnode  -v /var/run/docker.sock:/var/run/docker.sock -v /proc:/host/proc:ro registry.cn-hangzhou.aliyuncs.com/tiptime/ttnode:latest
else
  echo "Argument wxedge or tiptime required. Example: bash ./run.sh wxedge /EC"
  exit 0
fi


