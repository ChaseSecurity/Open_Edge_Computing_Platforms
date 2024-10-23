#!/bin/bash
# Open forwarding.
echo "net.ipv4.ip_forward=1">>/etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1">>/etc/sysctl.conf

# Download miniupnpd.
apt-get install unzip -y
unzip miniupnpd.zip
cd miniupnpd
apt-get install iptables-dev libiptc-dev libssl-dev pkg-config -y
bash netfilter/iptables_init.sh
./configure
make
make install

# Configure miniupnpd.
bash /etc/miniupnpd/miniupnpd_functions.sh
bash /etc/miniupnpd/ip6tables_init.sh
bash /etc/miniupnpd/iptables_init.sh

echo "ext_ifname=eth0">>miniupnpd.conf
echo "ext_ip="$1>>miniupnpd.conf
echo "listening_ip=docker0">>miniupnpd.conf
echo "enable_natpmp=yes">>miniupnpd.conf
echo "enable_upnp=yes">>miniupnpd.conf
# Change network_ip to your listening ips.
network_ip=172.17.0.0/24
echo "allow 1024-65535 $network_ip 1024-65535">>miniupnpd.conf

/etc/init.d/miniupnpd start
iptables -t nat -vnL
