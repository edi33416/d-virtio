#!/bin/sh
module_path=virtio_net_tmp.ko
vm_ip=172.213.0.2/24
host_ip=172.213.0.1

insmod $module_path
ip a a $vm_ip dev eth0 > /dev/null 2>&1
ip l set eth0 up > /dev/null 2>&1
ping -c 3 $host_ip
ip route add default via 172.213.0.1
echo "nameserver 8.8.8.8 8.8.4.4" > /etc/resolv.conf
ping -c 3 google.com
echo "279be1aeba9eb6f9293e50d394727867  -" > ref
wget -O - http://swarm.cs.pub.ro/index.html | tee index.html | md5sum > out
cmp -s ref out && echo '### SUCCESS: Files Are Identical! ###' || echo '### WARN'
rm ref out index.html
rmmod $module_path
