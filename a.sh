sudo ip link set enp2s0 up
sudo ip link set enp3s0 up

sudo rmmod bridge
sudo insmod bridge.ko

sudo brctl addbr br0
sudo brctl addif br0 enp2s0
sudo brctl addif br0 enp3s0

sudo ip link set br0 up

