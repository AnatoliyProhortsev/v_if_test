# Test project: Linux module for virtual ping interface
Autor: Prohorcev Anatoliy

## Functionality:
- Set IPv4 with proc file
- Get current IPv4 from proc file
- Response for ARP requests
- Response for ICMP requests

## Project structure
- vnet_ping.c - kernel module
- Makefile - build script
- README.md - this file

## Defaults
- IPv4: 10.0.0.2
- Proc entry: /proc/vnet_ping0
- Interface name: vnet_ping0

## Build (in source directory)
```bash
make
```
### Output:
```
vnet_ping.ko
```

## Load module
```bash
sudo insmod vnet_ping.ko
```
Note: on systems with Secure Boot enabled, loading unsigned kernel modules may fail
### Check that interface exists
```bash
ip link show vnet_ping0
```
### Set interface up
```bash
sudo ip link set vnet_ping0 up
```

## Configure IPv4
```bash
echo {your_ip} > /proc/vnet_ping0
```
### Read current IPv4
```bash
cat /proc/vnet_ping0
```

## Testing
### Add route to interface
```bash
sudo ip route add $(cat /proc/vnet_ping0) dev vnet_ping0
```
### In other console: start monitoring ARP traffic
```bash
sudo tcpdump -ni vnet_ping0 -e arp
```
### In other console: view kernel logs
```bash
sudo dmesg -w
```
### Start ping
```bash
ping $(cat /proc/vnet_ping0)
```
### If succeed:
```bash
~/dev/v_if_test$ ping 10.0.0.2
PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.
64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=0.066 ms
64 bytes from 10.0.0.2: icmp_seq=4 ttl=64 time=0.035 ms
64 bytes from 10.0.0.2: icmp_seq=5 ttl=64 time=0.046 ms
```
dmesg output:
```
[12879.282404] vnet_ping created {vnet_ping0}
[12879.282410] proc created {vnet_ping_ipv4}
[12879.290194] vnet_ping0: opened
... (broadcast likely) ...
[12896.636203] vnet_ping0: ARP request who-has 10.0.0.2 from 192.168.0.9
[12896.636214] vnet_ping0: ip proto=1 src=192.168.0.9 dst=10.0.0.2 myip=10.0.0.2
[12896.636217] vnet_ping0: dst matches my ip 10.0.0.2
[12896.636218] vnet_ping0: icmp path src=192.168.0.9 dst=10.0.0.2 type=8 myip=10.0.0.2
[12896.636220] vnet_ping0: ICMP_ECHO detected
[12896.636221] vnet_ping0 sending ping response for 192.168.0.9
```

## Deinit
```bash
sudo rmmod vnet_ping
```


