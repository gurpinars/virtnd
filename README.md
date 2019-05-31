# virtnd
Virtual Network Device built on top of linux TAP device

### Prerequisites
+ [CMake](http://www.cmake.org "CMake project page") (>= 3.9)
+ [GCC](http://gcc.gnu.org "GCC home") (>= 7.2.0)

### Building
```bash
cd build
./builder.sh
```
### Getting Started
```bash 
>> sudo ./virtnd
```
Now you can ping the device
```bash 
>>  ping -c 4 10.0.0.1
PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.266 ms
64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=0.199 ms
64 bytes from 10.0.0.1: icmp_seq=3 ttl=64 time=0.193 ms
64 bytes from 10.0.0.1: icmp_seq=4 ttl=64 time=0.101 ms

--- 10.0.0.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3045ms
rtt min/avg/max/mdev = 0.101/0.189/0.266/0.061 ms

```



TODO: UDP,TCP
