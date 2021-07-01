# Netiny
Netiny is a basic network capture tool.<br>
Written in **Python3.9** with raw sockets, it allows **low-level management of network protocols**.<br>
<br>
Netiny is easily modifiable, so as to allow any implementation of network protocols.<br>
For the moment the supported protocols are the following:<br>
<br>
**Ethernet**
```python
{
  0x800: "IPv4",
  0x806: "ARP",
  0x8035: "RARP",
  0x86dd: "IPv6",
}
```

**IPv4**
```python
{
  0x11: "UDP",
  0x6: "TCP",
  0x1: "ICMP",
  0x29: "IPv6",
}
```

## Sample output
![example](https://user-images.githubusercontent.com/78198739/124131363-03d6a600-da80-11eb-9f13-25259eef09f4.png)
