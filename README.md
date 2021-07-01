# Netiny
Netiny is a basic network capture tool.
Written in **Python3.9** with raw sockets, it allows **low-level management of network protocols**.

Netiny is easily modifiable, so as to allow any implementation of network protocols.
For the moment the supported protocols are the following:

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
