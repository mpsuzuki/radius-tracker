# radius-tracker.py

A Python script to parse a packet capture file
(by wireshark or tcpdump), and track the transactions
of RADIUS Access-Request and Access-Accept.

## Prerequisite

Python scapy. I use 2.6.1, it has builtin parser for RADIUS.

## Usage

### count requests for each MAC address
```
$ ./radius-tracker.py --show-counts xxx.pcap

mac=6C-4B-90-4F-C7-2C, count=24, first=10:00:59, last=11:19:38
mac=6C-4B-90-4F-C7-D2, count=87, first=10:05:56, last=11:19:29
mac=6C-4B-90-4F-C8-08, count=24, first=10:05:26, last=11:19:47
mac=6C-4B-90-4F-C8-32, count=15, first=10:05:46, last=11:00:22
mac=6C-4B-90-4F-C8-C6, count=15, first=10:26:31, last=11:04:56
mac=6C-4B-90-4F-C9-8A, count=78, first=10:05:05, last=11:19:32
mac=6C-4B-90-4F-CA-1E, count=15, first=10:05:10, last=10:59:43
mac=6C-4B-90-4F-CA-27, count=15, first=10:06:10, last=10:59:50
mac=6C-4B-90-4F-CB-27, count=15, first=10:05:08, last=10:59:24
mac=6C-4B-90-4F-CB-CB, count=18, first=10:00:58, last=11:00:09
```
For MAC address 6C-4B-90-4F-C7-D2, 87 requests are sent
during 74 minutes. This mode does not count the number
of Accept or Reject packets.

### transaction status (default timeout is set to 10 sec)
```
$ ./radius-tracker.py --show-transaction xxx.cap

ip=10.12.0.11, port=1812, id=142, mac=6C-4B-90-4F-C7-D2, request=11:19:23.807725, accept=11:19:31.873647, num-reqs=6, auth=c52a3fee,
ip=10.12.0.11, port=1812, id=144, mac=6C-4B-90-4F-C7-2C, request=11:19:32.808165, accept=11:19:40.872447, num-reqs=6, auth=dfe7d9ed,
ip=10.12.0.11, port=1812, id=145, mac=6C-4B-90-4F-CC-1F, request=11:19:35.808104, accept=11:19:43.873816, num-reqs=6, auth=a8893fb0,
ip=10.12.0.11, port=1812, id=146, mac=6C-4B-90-4F-C8-08, request=11:19:42.808492, accept=11:19:50.874953, num-reqs=6, auth=51bfbaa4,
```
For each MAC address, 6 request packets are sent,
and the reply appears 8 seconds after the first request.

Authenticators are shorten to their first 32-bit.
