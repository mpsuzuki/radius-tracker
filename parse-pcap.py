#!/usr/bin/env python

import re
import os
import sys
import argparse
import datetime

from collections import deque

parser = argparse.ArgumentParser(description = "Extract MAC address from RADIUS request")
parser.add_argument("--show-counts", "--show-count", "--show-stats", "--show-stat",
                    action = "store_true",
                    help = "Show count")
parser.add_argument("--show-sessions", "--show-session", "--show-sess",
                    action = "store_true",
                    help = "Show sessions")
parser.add_argument("pcap_file", help = "Path to the PCAP file")
args = parser.parse_args()



from scapy.all import rdpcap, load_contrib
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP
from scapy.layers.radius import Radius

# read pcap file
packets = rdpcap(args.pcap_file)

deque_session = deque()
count_radius_request = dict()

for pkt in packets:
  if pkt.haslayer(UDP) and pkt.haslayer(Radius):
    radius_layer = pkt[Radius]
    radius_ip = pkt["IP"]
    radius_udp = pkt[UDP]
    radius_id = radius_layer.id

    ftime = float(pkt.time)
    str_datetime = datetime.datetime.fromtimestamp(ftime).isoformat().split("T")[1].split(".")[0]

    # Access-Request has .code == 1 attribute
    if radius_layer.code == 1:
      req_ip = radius_ip.src
      req_sport = radius_udp.sport
      sess_dict = { "ip": req_ip, "port": req_sport, "radius-id": radius_id, "ftime-request": ftime }
      sess_dict["auth"] = radius_layer.authenticator.hex()

      for attr in radius_layer.attributes:
        if attr.name == "Calling-Station-Id" or attr.type == 31:
          str_mac = attr.value.decode("ascii")

          sess_dict["mac"] = str_mac
          deque_session.append(sess_dict)

          if str_mac in count_radius_request:
            count_radius_request[str_mac]["count"] += 1
            count_radius_request[str_mac]["last-date"] = str_datetime
          else:
            count_radius_request[str_mac] = dict({})
            count_radius_request[str_mac]["count"] = 1
            count_radius_request[str_mac]["first-date"] = str_datetime
            count_radius_request[str_mac]["last-date"] = str_datetime

    # Access-Accept has .code == 1 attribute
    elif radius_layer.code == 2:
      rep_ip = radius_ip.dst
      rep_dport = radius_udp.dport

      for dic in reversed(deque_session):
        if dic["ftime-request"] + 10 < ftime:
          break
        if dic["ip"] == rep_ip and dic["port"] == rep_dport and dic["radius-id"] == radius_id:
          dic["ftime-accept"] = ftime
          break

if args.show_counts:
  for str_mac in sorted(count_radius_request.keys()):
    print(f"mac={str_mac}, "
          f"count={count_radius_request[str_mac]["count"]}, "
          f"first={count_radius_request[str_mac]["first-date"]}, "
          f"last={count_radius_request[str_mac]["last-date"]}"
    )
elif args.show_sessions:
  for dict in deque_session:
    if "ftime-request" in dict and "ftime-accept" in dict:
      ip = dict["ip"]
      port = dict["port"]
      rid = dict["radius-id"]
      mac = dict["mac"]
      req = datetime.datetime.fromtimestamp(
        dict["ftime-request"] ).isoformat().split("T")[1] # .split(".")[0]
      acc = datetime.datetime.fromtimestamp(
        dict["ftime-accept"] ).isoformat().split("T")[1] # .split(".")[0]
      auth = dict["auth"]
      print(f"ip={ip}, "
            f"port={port}, "
            f"id={rid}, "
            f"mac={mac}, "
            f"auth={auth}, "
            f"request-time={req}, "
            f"accept-time={acc}"
      )
    elif "ftime-request" in dict:
      ip = dict["ip"]
      port = dict["port"]
      rid = dict["radius-id"]
      mac = dict["mac"]
      req = datetime.datetime.fromtimestamp(
        dict["ftime-request"] ).isoformat().split("T")[1] # .split(".")[0]
      auth = dict["auth"]
      print(f"ip={ip}, "
            f"port={port}, "
            f"id={rid}, "
            f"mac={mac}, "
            f"auth={auth}, "
            f"request-time={req}, "
            f"accept-time=<NO_REPLY>"
      )
