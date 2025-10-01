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

auth2group = dict({})
deque_group = deque()
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
      auth = radius_layer.authenticator
      if auth in auth2group:
        sess_dict = auth2group[auth]
        sess_dict["last-time"] = ftime
        sess_dict["times"].append(ftime)
      else:
        sess_dict = {
          "ip": req_ip,
          "port": req_sport,
          "radius-id": radius_id,
          "auth": auth,
          "first-time": ftime,
          "last-time": ftime,
          "times": list([ftime])
        }
        auth2group[auth] = sess_dict

      for attr in radius_layer.attributes:
        if attr.name == "Calling-Station-Id" or attr.type == 31:
          str_mac = attr.value.decode("ascii")

          if "mac" in sess_dict:
            pass # duplicated request
          else:
            sess_dict["mac"] = str_mac
            deque_group.append(sess_dict)

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

      for dic in reversed(deque_group):
        if dic["last-time"] + 10 < ftime:
          pass
        if dic["ip"] == rep_ip and dic["port"] == rep_dport and dic["radius-id"] == radius_id:
          dic["accept-time"] = ftime
          break

if args.show_counts:
  for str_mac in sorted(count_radius_request.keys()):
    print(f"mac={str_mac}, "
          f"count={count_radius_request[str_mac]["count"]}, "
          f"first={count_radius_request[str_mac]["first-date"]}, "
          f"last={count_radius_request[str_mac]["last-date"]}"
    )
elif args.show_sessions:
  for dict in deque_group:
    if "first-time" in dict and "accept-time" in dict:
      ip = dict["ip"]
      port = dict["port"]
      rid = dict["radius-id"]
      mac = dict["mac"]
      req = datetime.datetime.fromtimestamp(
        dict["first-time"] ).isoformat().split("T")[1] # .split(".")[0]
      acc = datetime.datetime.fromtimestamp(
        dict["accept-time"] ).isoformat().split("T")[1] # .split(".")[0]
      auth = dict["auth"]
      print(f"ip={ip}, "
            f"port={port}, "
            f"id={rid}, "
            f"mac={mac}, "
            f"request-time={req}, "
            f"accept-time={acc}"
            f"auth={auth.hex()}, "
      )
    else:
      ip = dict["ip"]
      port = dict["port"]
      rid = dict["radius-id"]
      mac = dict["mac"]
      req = datetime.datetime.fromtimestamp(
        dict["first-time"] ).isoformat().split("T")[1] # .split(".")[0]
      auth = dict["auth"]
      print(f"ip={ip}, "
            f"port={port}, "
            f"id={rid}, "
            f"mac={mac}, "
            f"request-time={req}, "
            f"accept-time=<NO_REPLY>"
            f"auth={auth.hex()}, "
      )
      for dup_time in dict["times"]:
        dt = datetime.datetime.fromtimestamp( dup_time ).isoformat().split("T")[1] # .split(".")[0]
        print(f"\t{dt}")
