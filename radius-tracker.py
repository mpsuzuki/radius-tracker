#!/usr/bin/env python

import re
import os
import sys
import argparse
import datetime

from collections import deque

parser = argparse.ArgumentParser(description = "Extract MAC address from RADIUS request")
parser.add_argument("--timeout", "-T",
                    type = int, default = 10,
                    help = "Timeout (sec) since last request (default 10)")
parser.add_argument("--show-counts", "--show-count", "--show-stats", "--show-stat",
                    action = "store_true",
                    help = "Show count")
parser.add_argument("--show-transactions", "--show-transaction", "--show-txn",
                    action = "store_true",
                    help = "Show transactions")
parser.add_argument("--show-all-times",
                    action = "store_true",
                    help = "Show all times of request packets")
parser.add_argument("--omit-ip", "--no-ip",
                    action = "store_true",
                    help = "Do not show src IP address")
parser.add_argument("--omit-port", "--no-port",
                    action = "store_true",
                    help = "Do not show src UDP port")
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
      client_ip = radius_ip.src
      client_port = radius_udp.sport
      server_ip = radius_ip.dst
      server_port = radius_udp.dport
      auth = radius_layer.authenticator
      if auth in auth2group:
        txn_dict = auth2group[auth]
        txn_dict["last-time"] = ftime
        txn_dict["times"].append(ftime)
      else:
        txn_dict = {
          "client-ip": client_ip,
          "client-port": client_port,
          "server-ip": server_ip,
          "server-port": server_port,
          "radius-id": radius_id,
          "auth": auth,
          "first-time": ftime,
          "last-time": ftime,
          "times": list([ftime])
        }
        auth2group[auth] = txn_dict

      for attr in radius_layer.attributes:
        if attr.name == "Calling-Station-Id" or attr.type == 31:
          str_mac = attr.value.decode("ascii")

          if "mac" in txn_dict:
            pass # duplicated request
          else:
            txn_dict["mac"] = str_mac
            deque_group.append(txn_dict)

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
      server_ip = radius_ip.src
      server_port = radius_udp.sport
      client_ip = radius_ip.dst
      client_port = radius_udp.dport

      for dic in reversed(deque_group):
        if dic["last-time"] + args.timeout < ftime:
          pass
        elif dic["client-ip"] != client_ip:
          pass
        elif dic["client-port"] != client_port:
          pass
        elif dic["radius-id"] == radius_id:
          dic["accept-time"] = ftime
          break

if args.show_counts:
  for str_mac in sorted(count_radius_request.keys()):
    print(f"mac={str_mac}, "
          f"count={count_radius_request[str_mac]["count"]}, "
          f"first={count_radius_request[str_mac]["first-date"]}, "
          f"last={count_radius_request[str_mac]["last-date"]}"
    )
elif args.show_transactions:
  for dict in deque_group:
    if args.show_all_times:
      req_cnts = ""
    else:
      len_times = len(dict["times"])
      req_cnts = f"num-reqs={len_times}, "

    if "first-time" in dict and "accept-time" in dict:
      ip = dict["server-ip"]
      port = dict["server-port"]
      rid = dict["radius-id"]
      mac = dict["mac"]
      req = datetime.datetime.fromtimestamp(
        dict["first-time"] ).isoformat().split("T")[1] # .split(".")[0]
      acc = datetime.datetime.fromtimestamp(
        dict["accept-time"] ).isoformat().split("T")[1] # .split(".")[0]
      auth = dict["auth"]

      if args.omit_ip:
        prefix = ""
      else:
        prefix = f"ip={ip}, "
      if not args.omit_port:
        prefix += f"port={port}, "

      print(f"{prefix}"
            f"id={rid}, "
            f"mac={mac}, "
            f"request={req}, "
            f"accept={acc}, "
            f"{req_cnts}"
            f"auth={auth.hex()[0:8]}, "
      )
    else:
      ip = dict["server-ip"]
      port = dict["server-port"]
      rid = dict["radius-id"]
      mac = dict["mac"]
      req = datetime.datetime.fromtimestamp(
        dict["first-time"] ).isoformat().split("T")[1] # .split(".")[0]
      auth = dict["auth"]

      if args.omit_ip:
        prefix = ""
      else:
        prefix = f"ip={ip}, "
      if not args.omit_port:
        prefix += f"port={port}, "

      print(f"{prefix}"
            f"id={rid}, "
            f"mac={mac}, "
            f"request={req}, "
            # f"accept=<NO_REPLY_WITHIN_{args.timeout}_SEC>, "
            f"accept=<NO_REPLY>, "
            f"{req_cnts}"
            f"auth={auth.hex()[0:8]}, "
      )
    if args.show_all_times:
      for dup_time in dict["times"]:
        dt = datetime.datetime.fromtimestamp( dup_time ).isoformat().split("T")[1] # .split(".")[0]
        print(f"\t{dt}")
