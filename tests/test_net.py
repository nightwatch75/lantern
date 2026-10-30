"""Self-check for the OS output parsers: python3 tests/test_net.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import app

win = """
Interface: 192.0.2.61 --- 0x5
  Internet Address      Physical Address      Type
  192.0.2.254         00-11-22-33-44-55     dynamic
  192.0.2.70          00-11-22-33-44-66     dinamico
  192.0.2.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""
assert app.parse_arp(win) == {"192.0.2.254": ("00:11:22:33:44:55", ""), "192.0.2.70": ("00:11:22:33:44:66", "")}
linux = "192.0.2.254 dev wlan0 lladdr 00:11:22:33:44:55 REACHABLE\nfe80::1 dev wlan0 lladdr 00:11:22:33:44:55 router STALE\n192.0.2.9 dev wlan0  FAILED\n"
assert app.parse_neigh(linux) == {"192.0.2.254": ("00:11:22:33:44:55", "REACHABLE")}
app.SUBNETS[:] = ["192.0.2.0/24"]
assert [str(n) for n in app.local_nets()[0]] == ["192.0.2.0/24"]
print("ok")
