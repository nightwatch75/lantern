"""Self-check for the OS output parsers: python3 test_net.py"""
import app

win = """
Interface: 192.168.1.61 --- 0x5
  Internet Address      Physical Address      Type
  192.168.1.254         e4-4e-12-7f-c9-9b     dynamic
  192.168.1.70          40-2F-86-B3-C0-E2     dinamico
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""
assert app.parse_arp(win) == {"192.168.1.254": ("e4:4e:12:7f:c9:9b", ""), "192.168.1.70": ("40:2f:86:b3:c0:e2", "")}
linux = "192.168.1.254 dev wlan0 lladdr e4:4e:12:7f:c9:9b REACHABLE\nfe80::1 dev wlan0 lladdr e4:4e:12:7f:c9:9b router STALE\n192.168.1.9 dev wlan0  FAILED\n"
assert app.parse_neigh(linux) == {"192.168.1.254": ("e4:4e:12:7f:c9:9b", "REACHABLE")}
app.SUBNETS[:] = ["192.168.1.0/24"]
assert [str(n) for n in app.local_nets()[0]] == ["192.168.1.0/24"]
print("ok")
