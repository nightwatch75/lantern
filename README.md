<p align="center"><img src="logo.svg" width="120" alt="LANtern logo"></p>
<h1 align="center">LANtern</h1>
<p align="center">The radar for your LAN: a small device inventory with live availability.<br>
Python standard library only. No login, no cloud, one SQLite file.</p>

<p align="center">
  <img src="docs/screenshot-light.png" width="48%" alt="Light theme">
  <img src="docs/screenshot-dark.png" width="48%" alt="Dark theme">
</p>

## What it does

- First start: LANtern discovers the devices on its own (ping sweep + ARP). The **Discover** button repeats it and adds only the new ones.
- Inventory of every device by MAC: name, IP, vendor, notes, category.
- Live status: online, offline, or "MAC differs" when an IP answers with another MAC. Auto-refresh every 30 s, with a pause button.
- IP assignment per device: dynamic, DHCP reservation, or fixed on the device.
- Port scan, per device or for all online devices. Separate from the refresh.
- Editable categories (name, icon, icon color) and filters, sort by type.
- Recognition: vendor from the MAC prefix (IEEE OUI database, updatable in one click, registry URLs editable), category from editable rules. LANtern suggests, you confirm.
- CSV and Excel export. Import from a CSV (LANtern's own export works as a backup) or an nmap XML (`nmap -sn -oX`). Known MACs are never overwritten.
- Light and dark theme, font size, Italian and English (flag in the top bar).

## Run

```
python3 app.py [options]
```

Open `http://127.0.0.1:8099`. Run it on a machine inside the LAN you want to watch.

Needs Python 3. `nmap` is optional (port scan only). Linux uses `ping` and `ip`. Windows uses `ping` and `arp`, both built in: use `py app.py`. **Windows support is experimental and untested on real hardware.**

## Options

| Option | Default | Meaning |
|---|---|---|
| `-p`, `--port PORT` (or just `PORT`) | `8099` | HTTP port |
| `--host ADDRESS` | `127.0.0.1` | Listen address. Anything else prints a warning: there is no login |
| `--db FILE` (or env `LANTERN_DB`) | `devices.db` next to `app.py` | SQLite file |
| `--subnet CIDR` | detected | Subnet to sweep, repeatable, `/22` at most. Use it when detection picks the wrong network (VPN, several adapters) |
| `--no-discover` | off | Skip the discovery on first start (the Discover button still works) |
| `--version` | | Print the version |
| `seed.local.json` | none | Optional automatic import on first start, JSON: `[[name, ip, mac, vendor, type, notes, reserved], ...]`, `reserved` = 0 dynamic, 1 reservation, 2 fixed |

The database starts empty and fills itself with a discovery on first start. `seed.local.json` is only needed to import data you already have.

## Security

LANtern listens on `127.0.0.1` only and has no authentication. Do not expose it to the internet.

## License

MIT
