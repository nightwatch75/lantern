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
- Live status: online, offline, or "MAC differs" when an IP answers with another MAC.
- IP assignment per device: dynamic, DHCP reservation, or fixed on the device.
- Port scan, per device or for all online devices. Separate from the refresh.
- Editable categories (name, icon, icon color) and filters, sort by type.
- Recognition: vendor from the MAC prefix (IEEE OUI database, updatable in one click), category from editable rules. LANtern suggests, you confirm.
- CSV and Excel export.
- Light and dark theme, font size, Italian and English (flag in the top bar).

## Run

```
python3 app.py [port]
```

Open `http://127.0.0.1:8099`. Run it on a machine inside the LAN you want to watch.

Needs Python 3. `nmap` is optional (port scan only). Uses `ping` and `ip neigh`, so Linux. Discovery sweeps the local subnets (at most a /22 each, container and VPN interfaces skipped) and sees only the devices that answer ping or ARP.

## Options

| Option | Default | Meaning |
|---|---|---|
| `port` (argument) | `8099` | HTTP port |
| `LANTERN_DB` (env) | `devices.db` next to `app.py` | SQLite file |
| `seed.local.json` | none | Optional first-run import: `[[name, ip, mac, vendor, type, notes, reserved], ...]`, `reserved` = 0 dynamic, 1 reservation, 2 fixed |

The database starts empty and fills itself with a discovery on first start. `seed.local.json` is only needed to import data you already have.

## Security

LANtern listens on `127.0.0.1` only and has no authentication. Do not expose it to the internet.

## License

MIT
