<p align="center"><img src="logo.svg" width="120" alt="LANtern logo"></p>
<h1 align="center">LANtern</h1>
<p align="center">The radar for your LAN: a small device inventory with live availability.<br>
Python standard library only. Optional login, no cloud, one SQLite file.</p>

<p align="center">
  <img src="docs/screenshot-light.png" width="32%" alt="Classic Light">
  <img src="docs/screenshot-dark.png" width="32%" alt="Classic Dark">
  <img src="docs/screenshot-themes.png" width="32%" alt="Theme menu">
</p>

## What it does

- First start: LANtern discovers the devices on its own (ping sweep + ARP), with a lantern animation while it runs. The **Discover** button repeats it and adds only the new ones.
- Inventory of every device by MAC: name, IP, vendor, notes, category.
- Live status: online, offline, or "MAC differs" when an IP answers with another MAC. Auto-refresh every 30 s, with a pause button.
- IP assignment per device: dynamic, DHCP reservation, or fixed on the device.
- Port scan, per device or for all online devices. Separate from the refresh. The list of ports to check is editable (ranges allowed, `22,80,8000-8100`), with one click back to the known ports. A compact view replaces the ports with an icon (or `-`).
- Backups from the web UI: create, add a note, download, import a file, restore. History in a `backups/` folder next to the database (so a Docker volume keeps it). A restore first saves an automatic backup. The login user is never in a backup, and a restore keeps it.
- Editable categories (name, icon, icon color), each with its own default color so they differ at a glance. A device can have its own icon and color that win over the category ones. A checkbox applies category, icon and color to every device of the same producer (by MAC prefix, e.g. all Espressif). Color picker with a standard palette. Filters, sort by type.
- Identification, step by step. **Discover** also listens to mDNS and SSDP and reads host names, so new devices get a vendor, a category and a **model** (shown under the name) when the match is not weak. The port scan also reads banners and page titles. The **globe button** (per device, or in the top bar for all devices without a model) collects fresh evidence, scores it with `fingerprints.json` (a public table of host names, mDNS models, ports, banners per vendor, no data of anybody's LAN) and searches the web for the model codes it found. Result: candidates with a confidence (high, medium, low), the evidence and the links. You apply or discard, nothing is overwritten by itself. A rule-based method, not AI. The web step sends only vendor and model code (or host name), never the MAC or the IP, asks once with a disclaimer, and is off with `--no-web`. Search engines may refuse automated requests: point `--search-url` to your own SearXNG.
- Recognition: vendor from the MAC prefix (IEEE OUI database, updatable in one click, registry URLs editable), category from editable rules. LANtern suggests, you confirm.
- CSV and Excel export. Import from a CSV (LANtern's own export works as a backup) or an nmap XML (`nmap -sn -oX`). Known MACs are never overwritten.
- 30 themes in one menu: Classic Light and Classic Dark first (the default follows your OS), then Ayu, Catppuccin, Dracula, Nord, Tokyo Night, Kanagawa and more, each with a light variant when it has one. Font size (with reset), Italian and English (flag in the top bar).

## Run

```
python3 app.py [options]
```

Open `http://127.0.0.1:8099`. Run it on a machine inside the LAN you want to watch.

Needs Python 3. `nmap` is optional (port scan only). The OS is detected at start-up:

- **Linux**: `ping` and `ip` (iproute2).
- **Windows**: `ping` and `arp`, both built in. Run `py app.py`. **Experimental, untested on real hardware.**
- Other systems (macOS, BSD): inventory, import and export work, but status and discovery do not.

## Options

| Option | Default | Meaning |
|---|---|---|
| `-p`, `--port PORT` (or just `PORT`) | `8099` | HTTP port |
| `--host ADDRESS` | `127.0.0.1` | Listen address. Anything else needs a login user first |
| `--db FILE` (or env `LANTERN_DB`) | `lantern.db` next to `app.py` | SQLite file |
| `--subnet CIDR` | detected | Subnet to sweep, repeatable, `/22` at most. Use it when detection picks the wrong network (VPN, several adapters) |
| `--no-discover` | off | Skip the discovery on first start (the Discover button still works) |
| `--no-web` (or env `LANTERN_NO_WEB=1`) | off | Never search the web to identify devices, and hide the globe button |
| `--search-url URL` (or env `LANTERN_SEARCH_URL`) | DuckDuckGo HTML | Search page used by Identify, `{q}` is the query. HTML or JSON (SearXNG) |
| `--set-password USER` | | Create or replace the login user, then exit |
| `--disable-login` | | Remove the login user, then exit |
| `--version` | | Print the version |
| `seed.local.json` | none | Optional automatic import on first start, JSON: `[[name, ip, mac, vendor, type, notes, reserved], ...]`, `reserved` = 0 dynamic, 1 reservation, 2 fixed |

The database starts empty and fills itself with a discovery on first start. `seed.local.json` is only needed to import data you already have.

## Docker

Linux only. The container uses the host network, because discovery needs to see the LAN (ARP, ping). With Docker Desktop (Windows, macOS) run LANtern natively instead.

```
cp .env.example .env     # edit it
docker compose up -d --build
docker compose ps        # "healthy" after a few seconds
docker compose logs lantern
```

Then open `http://127.0.0.1:8099` (or the host and port you set). On the first start, with an empty database, LANtern discovers the devices by itself.

| Variable (`.env`) | Default | Meaning |
|---|---|---|
| `LANTERN_USER`, `LANTERN_PASSWORD` | empty | Both set: the user is created at start, and `.env` wins over the web page. The password needs 8 to 200 characters, or the container stops. Both empty: no login |
| `LANTERN_HOST` | `127.0.0.1` | Listen address. `0.0.0.0` or a LAN address needs a user, or the container stops |
| `LANTERN_PORT` | `8099` | HTTP port. With the host network it is used directly: it must be free |
| `LANTERN_DATA` | `lantern-data` | Database: a Docker volume name, or a host folder (`./lantern_data`, `/srv/lantern`; keep the `./`). Docker creates the folder: do not create it yourself |
| `LANTERN_SUBNET`, `LANTERN_NO_DISCOVER`, `LANTERN_NO_WEB`, `LANTERN_SEARCH_URL` | unset | Same as `--subnet`, `--no-discover`, `--no-web`, `--search-url` |
| `TZ` | `Europe/Rome` | Time zone of the container |

Update: `git pull && docker compose up -d --build`. The data and the backups stay in the volume or folder. Stop: `docker compose down`.

Emptying `LANTERN_USER` does not remove a user already stored in the database. To do that: `docker compose exec lantern python app.py --disable-login`.

The same variables work without Docker: `LANTERN_HOST`, `LANTERN_PORT`, `LANTERN_DB`, `LANTERN_USER`, `LANTERN_PASSWORD`, `LANTERN_SUBNET`, `LANTERN_NO_DISCOVER`, `LANTERN_NO_WEB`, `LANTERN_SEARCH_URL`.

## Login

Off by default. Turn it on from the account button in the top bar, or from the shell:

```
python3 app.py --set-password max     # asks for the password, then exits
python3 app.py --disable-login        # lost password: remove the user (needs access to the db file)
```

- One user, stored in the `users` table of the database. The password is hashed with scrypt and a random salt, never stored in clear.
- Session cookie: `HttpOnly`, `SameSite=Strict`, 12 hours, kept in memory (a restart signs everybody out). After 5 wrong passwords the client waits one minute.
- With `--host` set to anything other than this machine, LANtern refuses to start until a user exists.
- The cookie has no `Secure` flag because LANtern speaks plain HTTP. To use it across the network, put it behind a reverse proxy with HTTPS.

## Security

LANtern listens on `127.0.0.1` by default. It can scan your network, so do not expose it to the internet. On loopback it also rejects requests whose `Host` is not `localhost` (DNS rebinding), and cross-site POSTs.

## Tests

```
for t in tests/test_*.py; do python3 $t; done
```

## Credits

Theme colors come from the built-in palettes of [Noctalia](https://github.com/noctalia-dev/noctalia) (MIT), as collected in [NaviradioManagerPlus](https://github.com/nightwatch75/NaviradioManagerPlus).

## License

MIT
