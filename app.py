#!/usr/bin/env python3
"""LANtern: LAN inventory and radar (standard library only). Usage: python3 app.py [port]"""
import argparse, contextlib, fnmatch, getpass, hashlib, hmac, html, secrets, select, struct, time, csv, io, ipaddress, json, os, re, socket, sqlite3, ssl, subprocess, sys, urllib.parse, urllib.request, uuid, zipfile
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = "0.9.0"
DIR = Path(__file__).parent
DB = Path(os.environ.get("LANTERN_DB", DIR / "lantern.db"))  # --db overrides
WIN = os.name == "nt"
SUBNETS = []  # --subnet overrides the automatic detection
AUTO_DISCOVER = True  # --no-discover turns the first-start discovery off
LOOPBACK = True  # set from --host: only then the Host header is checked against DNS rebinding
SESSIONS = {}  # token -> (username, expires). In memory on purpose: a restart logs everybody out
FAILS = {}  # client ip -> (failures, locked until)
SESSION_TTL, MAX_FAILS, LOCK_SECONDS = 12 * 3600, 5, 60
PUBLIC = ("/", "/logo.svg", "/api/login", "/api/session")
FIELDS = ("name", "ip", "mac", "vendor", "model", "type", "notes", "reserved", "icon", "color")  # icon, color: look of this device, empty = the category one
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")

# Optional first-run import: seed.local.json = [[name, ip, mac, vendor, type, notes, reserved], ...]
# (reserved: 0 dynamic, 1 DHCP reservation, 2 fixed on the device). Not versioned: it holds your own LAN.
SEED_FILE = DIR / "seed.local.json"

# key, label, icon (name in the index.html set), icon background color ('' = theme default)
CATS = [("router", "Router", "router", ""), ("server", "Server", "server", ""), ("nas", "NAS", "nas", ""),
        ("sbc", "SBC / Raspberry", "sbc", ""), ("wifi", "Extender / AP", "wifi", ""), ("light", "Light", "light", ""),
        ("speaker", "Speaker", "speaker", ""), ("tv", "TV", "tv", ""), ("game", "Console", "game", ""),
        ("computer", "PC", "computer", ""), ("phone", "Smartphone", "phone", ""), ("tablet", "Tablet", "tablet", ""),
        ("camera", "Camera / Intercom", "camera", ""), ("plug", "Smart plug", "plug", ""),
        ("ac", "Air conditioner", "ac", ""), ("vacuum", "Robot vacuum", "vacuum", ""), ("iot", "IoT / Other", "iot", "")]

OUI_URLS = ("https://standards-oui.ieee.org/oui/oui.csv", "https://standards-oui.ieee.org/oui28/mam.csv",
            "https://standards-oui.ieee.org/oui36/oui36.csv")  # MA-L, MA-M, MA-S
OUI_SYSTEM = Path("/usr/share/hwdata/oui.txt")  # first offline start only; then update from IEEE
FIELDS_RULE = {"mac", "name", "ports", "vendor"}
FIELD_ORDER = ("mac", "name", "ports", "vendor")  # most to least specific
# field, pattern, category: default rules, editable from the UI
RULES = [("vendor", "raspberry", "sbc"), ("vendor", "synology", "nas"), ("vendor", "amazon", "speaker"),
         ("vendor", "lg innotek", "tv"), ("vendor", "dahua", "camera"), ("vendor", "hikvision", "camera"),
         ("vendor", "tp-link", "wifi"), ("vendor", "zte", "router"), ("vendor", "azurewave", "computer"),
         ("vendor", "espressif", "iot"), ("vendor", "tuya", "iot"), ("vendor", "ai-link", "iot"),
         ("name", "yeelink", "light"), ("name", "yeelight", "light"), ("name", "meross", "plug"),
         ("name", "vacuum", "vacuum"), ("name", "net_ac", "ac"), ("name", "ps5", "game"),
         ("name", "webos", "tv"), ("name", "echo", "speaker"), ("name", "pihole", "sbc"),
         ("ports", "554", "camera"), ("ports", "5001", "nas")]


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    new = not c.execute("SELECT 1 FROM sqlite_master WHERE name='devices'").fetchone()
    c.execute("""CREATE TABLE IF NOT EXISTS devices (id INTEGER PRIMARY KEY, name TEXT NOT NULL,
        ip TEXT NOT NULL DEFAULT '', mac TEXT NOT NULL UNIQUE, vendor TEXT NOT NULL DEFAULT '',
        type TEXT NOT NULL DEFAULT 'iot', notes TEXT NOT NULL DEFAULT '', reserved INTEGER NOT NULL DEFAULT 0)""")
    c.execute("CREATE TABLE IF NOT EXISTS categories (key TEXT PRIMARY KEY, label TEXT NOT NULL, icon TEXT NOT NULL, color TEXT NOT NULL DEFAULT '')")
    if not c.execute("SELECT 1 FROM categories").fetchone():  # first run: default categories
        c.executemany("INSERT INTO categories VALUES (?,?,?,?)", CATS)
        c.commit()
    c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, hash TEXT NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS oui (prefix TEXT PRIMARY KEY, vendor TEXT NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    if new:  # until the first discovery (meta 'discovered') the page runs one by itself
        c.execute("INSERT OR IGNORE INTO meta VALUES ('fresh', '1')")
    c.execute("CREATE TABLE IF NOT EXISTS evidence (device_id INTEGER NOT NULL, source TEXT NOT NULL, value TEXT NOT NULL, seen_at TEXT NOT NULL DEFAULT (datetime('now','localtime')), PRIMARY KEY (device_id, source, value))")
    c.execute("CREATE TABLE IF NOT EXISTS lookups (query TEXT PRIMARY KEY, results TEXT NOT NULL, fetched_at TEXT NOT NULL DEFAULT (datetime('now')))")
    c.execute("CREATE TABLE IF NOT EXISTS rules (id INTEGER PRIMARY KEY, field TEXT NOT NULL, pattern TEXT NOT NULL, category TEXT NOT NULL)")
    if not c.execute("SELECT 1 FROM rules").fetchone():
        c.executemany("INSERT INTO rules (field,pattern,category) VALUES (?,?,?)", RULES)
    if not c.execute("SELECT 1 FROM oui").fetchone() and OUI_SYSTEM.exists():
        with open(OUI_SYSTEM, encoding="utf-8", errors="replace") as fh:
            c.executemany("INSERT OR IGNORE INTO oui VALUES (?,?)", re.findall(r"^([0-9A-F]{6})\s+\(base 16\)\s+(.+?)\s*$", fh.read(), re.M))
        c.execute("INSERT OR REPLACE INTO meta VALUES ('oui_source', 'system database'), ('oui_updated', datetime('now','localtime'))")
    c.commit()
    for col in ("ports", "scanned_at", "icon", "color", "model"):  # migration from versions without these columns
        if col not in [r[1] for r in c.execute("PRAGMA table_info(devices)")]:
            c.execute(f"ALTER TABLE devices ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
    if not c.execute("SELECT 1 FROM devices").fetchone():  # new database: the seed does not count as a discovery
        c.executemany("INSERT INTO devices (name,ip,mac,vendor,type,notes,reserved) VALUES (?,?,?,?,?,?,?)", json.loads(SEED_FILE.read_text()) if SEED_FILE.exists() else [])
        c.commit()
    elif not c.execute("SELECT 1 FROM meta WHERE key IN ('discovered', 'fresh')").fetchone():  # database of an older version: no first-run discovery
        c.execute("INSERT INTO meta VALUES ('discovered', 'before 0.8.3')")
        c.commit()
    return c


MAX_PORTS = 1024
SCAN_PORTS = ("21,22,23,25,53,80,81,110,111,123,135,139,143,161,443,445,515,554,631,993,1080,1883,1900,3000,3306,"
              "3389,5000,5001,5005,5006,5353,5555,5900,6668,7000,8000,8008,8009,8080,8081,8443,8883,8888,9000,9100,"
              "9999,10001,49152,55443,62078")


def scan_ports(c):
    row = c.execute("SELECT value FROM meta WHERE key='scan_ports'").fetchone()
    return row[0] if row else SCAN_PORTS


def clean_ports(text):
    """'22, 80,8000-8100' -> '22,80,8000-8100'. Empty means: back to the known ports."""
    s = re.sub(r"\s+", "", str(text)).strip(",")
    n = 0
    for p in s.split(",") if s else []:
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", p)
        a, b = (int(m[1]), int(m[2] or m[1])) if m else (0, 0)
        if not 1 <= a <= b <= 65535:
            raise ValueError(f"invalid port or range: {p!r} (use 22,80,8000-8100)")
        n += b - a + 1
    if n > MAX_PORTS:
        raise ValueError(f"too many ports ({n}), at most {MAX_PORTS}")
    return s


def scan(ip, ports=SCAN_PORTS):
    """Listening TCP ports among `ports`, e.g. '22/ssh,80/http'. Needs nmap (connect scan, no root)."""
    ipaddress.IPv4Address(ip)
    out = subprocess.run(["nmap", "-Pn", "-sT", "-n", "-T4", "--max-retries", "1", "--host-timeout", "40s",
                          "-p", ports, "-oG", "-", ip], capture_output=True, text=True, timeout=60).stdout
    return ",".join(f"{p}/{n}" for p, n in re.findall(r"(\d+)/open/tcp//([^/]*)/", out))


# Backups: files next to the database, so a Docker volume keeps them. The login (users table) is never included.
BK_RE = re.compile(r"lantern-\d{8}-\d{6}(?:-\d+)?\.db")
BK_TABLES = ("devices", "categories", "rules", "oui", "meta", "evidence")
MAX_UPLOAD = 128 * 1024 * 1024


def bk_dir():
    d = DB.parent / "backups"
    d.mkdir(exist_ok=True)
    return d


def bk_path(name):
    p = bk_dir() / name
    if not BK_RE.fullmatch(name) or not p.is_file():
        raise ValueError("backup not found")
    return p


def bk_note(p, note):
    n = p.with_suffix(".txt")
    note = str(note).strip()[:200]
    n.write_text(note, encoding="utf-8") if note else n.unlink(missing_ok=True)


def bk_slot():
    stamp, i, d = time.strftime("%Y%m%d-%H%M%S"), 0, bk_dir()
    while (d / f"lantern-{stamp}{f'-{i}' if i else ''}.db").exists():
        i += 1
    return d / f"lantern-{stamp}{f'-{i}' if i else ''}.db"


def bk_list():
    return [{"name": p.name, "size": p.stat().st_size, "created": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.stat().st_mtime)),
             "note": p.with_suffix(".txt").read_text(encoding="utf-8") if p.with_suffix(".txt").exists() else ""}
            for p in sorted(bk_dir().glob("lantern-*.db"), key=lambda p: p.stat().st_mtime, reverse=True) if BK_RE.fullmatch(p.name)]


def bk_new(note=""):
    p = bk_slot()
    c = db()
    with contextlib.closing(c), contextlib.closing(sqlite3.connect(p)) as dst:
        c.backup(dst)  # consistent copy while the app runs
        dst.execute("DROP TABLE users")
        dst.execute("DELETE FROM meta WHERE key IN (?)", SECRET_META)
        dst.commit()
        dst.execute("VACUUM")
    bk_note(p, note)
    return p.name


def bk_import(data, note=""):
    if not data.startswith(b"SQLite format 3\0"):
        raise ValueError("not a SQLite database")
    p = bk_slot()
    p.write_bytes(data)
    try:
        with contextlib.closing(sqlite3.connect(p)) as x:
            tables = {r[0] for r in x.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"devices", "categories"} <= tables or x.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("not a LANtern database")
            x.execute("DROP TABLE IF EXISTS users")  # a foreign file must not carry a login into the history
            x.execute("DELETE FROM meta WHERE key IN (?)", SECRET_META)
            x.commit()
            x.execute("VACUUM")
    except (sqlite3.Error, ValueError):
        p.unlink(missing_ok=True)
        raise ValueError("not a LANtern database")
    bk_note(p, note)
    return p.name


def bk_restore(name):
    """Replace devices, categories, rules, OUI and settings with the backup's. A backup of the current state is taken first."""
    p = bk_path(name)
    bk_new(f"automatic, before restoring {name}")
    c = db()
    with contextlib.closing(c):
        c.execute("ATTACH DATABASE ? AS bk", (str(p),))
        keep = c.execute("SELECT key, value FROM main.meta WHERE key IN (?)", SECRET_META).fetchall()
        try:
            for t in BK_TABLES:
                have = {r[1] for r in c.execute(f"PRAGMA bk.table_info({t})")}  # a backup from an older version may lack columns
                cols = ",".join(r[1] for r in c.execute(f"PRAGMA main.table_info({t})") if r[1] in have)
                c.execute(f"DELETE FROM main.{t}")  # also when an older backup lacks the table: its state had none
                if cols:
                    c.execute(f"INSERT INTO main.{t} ({cols}) SELECT {cols} FROM bk.{t}")
            c.executemany("INSERT OR REPLACE INTO meta VALUES (?,?)", keep)  # the restore does not touch the API key
            c.commit()
        except sqlite3.Error:
            c.rollback()
            raise
        finally:
            c.execute("DETACH DATABASE bk")


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", **kw).stdout  # Windows prints in the OEM code page


def ping(ip, count=1, wait=1):
    if WIN:  # Windows ping exits 0 on "destination unreachable" too: look for a real reply
        return "TTL=" in run(["ping", "-n", str(count), "-w", str(wait * 1000), ip])
    return subprocess.run(["ping", "-c", str(count), "-W", str(wait), ip], capture_output=True).returncode == 0


def parse_neigh(text):
    """Linux `ip neigh` -> {ip: (mac, state)}."""
    return {ip: (mac.lower(), st) for ip, mac, st in re.findall(r"^(\S+) dev \S+ lladdr (\S+) (\w+)", text, re.M) if ":" not in ip}


def parse_arp(text):
    """Windows `arp -a` -> {ip: (mac, state)}; broadcast and multicast rows are dropped. State words are localized, so ignored."""
    rows = re.findall(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\b", text, re.M | re.I)
    return {ip: (m, "") for ip, m in ((ip, norm_mac(m)) for ip, m in rows) if m != "ff:ff:ff:ff:ff:ff" and not m.startswith("01:00:5e")}


def neighbors(ip=None):
    """OS neighbor (ARP) table, optionally for one IP."""
    if WIN:
        return parse_arp(run(["arp", "-a"] + ([ip] if ip else [])))
    return parse_neigh(run(["ip", "neigh", "show"] + ([ip] if ip else [])))


def local_nets():
    """(subnets to sweep, {mac: ip} of this host). Never more than a /22 per subnet."""
    def net(i):
        return ipaddress.ip_network(f"{i.ip}/{max(i.network.prefixlen, 22)}", strict=False)
    if SUBNETS:
        return [ipaddress.ip_network(n, strict=False) for n in SUBNETS], {}
    if WIN or not sys.platform.startswith("linux"):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:  # no packet is sent: the OS only picks the outgoing interface
            sk.connect(("192.0.2.1", 9))
            ip = sk.getsockname()[0]
        node = uuid.getnode()  # shortcut: may be another adapter; bit 40 set means "random", then skip it
        own = {} if node >> 40 & 1 else {":".join(f"{node:012x}"[i:i + 2] for i in range(0, 12, 2)): ip}
        return [net(ipaddress.ip_interface(f"{ip}/24"))], own
    nets, own = [], {}
    for dev, addr in re.findall(r"^\d+:\s+(\S+)\s+inet (\S+)", run(["ip", "-o", "-4", "addr", "show", "scope", "global"], timeout=10), re.M):
        if re.match(r"(docker|br-|veth|virbr|tun|tap|lo)", dev):  # containers and VPNs are not the LAN
            continue
        i = ipaddress.ip_interface(addr)
        nets.append(net(i))
        try:  # this host does not show up in its own ARP table
            own[Path(f"/sys/class/net/{dev}/address").read_text().strip().lower()] = str(i.ip)
        except OSError:
            pass
    return nets, own


def probe(d):
    """'on' | 'off' | 'conflict' (MAC differs from the expected one) | None (no IP)."""
    if not d["ip"]:
        return None
    up = ping(d["ip"], 2, 2)
    m = neighbors(d["ip"]).get(d["ip"])
    if not (up or (m and m[1] == "REACHABLE")):
        return "off"
    return "conflict" if m and m[0] != d["mac"] else "on"


def devices_with_status(c):
    rows = [dict(r) for r in c.execute("SELECT * FROM devices")]
    with ThreadPoolExecutor(32) as ex:
        for r, s in zip(rows, ex.map(probe, rows)):
            r["status"] = s
    return rows


EXPORT_HEAD = {"it": ["Nome", "IP", "MAC", "Produttore", "Modello", "Tipo", "Stato", "Assegnazione IP", "Porte in ascolto", "Note"],
               "en": ["Name", "IP", "MAC", "Vendor", "Model", "Type", "Status", "IP assignment", "Listening ports", "Notes"]}
ASSIGN = {"it": ["Dinamico", "Reservation", "Fisso"], "en": ["Dynamic", "Reservation", "Static"]}
STATUS = {"it": {"on": "Online", "off": "Offline", "conflict": "MAC diverso", None: "N/D"},
          "en": {"on": "Online", "off": "Offline", "conflict": "MAC mismatch", None: "N/A"}}


def export_rows(c, lang="it"):
    labels = dict(c.execute("SELECT key, label FROM categories"))
    return [EXPORT_HEAD[lang]] + [[d["name"], d["ip"], d["mac"], d["vendor"], d["model"], labels.get(d["type"], d["type"]), STATUS[lang][d["status"]],
                             ASSIGN[lang][d["reserved"]], d["ports"], d["notes"]] for d in devices_with_status(c)]


def to_csv(rows):  # ';' and BOM: Excel opens it without the import wizard
    out = io.StringIO()
    csv.writer(out, delimiter=";").writerows(rows)
    return b"\xef\xbb\xbf" + out.getvalue().encode()


def to_xlsx(rows):  # shortcut: foglio unico, solo stringhe, nessuno stile
    sheet = "".join(
        "<row>" + "".join(f'<c t="inlineStr"><is><t>{escape(str(v))}</t></is></c>' for v in r) + "</row>" for r in rows)
    parts = {
        "[Content_Types].xml": '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>',
        "_rels/.rels": '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
        "xl/workbook.xml": '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Device" sheetId="1" r:id="rId1"/></sheets></workbook>',
        "xl/_rels/workbook.xml.rels": '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
        "xl/worksheets/sheet1.xml": f'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{sheet}</sheetData></worksheet>',
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, x in parts.items():
            z.writestr(n, x)
    return buf.getvalue()


def oui_info(c):
    m = dict(c.execute("SELECT key, value FROM meta"))
    return {"count": c.execute("SELECT COUNT(*) FROM oui").fetchone()[0], "source": m.get("oui_source", "-"), "updated": m.get("oui_updated", "-"), "urls": oui_urls(c)}


def oui_urls(c):
    r = c.execute("SELECT value FROM meta WHERE key='oui_urls'").fetchone()
    return r[0].split("\n") if r else list(OUI_URLS)


def oui_update(c, urls=None):
    """Download the OUI registries (IEEE CSV or the oui.txt format) and replace the local copy."""
    if urls is not None:
        urls = [u.strip() for u in urls if u.strip()] or list(OUI_URLS)
        if not all(re.match(r"https?://\S+$", u) for u in urls):  # no file:// and friends
            raise ValueError("invalid URL (http or https only)")
        c.execute("INSERT OR REPLACE INTO meta VALUES ('oui_urls', ?)", ("\n".join(urls),))
    urls = urls or oui_urls(c)
    rows = {}
    for url in urls:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 lan-inventory"})
        with urllib.request.urlopen(req, timeout=60) as r:
            text = r.read().decode("utf-8-sig", errors="replace")
        if "(base 16)" in text:
            rows.update((p, v) for p, v in re.findall(r"^([0-9A-F]{6,9})\s+\(base 16\)\s+(.+?)\s*$", text, re.M))
        else:
            for rec in csv.DictReader(io.StringIO(text)):
                rows[rec["Assignment"].upper()] = rec["Organization Name"].strip()
    if not rows:
        raise ValueError("empty IEEE response")
    c.execute("DELETE FROM oui")
    c.executemany("INSERT INTO oui VALUES (?,?)", rows.items())
    src = ", ".join(dict.fromkeys(u.split("/")[2] for u in urls))
    c.execute("INSERT OR REPLACE INTO meta VALUES ('oui_source', ?), ('oui_updated', datetime('now','localtime'))", (src,))
    c.commit()


def oui_vendor(c, mac):
    """(producer from the OUI registry, locally administered?). A local MAC has no producer."""
    valid = bool(MAC_RE.match(mac))
    local = valid and bool(int(mac[:2], 16) & 2)  # 'locally administered' bit: no vendor in the IEEE registry
    if not valid or local:
        return "", local
    h = mac.replace(":", "").upper()
    r = c.execute("SELECT vendor FROM oui WHERE prefix IN (?,?,?) ORDER BY length(prefix) DESC LIMIT 1", (h[:9], h[:7], h[:6])).fetchone()
    return (r[0] if r else ""), local


def family(c, did):
    """(producer, [(id, name)]) of the other devices whose MAC belongs to the same producer. No producer, no family."""
    me = c.execute("SELECT mac FROM devices WHERE id=?", (did,)).fetchone()
    vendor = oui_vendor(c, me[0])[0] if me else ""
    if not vendor:
        return "", []
    return vendor, [(i, n) for i, n, m in c.execute("SELECT id, name, mac FROM devices WHERE id != ?", (did,)) if oui_vendor(c, m)[0] == vendor]


def suggest(c, mac, name, ports):
    """Produttore dal prefisso MAC (OUI) e categoria dalla prima regola che corrisponde."""
    mac = mac.strip().lower()
    vendor, local = oui_vendor(c, mac)
    port_list = [p.split("/")[0] for p in ports.split(",") if p]
    rules = sorted(c.execute("SELECT r.* FROM rules r JOIN categories k ON k.key = r.category"), key=lambda r: (FIELD_ORDER.index(r["field"]), r["id"]))
    for r in rules:
        pat = r["pattern"].lower()
        hit = {"mac": mac.startswith(pat), "name": pat in name.lower(), "vendor": pat in vendor.lower(), "ports": pat in port_list}[r["field"]]
        if hit:
            return {"vendor": vendor, "local": local, "category": r["category"], "rule": f"{r['field']}: {r['pattern']}"}
    return {"vendor": vendor, "local": local, "category": None, "rule": None}


def add_new(c, name, ip, mac, vendor="", type="", notes="", reserved=0, model=""):
    """Insert a device unless its MAC is already known; vendor and category come from OUI and rules when missing."""
    s = suggest(c, mac, name, "")
    return c.execute("INSERT OR IGNORE INTO devices (name,ip,mac,vendor,type,notes,reserved,model) VALUES (?,?,?,?,?,?,?,?)",
                     (name or s["vendor"] or f"Device {ip}", ip, mac, vendor or s["vendor"], type or s["category"] or "iot", notes, reserved, model)).rowcount


def discover(c):
    """Ping-sweep the local subnets, read the ARP table, add the MACs not in the inventory yet."""
    nets, found = local_nets()  # found: mac -> ip
    with ThreadPoolExecutor(64) as ex:
        list(ex.map(ping, [str(h) for n in nets for h in n.hosts()]))
    for ip, (mac, _) in neighbors().items():
        if any(ipaddress.ip_address(ip) in n for n in nets):
            found.setdefault(mac, ip)
    if not c.execute("SELECT 1 FROM oui").fetchone():  # fresh machine without a system OUI file
        try:
            oui_update(c)
        except (OSError, ValueError):
            pass
    def host(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except OSError:
            return ""
    with ThreadPoolExecutor(32) as ex:
        names = dict(zip(found, ex.map(host, found.values())))
    before = {r[0] for r in c.execute("SELECT id FROM devices")}
    added = sum(add_new(c, names[mac], ip, mac) for mac, ip in found.items())
    c.commit()
    for mac, name in names.items():
        row = c.execute("SELECT id FROM devices WHERE mac=?", (mac,)).fetchone()
        if row and name:
            store_evidence(c, row[0], "rdns", [name])
    collect_lan(c)
    auto_identify(c, [r[0] for r in c.execute("SELECT id FROM devices") if r[0] not in before])
    c.commit()
    return {"found": len(found), "added": added}


# ---- identification: evidence from the LAN + the public fingerprints.json + an optional web search ----
FP_FILE = DIR / "fingerprints.json"
NO_WEB = False  # --no-web
DEFAULT_SEARCH = SEARCH_URL = "https://html.duckduckgo.com/html/?q={q}"  # --search-url: any HTML or JSON (SearXNG) search page
SEARXNG_URL = "http://127.0.0.1:8888"  # the SearXNG of compose.yaml
ENGINES = ("ddg", "searxng", "brave", "custom")  # Google: its Custom Search API is closed to new customers (ends 2027-01-01)
SECRET_META = ("search_key",)  # never in a backup
MDNS_TYPES = ("_hap._tcp", "_spotify-connect._tcp", "_matter._tcp", "_googlecast._tcp", "_airplay._tcp", "_raop._tcp",
              "_companion-link._tcp", "_http._tcp", "_ipp._tcp", "_printer._tcp", "_smb._tcp", "_device-info._tcp",
              "_workstation._tcp", "_amzn-wplay._tcp", "_sonos._tcp", "_hue._tcp", "_esphomelib._tcp", "_shelly._tcp",
              "_ewelink._tcp", "_samsungmsf._tcp", "_ssh._tcp")
MD_KEYS = ("md", "am", "ty", "product", "usb_MDL")  # TXT keys that carry a model ("model" is not read: some NAS fake it)
WEB_PORTS, TLS_PORTS = {80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000}, {443, 5001, 8443}
_FP = []


class WebError(Exception):
    pass


def load_fingerprints():
    if not _FP:
        _FP.extend(json.loads(FP_FILE.read_text(encoding="utf-8")))
    return _FP


def conf(score):
    return "high" if score >= 4 else "medium" if score >= 2 else "low"


def dns_query(names):  # one PTR question per name, with the "unicast reply" bit
    return b"\0\0\0\0" + len(names).to_bytes(2, "big") + b"\0" * 6 + b"".join(
        b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\0\x00\x0c\x80\x01" for n in names)


def dns_name(d, i):
    labels, end = [], 0
    for _ in range(64):  # a compression loop must not hang us
        n = d[i]
        if n == 0:
            return ".".join(labels), end or i + 1
        if n & 0xC0 == 0xC0:
            end = end or i + 2
            i = ((n & 0x3F) << 8) | d[i + 1]
        else:
            labels.append(d[i + 1:i + 1 + n].decode(errors="replace"))
            i += 1 + n
    return ".".join(labels), end or i


def dns_records(d):
    """[(owner, type, value)]: PTR -> name, SRV -> target, A -> address, TXT -> {key: value}. A broken packet gives what was read."""
    out = []
    try:
        qd, an, ns, ar = struct.unpack(">4H", d[4:12])
        i = 12
        for _ in range(qd):
            i = dns_name(d, i)[1] + 4
        for _ in range(an + ns + ar):
            name, i = dns_name(d, i)
            t, _, _, ln = struct.unpack(">HHIH", d[i:i + 10])
            i += 10
            if t == 12:
                out.append((name, t, dns_name(d, i)[0]))
            elif t == 33:
                out.append((name, t, dns_name(d, i + 6)[0]))
            elif t == 1 and ln == 4:
                out.append((name, t, ".".join(map(str, d[i:i + 4]))))
            elif t == 16:
                kv, j, r = {}, 0, d[i:i + ln]
                while j < len(r):
                    k, _, v = r[j + 1:j + 1 + r[j]].decode(errors="replace").partition("=")
                    kv[k] = v
                    j += 1 + r[j]
                out.append((name, t, kv))
            i += ln
    except (IndexError, struct.error):
        pass
    return out


def mdns_scan(wait=3):
    """{ip: {"host": set, "svc": set, "md": set}}: one multicast question for the common service types, then listen."""
    found, socks = {}, []
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    socks.append(tx)
    try:  # also hear the answers other devices send to the group (port 5353 is shared with avahi and the like)
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        rx.bind(("", 5353))
        rx.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton("224.0.0.251") + socket.inet_aton("0.0.0.0"))
        socks.append(rx)
    except OSError:
        pass
    try:
        tx.sendto(dns_query(["_services._dns-sd._udp.local"] + [t + ".local" for t in MDNS_TYPES]), ("224.0.0.251", 5353))
        end = time.time() + wait
        while time.time() < end:
            for s in select.select(socks, [], [], 0.3)[0]:
                d, a = s.recvfrom(9000)
                if len(d) < 12 or not d[2] & 0x80:  # a question of another host, not an answer
                    continue
                e = found.setdefault(a[0], {"host": set(), "svc": set(), "md": set()})
                for name, t, v in dns_records(d):
                    if t == 12:
                        e["svc"].add((v if name.startswith("_services.") else name).removesuffix(".local"))
                    elif t in (33, 1):
                        e["host"].add((v if t == 33 else name).removesuffix(".local"))
                    elif t == 16:
                        e["md"].update(v[k] for k in MD_KEYS if v.get(k))
    finally:
        for s in socks:
            s.close()
    return found


def ssdp_scan(wait=3):
    """{ip: ["server: ...", "manufacturer: ...", "model: ...", "name: ..."]}: SSDP answers and the device description."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    seen = {}
    try:
        for _ in range(2):
            s.sendto(b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n', ("239.255.255.250", 1900))
        end = time.time() + wait
        while time.time() < end:
            try:
                d, a = s.recvfrom(4096)
            except socket.timeout:
                continue
            h = {k.lower(): v for k, v in re.findall(r"^([A-Za-z-]+):\s*(.*?)\r?$", d.decode(errors="replace"), re.M)}
            e = seen.setdefault(a[0], {"server": h.get("server", ""), "loc": set()})
            if "location" in h:
                e["loc"].add(h["location"])
    finally:
        s.close()
    out = {}
    for ip, e in seen.items():
        vals = [f"server: {e['server'][:80]}"] if e["server"] else []
        for loc in sorted(e["loc"])[:2]:
            u = urllib.parse.urlsplit(loc)
            if u.scheme != "http" or u.hostname != ip:  # the description must come from the device that answered
                continue
            try:  # shortcut: ElementTree does not guard against hostile XML, fine for a device of your own LAN
                x = ET.fromstring(urllib.request.urlopen(loc, timeout=3).read(65536))
            except (OSError, ET.ParseError, ValueError):
                continue
            for tag, label in (("manufacturer", "manufacturer"), ("modelName", "model"), ("friendlyName", "name")):
                el = next((n for n in x.iter() if n.tag.rsplit("}", 1)[-1] == tag), None)
                if el is not None and el.text and el.text.strip():
                    vals.append(f"{label}: {el.text.strip()[:60]}")
        out[ip] = list(dict.fromkeys(vals))
    return out


def http_peek(ip, port, tls):
    """(Server header, page title) of GET /. Read only, no login."""
    s = socket.create_connection((ip, port), 3)
    s.settimeout(3)
    if tls:
        cx = ssl.create_default_context()
        cx.check_hostname, cx.verify_mode = False, ssl.CERT_NONE  # a LAN device with its own certificate: we only read a title
        s = cx.wrap_socket(s)
    s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
    d = b""
    while len(d) < 6000:
        x = s.recv(2000)
        if not x:
            break
        d += x
    s.close()
    d = d.decode(errors="replace")
    srv, ti = re.search(r"^Server:\s*(.*?)\r?$", d, re.M | re.I), re.search(r"<title[^>]*>(.*?)</title>", d, re.S | re.I)
    return (srv.group(1).strip() if srv else ""), (html.unescape(ti.group(1)).strip() if ti else "")


def banners(ip, ports):
    """[(source, text)] read from the open ports: SSH banner, HTTP Server and title, RTSP realm (without its serial)."""
    out = []
    for p in (int(x.split("/")[0]) for x in ports.split(",") if x):
        try:
            if p == 22:
                s = socket.create_connection((ip, p), 3)
                s.settimeout(3)
                line = s.recv(100).split(b"\n")[0].decode(errors="replace").strip()
                s.close()
                if line.startswith("SSH-"):
                    out.append(("banner", "ssh: " + line[:60]))
            elif p == 554:
                s = socket.create_connection((ip, p), 3)
                s.settimeout(3)
                s.sendall(f"OPTIONS rtsp://{ip}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
                m = re.search(r'realm="([^"]*)"', s.recv(600).decode(errors="replace"))
                s.close()
                if m:
                    out.append(("banner", "rtsp-realm: " + " ".join(m.group(1).split()[:2])))
            elif p in WEB_PORTS | TLS_PORTS:
                srv, title = http_peek(ip, p, p in TLS_PORTS)
                out += ([("banner", "http-server: " + srv[:40])] if srv else []) + ([("title", title[:80])] if title else [])
        except (OSError, ssl.SSLError):
            pass
    return out


def scan_one(ip, ports):
    found = scan(ip, ports)
    return found, banners(ip, found)


def store_evidence(c, did, source, values):
    c.execute("DELETE FROM evidence WHERE device_id=? AND source=?", (did, source))
    c.executemany("INSERT OR IGNORE INTO evidence (device_id, source, value) VALUES (?,?,?)", [(did, source, v) for v in values if v])


def store_banners(c, did, pairs):
    for source in ("title", "banner"):
        store_evidence(c, did, source, [v for s, v in pairs if s == source])


def collect_lan(c):
    """mDNS and SSDP answers of the whole LAN (about 3 seconds), kept as evidence of the devices with that IP."""
    with ThreadPoolExecutor(2) as ex:
        fs = {"mdns": ex.submit(mdns_scan), "ssdp": ex.submit(ssdp_scan)}
    res = {}
    for k, f in fs.items():
        try:
            res[k] = f.result()
        except OSError:  # no multicast here (container network, firewall): the rest still works
            res[k] = {}
    for did, ip in list(c.execute("SELECT id, ip FROM devices WHERE ip != ''")):
        if ip in res["mdns"]:
            e = res["mdns"][ip]
            for src, key in (("mdns_host", "host"), ("svc", "svc"), ("md", "md")):
                if e[key]:
                    store_evidence(c, did, src, sorted(e[key]))
        if res["ssdp"].get(ip):
            store_evidence(c, did, "ssdp", res["ssdp"][ip])
    c.commit()


def evidence(c, did):
    ev = {}
    for source, value in c.execute("SELECT source, value FROM evidence WHERE device_id=?", (did,)):
        ev.setdefault(source, []).append(value)
    return ev


def fp_match(fp, ev, oui, ports):
    """{key: matched evidence} when every matching key of the entry hits, else None."""
    hosts = ev.get("rdns", []) + ev.get("mdns_host", [])
    hits = {}
    for key, pat in fp.items():
        if key in ("vendor", "type", "model", "model_from_host", "w"):
            continue
        if key == "host":
            hit = next((h for h in hosts if fnmatch.fnmatchcase(h.lower(), pat.lower())), None)
        elif key == "title":
            hit = next((t for t in ev.get("title", []) if fnmatch.fnmatchcase(t.lower(), pat.lower())), None)
        elif key == "oui":
            hit = oui if pat in oui.lower() else None
        elif key == "md":
            hit = next((m for m in ev.get("md", []) if m.lower() == pat.lower()), None)
        elif key in ("svc", "ssdp", "banner"):
            hit = next((x for x in ev.get(key, []) if pat.lower() in x.lower()), None)
        elif key == "ports":
            hit = ",".join(map(str, pat)) if all(p in ports for p in pat) else None
        else:
            hit = None
        if not hit:
            return None
        hits[key] = hit
    return hits or None


def identify_local(c, d):
    """Candidates [{vendor, type, model, score, confidence, why}] from the evidence of the device, the OUI and the fingerprints."""
    ev = evidence(c, d["id"])
    oui = oui_vendor(c, d["mac"])[0]
    ports = {int(p.split("/")[0]) for p in d["ports"].split(",") if p}
    cands = {}

    def add(vendor, type_, model, w, why):
        e = cands.setdefault(vendor.lower(), {"vendor": vendor, "score": 0, "types": {}, "models": {}, "why": []})
        e["score"] += w
        for k, v in (("types", type_), ("models", model)):
            if v:
                e[k][v] = e[k].get(v, 0) + w
        e["why"] += why

    for fp in load_fingerprints():
        hits = fp_match(fp, ev, oui, ports)
        if hits:
            model = fp.get("model", "")
            if fp.get("model_from_host"):
                model = hits["host"][len(re.split(r"[*?]", fp["host"])[0]):].strip(" _-")
            add(fp.get("vendor", ""), fp.get("type", ""), model, fp.get("w", 1), [f"{k}: {v}" for k, v in hits.items()])
    desc = {s.split(": ", 1)[0]: s.split(": ", 1)[1] for s in ev.get("ssdp", []) if ": " in s}
    if desc.get("model"):
        add(desc.get("manufacturer", ""), "", desc["model"], 2, [f"ssdp: {desc.get('manufacturer', '')} {desc['model']}".replace("  ", " ")])
    top = lambda m: max(m, key=m.get, default="")
    nov = cands.pop("", None)  # hits without a vendor (a page title, a hostname) join the vendor of the same category
    if nov:
        tgt = next((e for e in sorted(cands.values(), key=lambda e: -e["score"]) if top(e["types"]) == top(nov["types"])), None)
        if tgt:
            tgt["score"] += nov["score"]
            tgt["why"] += nov["why"]
            for k in ("types", "models"):
                for m, w in nov[k].items():
                    tgt[k][m] = tgt[k].get(m, 0) + w
        else:
            cands[""] = nov
    for e in cands.values():  # the MAC producer agrees with the vendor: one more point, once
        if e["vendor"] and oui and not any(w.startswith("oui:") for w in e["why"]) and (e["vendor"].lower() in oui.lower() or oui.lower().split()[0] in e["vendor"].lower()):
            e["score"] += 1
            e["why"].append(f"oui: {oui}")
    return sorted(({"vendor": e["vendor"], "type": top(e["types"]), "model": top(e["models"]), "score": e["score"],
                    "confidence": conf(e["score"]), "why": e["why"]} for e in cands.values()), key=lambda x: -x["score"])


def auto_identify(c, ids):
    """New devices only: keep the model, and the vendor and category while they are empty or the default, if the match is not weak."""
    for did in ids:
        d = dict(c.execute("SELECT * FROM devices WHERE id=?", (did,)).fetchone())
        top = (identify_local(c, d) or [None])[0]
        if top and top["confidence"] != "low":
            known = c.execute("SELECT 1 FROM categories WHERE key=?", (top["type"],)).fetchone()
            c.execute("UPDATE devices SET model=?, vendor=?, type=? WHERE id=?",
                      (top["model"], d["vendor"] or top["vendor"], top["type"] if known and d["type"] == "iot" else d["type"], did))


def parse_results(body):
    """[{title, url, snippet}] from a JSON answer (SearXNG, Brave) or a DuckDuckGo-style HTML page."""
    if body.lstrip().startswith("{"):
        j = json.loads(body)
        rows = j.get("results") or (j.get("web") or {}).get("results") or []
        return [{"title": r.get("title", ""), "url": r.get("url", ""), "snippet": r.get("content") or r.get("description", "")} for r in rows[:10]]
    plain = lambda t: html.unescape(re.sub(r"<[^>]+>", "", t)).strip()
    out = []
    for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>(.*?)(?=<a[^>]+class="result__a"|\Z)', body, re.S):
        href, title, rest = m.groups()
        u, sn = re.search(r"uddg=([^&]+)", href), re.search(r'class="result__snippet"[^>]*>(.*?)</a>', rest, re.S)
        out.append({"title": plain(title), "url": urllib.parse.unquote(u.group(1)) if u else html.unescape(href), "snippet": plain(sn.group(1)) if sn else ""})
    return out[:10]


def engine_conf(c):
    """The search engine setting: meta rows, else --search-url (custom), else DuckDuckGo."""
    m = dict(c.execute("SELECT key, value FROM meta WHERE key LIKE 'search_%'"))
    e = m.get("search_engine") or ("custom" if SEARCH_URL != DEFAULT_SEARCH else "ddg")
    return {"engine": e if e in ENGINES else "ddg", "url": m.get("search_url") or (SEARCH_URL if e == "custom" else SEARXNG_URL), "key": m.get("search_key", "")}


def engine_request(cf, q):
    """(url, headers) for the query q."""
    e, qq = cf["engine"], urllib.parse.quote_plus(q)
    if e == "searxng":
        return re.sub(r"(/search)?/?$", "", cf["url"].strip()) + f"/search?q={qq}&format=json", {}
    if e == "brave":
        return f"https://api.search.brave.com/res/v1/web/search?q={qq}&count=10", {"X-Subscription-Token": cf["key"], "Accept": "application/json"}
    return (cf["url"] if e == "custom" else DEFAULT_SEARCH).replace("{q}", qq), {}


def web_lookup(c, q, cf=None):
    """Search results for q, from the cache (30 days) or the search engine. Honest User-Agent: a refusal is reported, not worked around.
    cf: a setting to try without the cache (the Test button)."""
    row = None if cf else c.execute("SELECT results FROM lookups WHERE query=? AND fetched_at > datetime('now','-30 days')", (q,)).fetchone()
    if row:
        return json.loads(row[0])
    cf = cf or engine_conf(c)
    if cf["engine"] == "brave" and not cf["key"]:
        raise WebError("this search engine needs an API key")
    url, hdr = engine_request(cf, q)
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise WebError("the search URL must be http or https")
    time.sleep(1)  # one request a second at most
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": f"LANtern/{VERSION} (+https://github.com/nightwatch75/lantern)", **hdr}), timeout=8) as r:
            status, body = r.status, r.read(500000).decode(errors="replace")
    except OSError as e:
        raise WebError(f"search failed: {e}")
    try:
        res = parse_results(body) if status == 200 else []
    except ValueError:
        res = []
    if not res:
        raise WebError("the search engine returned no usable results (it may refuse automated requests: choose another engine, like your own SearXNG)")
    if not cf.get("test"):
        c.execute("INSERT OR REPLACE INTO lookups (query, results) VALUES (?,?)", (q, json.dumps(res)))
        c.commit()
    return res


def model_tokens(d, ev, local):
    """Model-like words (letters and digits, 5+ characters) from names and banners: not hex strings, not the tail of the MAC."""
    tail = re.sub(r"[^0-9a-f]", "", d["mac"].lower())
    texts = ev.get("rdns", []) + ev.get("mdns_host", []) + [s for s in ev.get("ssdp", []) if s.startswith("model: ")] + ev.get("md", [])
    toks = [w for t in texts for w in re.findall(r"[A-Za-z0-9][A-Za-z0-9-]{4,}", t)
            if re.search(r"[A-Za-z]", w) and re.search(r"\d", w) and not re.fullmatch(r"[0-9a-fA-F]+", w) and not w.lower().endswith((tail[-4:], tail[-6:]))]
    if local and local[0]["model"]:
        toks.append(local[0]["model"])
    return sorted(dict.fromkeys(toks), key=lambda w: -len(w))[:2]


def web_candidates(c, d, ev, local):
    """([candidate], status): search the model words with the vendor and count the results that mention them."""
    vendor = (local[0]["vendor"] if local else "") or oui_vendor(c, d["mac"])[0]
    toks = model_tokens(d, ev, local)
    if not toks:
        return [], "nodata"
    out = []
    for tok in toks:
        res = web_lookup(c, f"{vendor} {tok}".strip())
        rel = [r for r in res if tok.lower() in (r["title"] + " " + r["snippet"]).lower()][:3]
        if rel:
            v = vendor.split()[0].lower() if vendor else ""
            score = len(rel) + (1 if v and any(v in (r["title"] + " " + r["snippet"]).lower() for r in rel) else 0)
            out.append({"vendor": vendor, "type": local[0]["type"] if local else "", "model": tok, "score": score, "confidence": conf(score),
                        "why": [f"web: {len(rel)} results mention {tok}"], "links": [{"title": r["title"][:90], "url": r["url"]} for r in rel]})
    return out, "ok"


def identify_devices(c, devs, web):
    """Fresh LAN evidence (mDNS, SSDP, ports, banners), local candidates, then the web if asked. The inventory is not changed."""
    collect_lan(c)
    sp = scan_ports(c)

    def probe_one(d):
        try:
            ports = d["ports"] if d["scanned_at"] else scan(d["ip"], sp)
            return ports, banners(d["ip"], ports), socket.gethostbyaddr(d["ip"])[0]
        except socket.herror:
            return d["ports"], banners(d["ip"], d["ports"]), ""
        except (OSError, subprocess.TimeoutExpired):  # nmap missing or the device does not answer
            return d["ports"], [], ""
    with ThreadPoolExecutor(8) as ex:
        probed = list(ex.map(probe_one, devs))
    res, web_down = [], ""
    for d, (ports, ban, host) in zip(devs, probed):
        if not d["scanned_at"] and ports:
            c.execute("UPDATE devices SET ports=?, scanned_at=datetime('now','localtime') WHERE id=?", (ports, d["id"]))
        store_banners(c, d["id"], ban)
        if host:
            store_evidence(c, d["id"], "rdns", [host])
        d = dict(c.execute("SELECT * FROM devices WHERE id=?", (d["id"],)).fetchone())
        ev, local, status = evidence(c, d["id"]), identify_local(c, d), "off"
        if web and web_down:
            status = web_down
        elif web:
            try:
                found, status = web_candidates(c, d, ev, local)
                for w in found:
                    m = next((x for x in local if x["vendor"].lower() == w["vendor"].lower() and (not x["model"] or x["model"].lower() == w["model"].lower())), None)
                    if m:
                        m["score"] += w["score"]
                        m["model"], m["confidence"], m["links"] = m["model"] or w["model"], conf(m["score"]), w["links"]
                        m["why"] += w["why"]
                    else:
                        local.append(w)
                local.sort(key=lambda x: -x["score"])
            except WebError as e:  # the engine refused or is down: do not ask it again for every device
                status = web_down = "unavailable: " + str(e)
        res.append({"id": d["id"], "name": d["name"], "model": d["model"], "web": status, "candidates": local[:3]})
    c.commit()
    return res


COLUMNS = {"name": ("name", "nome", "hostname", "host name", "device"), "ip": ("ip", "ip address", "address", "ipv4"),
           "mac": ("mac", "mac address", "hardware address", "mac_address"), "vendor": ("vendor", "produttore", "manufacturer"), "model": ("model", "modello"),
           "type": ("type", "tipo", "category", "categoria"), "notes": ("notes", "note"),
           "reserved": ("ip assignment", "assegnazione ip", "assignment", "reserved")}
ASSIGN_IN = {"0": 0, "dynamic": 0, "dinamico": 0, "1": 1, "reservation": 1, "2": 2, "static": 2, "fisso": 2, "fixed": 2}


def norm_mac(m):
    m = re.sub(r"[^0-9a-f]", "", m.lower())
    return ":".join(m[i:i + 2] for i in range(0, 12, 2)) if len(m) == 12 else ""


def import_rows(c, text):
    """Import a LANtern/generic CSV or an nmap XML (-oX). Known MACs are left untouched."""
    text = text.lstrip("\ufeff").strip()
    rows = []
    if text.startswith("<"):  # shortcut: ElementTree does not guard against hostile XML, fine for your own files
        for h in ET.fromstring(text).iter("host"):
            a = {x.get("addrtype"): x for x in h.iter("address")}
            n = h.find("hostnames/hostname")
            rows.append({"mac": a["mac"].get("addr", "") if "mac" in a else "", "ip": a["ipv4"].get("addr", "") if "ipv4" in a else "",
                         "name": n.get("name", "") if n is not None else "", "vendor": a["mac"].get("vendor", "") if "mac" in a else ""})
    else:
        sample = text.split("\n", 1)[0]
        rd = csv.reader(io.StringIO(text), delimiter=";" if sample.count(";") > sample.count(",") else ",")
        head = [h.strip().lower() for h in next(rd, [])]
        col = {k: next((head.index(n) for n in names if n in head), None) for k, names in COLUMNS.items()}
        if col["mac"] is None:
            raise ValueError("no MAC column found (expected a header such as 'MAC')")
        for r in rd:
            rows.append({k: r[i].strip() if i is not None and i < len(r) else "" for k, i in col.items()})
    keys = {k: k for k, in c.execute("SELECT key FROM categories")} | {l.lower(): k for k, l in c.execute("SELECT key, label FROM categories")}
    added = skipped = 0
    for r in rows:
        mac = norm_mac(r.get("mac", ""))
        ip = r.get("ip", "")
        try:
            ipaddress.IPv4Address(ip) if ip else None
        except ValueError:
            ip = ""
        if not mac:
            skipped += 1
            continue
        added += add_new(c, r.get("name", "")[:60], ip, mac, r.get("vendor", "")[:60], keys.get(r.get("type", "").lower(), ""),
                         r.get("notes", "")[:200], ASSIGN_IN.get(r.get("reserved", "").lower(), 0), r.get("model", "")[:80])
    c.commit()
    return {"read": len(rows), "added": added, "skipped": skipped}


def hash_pw(pw):
    salt = os.urandom(16)
    return f"scrypt$16384$8$1${salt.hex()}${hashlib.scrypt(pw.encode(), salt=salt, n=16384, r=8, p=1).hex()}"


def check_pw(stored, pw):
    try:
        _, n, r, p, salt, h = stored.split("$")
        got = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=len(h) // 2)
    except ValueError:
        return False
    return hmac.compare_digest(got.hex(), h)


DUMMY_HASH = hash_pw("dummy")  # checked for unknown users too, so the answer time does not reveal them


def login_ok(c, username, password):
    row = c.execute("SELECT hash FROM users WHERE username=?", (username,)).fetchone()
    return check_pw(row[0] if row else DUMMY_HASH, password) and bool(row)


def set_user(c, username, password):
    """One account: the login is on as soon as a user exists."""
    if not re.fullmatch(r"[\w.@-]{1,40}", username):
        raise ValueError("username: 1-40 letters, digits, . _ @ -")
    if not 8 <= len(password) <= 200:
        raise ValueError("password: 8 to 200 characters")
    c.execute("DELETE FROM users")
    c.execute("INSERT INTO users VALUES (?,?)", (username, hash_pw(password)))
    c.commit()
    SESSIONS.clear()  # every old session dies with the old password


def new_session(username):
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = (username, time.time() + SESSION_TTL)
    return token


def clean_rule(c, data):
    r = {k: str(data.get(k, "")).strip() for k in ("field", "pattern", "category")}
    if r["field"] not in FIELDS_RULE or not r["pattern"] or len(r["pattern"]) > 60:
        raise ValueError("invalid field or empty text (max 60 characters)")
    r["pattern"] = r["pattern"].lower()
    check_type(c, {"type": r["category"]})
    return r


def clean_cat(data):
    r = {k: str(data.get(k, "")).strip() for k in ("label", "icon", "color")}
    r["color"] = r["color"].lower()
    if not r["label"] or len(r["label"]) > 40:
        raise ValueError("category name required (max 40 characters)")
    if not re.fullmatch(r"[a-z0-9_-]{1,32}", r["icon"]):
        raise ValueError("invalid icon")
    if r["color"] and not re.fullmatch(r"#[0-9a-f]{6}", r["color"]):
        raise ValueError("invalid color (#rrggbb)")
    return r


def check_type(c, r):
    if not c.execute("SELECT 1 FROM categories WHERE key=?", (r["type"],)).fetchone():
        raise ValueError("category does not exist")
    return r


def check_look(icon, color):
    if icon and not re.fullmatch(r"[a-z0-9_-]{1,32}", icon):
        raise ValueError("invalid icon")
    if color and not re.fullmatch(r"#[0-9a-f]{6}", color):
        raise ValueError("invalid color (#rrggbb)")


def clean(data):
    r = {k: str(data.get(k, "")).strip() for k in FIELDS if k != "reserved"}
    r["mac"] = r["mac"].lower()
    r["reserved"] = int(data.get("reserved") or 0)
    if r["reserved"] not in (0, 1, 2):
        raise ValueError("invalid IP assignment")
    if not r["name"] or not MAC_RE.match(r["mac"]):
        raise ValueError("name and MAC (aa:bb:cc:dd:ee:ff) required")
    if r["ip"]:
        ipaddress.IPv4Address(r["ip"])
    r["color"] = r["color"].lower()
    r["model"] = r["model"][:80]
    check_look(r["icon"], r["color"])
    return r


class H(BaseHTTPRequestHandler):
    def send(self, code, body, ctype="application/json", filename=None, cookie=None):
        b = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("X-Content-Type-Options", "nosniff")
        if cookie is not None:
            self.send_header("Set-Cookie", f"lantern_session={cookie}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL if cookie else 0}")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def body(self):
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")

    def user(self):
        t = SimpleCookie(self.headers.get("Cookie", "")).get("lantern_session")
        s = SESSIONS.get(t.value) if t else None
        if s and s[1] > time.time():
            return s[0]
        if t:
            SESSIONS.pop(t.value, None)

    def route(self, method):
        path = self.path.split("?")[0]
        try:
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
            origin = self.headers.get("Origin")
            if (LOOPBACK and host not in ("localhost", "127.0.0.1", "::1")) or \
                    (method != "GET" and origin and origin.split("://", 1)[-1] != self.headers.get("Host")):
                return self.send(403, {"error": "forbidden host or origin"})
            c = db()
            has_login = bool(c.execute("SELECT 1 FROM users").fetchone())
            if has_login and path not in PUBLIC and not self.user():
                return self.send(401, {"error": "login required"})
            if method == "GET" and path == "/api/session":
                return self.send(200, {"login": has_login, "user": self.user(), "web": not NO_WEB, "first": not c.execute("SELECT 1 FROM meta WHERE key='discovered'").fetchone()})
            if method == "POST" and path == "/api/login":
                ip, (n, until) = self.client_address[0], FAILS.get(self.client_address[0], (0, 0))
                if until > time.time():
                    return self.send(429, {"error": "too many attempts, wait a minute"})
                b = self.body()
                if login_ok(c, str(b.get("username", "")), str(b.get("password", ""))):
                    FAILS.pop(ip, None)
                    return self.send(200, {"ok": True}, cookie=new_session(str(b["username"])))
                FAILS[ip] = (n + 1, time.time() + LOCK_SECONDS if n + 1 >= MAX_FAILS else 0)
                return self.send(401, {"error": "wrong username or password"})
            if method == "POST" and path == "/api/logout":
                t = SimpleCookie(self.headers.get("Cookie", "")).get("lantern_session")
                SESSIONS.pop(t.value, None) if t else None
                return self.send(200, {"ok": True}, cookie="")
            if path == "/api/account" and method in ("POST", "DELETE"):
                b = self.body()
                if has_login and not login_ok(c, self.user(), str(b.get("current", ""))):
                    return self.send(403, {"error": "current password is wrong"})
                if method == "DELETE":
                    c.execute("DELETE FROM users")
                    c.commit()
                    SESSIONS.clear()
                    return self.send(200, {"ok": True}, cookie="")
                u = str(b.get("username", "")).strip()
                set_user(c, u, str(b.get("password", "")))
                return self.send(200, {"ok": True}, cookie=new_session(u))
            if method == "GET" and path == "/":
                return self.send(200, (DIR / "index.html").read_bytes().replace(b"{{VERSION}}", VERSION.encode()).replace(b"{{AUTO}}", b"true" if AUTO_DISCOVER else b"false"), "text/html; charset=utf-8")
            if method == "GET" and path == "/logo.svg":
                return self.send(200, (DIR / "logo.svg").read_bytes(), "image/svg+xml")
            if method == "GET" and path in ("/api/export.csv", "/api/export.xlsx"):
                rows = export_rows(db(), "en" if "lang=en" in self.path else "it")
                if path.endswith("csv"):
                    return self.send(200, to_csv(rows), "text/csv; charset=utf-8", "lan_devices.csv")
                return self.send(200, to_xlsx(rows), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "lan_devices.xlsx")
            if method == "POST" and (path == "/api/scan" or re.fullmatch(r"/api/devices/\d+/scan", path)):
                c = db()
                if path == "/api/scan":  # bulk: ids chosen by the client
                    ids = [int(i) for i in self.body().get("ids", [])]
                else:
                    ids = [int(path.split("/")[3])]
                ports = scan_ports(c)
                devs = [d for d in c.execute(f"SELECT id, ip FROM devices WHERE ip != '' AND id IN ({','.join('?' * len(ids))})", ids)]
                if not devs:
                    return self.send(404, {"error": "device has no IP or does not exist"})
                with ThreadPoolExecutor(8) as ex:  # sqlite: threads read, the main thread writes
                    found = list(ex.map(lambda d: scan_one(d["ip"], ports), devs))
                res = []
                for d, (open_ports, ban) in zip(devs, found):
                    c.execute("UPDATE devices SET ports=?, scanned_at=datetime('now','localtime') WHERE id=?", (open_ports, d["id"]))
                    store_banners(c, d["id"], ban)
                    res.append(dict(c.execute("SELECT id, ports, scanned_at FROM devices WHERE id=?", (d["id"],)).fetchone()))
                c.commit()
                return self.send(200, res)
            if method == "POST" and (path == "/api/identify" or re.fullmatch(r"/api/devices/\d+/identify", path)):
                b = self.body()
                ids = [int(i) for i in b.get("ids", [])][:40] if path == "/api/identify" else [int(path.split("/")[3])]
                devs = [dict(r) for r in c.execute(f"SELECT * FROM devices WHERE ip != '' AND id IN ({','.join('?' * len(ids))})", ids)]
                if not devs:
                    return self.send(404, {"error": "device has no IP or does not exist"})
                return self.send(200, identify_devices(c, devs, bool(b.get("web")) and not NO_WEB))
            if path == "/api/search" and method in ("GET", "PUT"):
                if method == "PUT":
                    b = self.body()
                    e = str(b.get("engine", ""))
                    if e not in ENGINES:
                        return self.send(400, {"error": "unknown search engine"})
                    rows = {"search_engine": e, "search_url": str(b.get("url", "")).strip()[:500]}
                    if b.get("key"):  # absent or empty: keep the saved key
                        rows["search_key"] = str(b["key"]).strip()[:500]
                    for k, v in rows.items():
                        c.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (k, v))
                    c.commit()
                cf = engine_conf(c)
                return self.send(200, {"engine": cf["engine"], "url": cf["url"], "has_key": bool(cf["key"]), "searxng": SEARXNG_URL, "web": not NO_WEB})
            if path == "/api/search/test" and method == "POST":
                b = self.body()
                cf = engine_conf(c)
                cf = {"engine": str(b.get("engine", "")), "url": str(b.get("url", "")).strip(), "key": str(b.get("key") or cf["key"]).strip(), "test": True}
                if cf["engine"] not in ENGINES:
                    return self.send(400, {"error": "unknown search engine"})
                try:
                    res = web_lookup(c, "Raspberry Pi 4 Model B", cf)
                except WebError as e:
                    return self.send(200, {"ok": False, "error": str(e)})
                return self.send(200, {"ok": True, "n": len(res), "first": res[0]["title"][:90]})
            if path == "/api/ports" and method in ("GET", "PUT"):
                if method == "PUT":
                    p = clean_ports(self.body().get("ports", ""))
                    if p and p != SCAN_PORTS:
                        c.execute("INSERT OR REPLACE INTO meta VALUES ('scan_ports', ?)", (p,))
                    else:
                        c.execute("DELETE FROM meta WHERE key='scan_ports'")
                    c.commit()
                cur = scan_ports(c)
                return self.send(200, {"ports": cur, "default": SCAN_PORTS, "custom": cur != SCAN_PORTS, "max": MAX_PORTS})
            if path == "/api/backups" and method in ("GET", "POST"):
                if method == "POST":
                    bk_new(str(self.body().get("note", "")))
                return self.send(200, {"dir": str(bk_dir()), "items": bk_list()})
            if path == "/api/backups/upload" and method == "POST":
                n = int(self.headers.get("Content-Length", 0))
                if n > MAX_UPLOAD:
                    return self.send(413, {"error": "file too large (128 MB at most)"})
                note = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("note", [""])[0]
                bk_import(self.rfile.read(n), note)
                return self.send(200, {"dir": str(bk_dir()), "items": bk_list()})
            m = re.fullmatch(r"/api/backups/([^/]+?)(?:/(download|restore))?", path)
            if m:
                p, act = bk_path(m.group(1)), m.group(2)
                if method == "GET" and act == "download":
                    return self.send(200, p.read_bytes(), "application/vnd.sqlite3", p.name)
                if method == "POST" and act == "restore":
                    bk_restore(p.name)
                    return self.send(200, {"ok": True})
                if method == "PUT" and not act:
                    bk_note(p, self.body().get("note", ""))
                    return self.send(200, {"ok": True})
                if method == "DELETE" and not act:
                    p.unlink()
                    p.with_suffix(".txt").unlink(missing_ok=True)
                    return self.send(200, {"ok": True})
                return self.send(405, {"error": "method not allowed"})
            if method == "GET" and path == "/api/oui":
                return self.send(200, oui_info(db()))
            if method == "POST" and path == "/api/oui/update":
                c = db()
                urls = self.body().get("urls")
                oui_update(c, urls if isinstance(urls, list) else None)
                return self.send(200, oui_info(c))
            if method == "POST" and path == "/api/import":
                return self.send(200, import_rows(db(), str(self.body().get("text", ""))))
            if method == "POST" and path == "/api/discover":
                res = discover(c)
                c.execute("INSERT OR REPLACE INTO meta VALUES ('discovered', datetime('now','localtime'))")
                c.commit()
                return self.send(200, res)
            if method == "POST" and path == "/api/suggest":
                b = self.body()
                return self.send(200, suggest(db(), str(b.get("mac", "")), str(b.get("name", "")), str(b.get("ports", ""))))
            m = re.fullmatch(r"/api/rules(?:/(\d+))?", path)
            if m:
                c, rid = db(), m.group(1)
                if method == "GET" and not rid:
                    return self.send(200, [dict(r) for r in c.execute("SELECT * FROM rules ORDER BY id")])
                if method == "POST" and not rid:
                    r = clean_rule(c, self.body())
                    c.execute("INSERT INTO rules (field,pattern,category) VALUES (:field,:pattern,:category)", r)
                elif method == "PUT" and rid:
                    r = clean_rule(c, self.body())
                    c.execute("UPDATE rules SET field=:field, pattern=:pattern, category=:category WHERE id=:id", {**r, "id": rid})
                elif method == "DELETE" and rid:
                    c.execute("DELETE FROM rules WHERE id=?", (rid,))
                else:
                    return self.send(405, {"error": "method not allowed"})
                c.commit()
                return self.send(200, {"ok": True})
            m = re.fullmatch(r"/api/categories(?:/([a-z0-9_-]+))?", path)
            if m:
                c, key = db(), m.group(1)
                if method == "GET" and not key:
                    return self.send(200, [dict(r) for r in c.execute("SELECT key, label, icon, color FROM categories ORDER BY rowid")])
                if method == "POST" and not key:
                    r = clean_cat(self.body())
                    base = re.sub(r"[^a-z0-9]+", "-", r["label"].lower()).strip("-") or "cat"
                    key, n = base, 2
                    while c.execute("SELECT 1 FROM categories WHERE key=?", (key,)).fetchone():
                        key, n = f"{base}-{n}", n + 1
                    c.execute("INSERT INTO categories VALUES (?,?,?,?)", (key, r["label"], r["icon"], r["color"]))
                elif method == "PUT" and key:
                    r = clean_cat(self.body())
                    if not c.execute("UPDATE categories SET label=?, icon=?, color=? WHERE key=?", (r["label"], r["icon"], r["color"], key)).rowcount:
                        return self.send(404, {"error": "category does not exist"})
                elif method == "DELETE" and key:
                    n = c.execute("SELECT COUNT(*) FROM devices WHERE type=?", (key,)).fetchone()[0]
                    if n:
                        return self.send(409, {"error": f"{n} devices use this category: move them to another one first"})
                    c.execute("DELETE FROM categories WHERE key=?", (key,))
                    c.execute("DELETE FROM rules WHERE category=?", (key,))
                else:
                    return self.send(405, {"error": "method not allowed"})
                c.commit()
                return self.send(200, {"ok": True, "key": key})
            m = re.fullmatch(r"/api/devices/(\d+)/family", path)
            if m and method == "GET":
                vendor, others = family(db(), m.group(1))
                return self.send(200, {"vendor": vendor, "count": len(others), "names": [n for _, n in others]})
            m = re.fullmatch(r"/api/devices(?:/(\d+))?", path)
            if not m:
                return self.send(404, {"error": "not found"})
            did = m.group(1)
            c = db()
            if method == "GET" and not did:
                return self.send(200, devices_with_status(c))
            if method == "POST" and not did:
                r = check_type(c, clean(self.body()))
                c.execute("INSERT INTO devices (name,ip,mac,vendor,model,type,notes,reserved,icon,color) VALUES (:name,:ip,:mac,:vendor,:model,:type,:notes,:reserved,:icon,:color)", r)
            elif method == "PUT" and did:
                b = self.body()
                r = check_type(c, clean(b))
                c.execute("UPDATE devices SET name=:name,ip=:ip,mac=:mac,vendor=:vendor,model=:model,type=:type,notes=:notes,reserved=:reserved,icon=:icon,color=:color WHERE id=:id", {**r, "id": did})
                if b.get("family"):  # forced: also replaces a look the others already have
                    # category too: an empty icon or color means "the category one", so the others must share it
                    others = family(c, did)[1]
                    c.executemany("UPDATE devices SET type=?, icon=?, color=? WHERE id=?", [(r["type"], r["icon"], r["color"], i) for i, _ in others])
                    c.commit()
                    return self.send(200, {"ok": True, "family": len(others)})
            elif method == "DELETE" and did:
                c.execute("DELETE FROM devices WHERE id=?", (did,))
                c.execute("DELETE FROM evidence WHERE device_id=?", (did,))
            else:
                return self.send(405, {"error": "method not allowed"})
            c.commit()
            self.send(200, {"ok": True})
        except (OSError, subprocess.TimeoutExpired) as e:  # nmap missing, network or IEEE unreachable
            self.send(502, {"error": f"operation failed (is nmap installed? network?): {e}"})
        except sqlite3.IntegrityError:
            self.send(409, {"error": "MAC already present"})
        except (ValueError, json.JSONDecodeError, ET.ParseError, csv.Error) as e:
            self.send(400, {"error": str(e)})

    do_GET = lambda s: s.route("GET")
    do_POST = lambda s: s.route("POST")
    do_PUT = lambda s: s.route("PUT")
    do_DELETE = lambda s: s.route("DELETE")

    def log_message(self, *a):
        pass


def die(msg):  # a one-line reason: argparse would bury it under the whole usage text
    sys.exit(f"LANtern: error: {msg}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(prog="lantern", description="LANtern: LAN inventory and radar.")
    ap.add_argument("port_pos", nargs="?", type=int, metavar="PORT", help="HTTP port (same as --port)")
    ap.add_argument("-p", "--port", type=int, default=int(os.environ.get("LANTERN_PORT", 8099)), help="HTTP port (default 8099, or $LANTERN_PORT)")
    ap.add_argument("--host", default=os.environ.get("LANTERN_HOST", "127.0.0.1"), help="address to listen on (default 127.0.0.1, or $LANTERN_HOST; anything else needs a login)")
    ap.add_argument("--db", default=os.environ.get("LANTERN_DB", DB), help="SQLite file (default: lantern.db next to app.py, or $LANTERN_DB)")
    ap.add_argument("--subnet", action="append", default=[n for n in os.environ.get("LANTERN_SUBNET", "").replace(",", " ").split()], metavar="CIDR", help="subnet to sweep, repeatable (default: detected, or $LANTERN_SUBNET, space or comma separated; at most a /22 each)")
    ap.add_argument("--no-discover", action="store_true", default=os.environ.get("LANTERN_NO_DISCOVER", "").lower() in ("1", "true", "yes"), help="do not discover devices on first start ($LANTERN_NO_DISCOVER=1)")
    ap.add_argument("--no-web", action="store_true", default=os.environ.get("LANTERN_NO_WEB", "").lower() in ("1", "true", "yes"), help="never search the web to identify devices, and hide the button (=1)")
    ap.add_argument("--search-url", default=os.environ.get("LANTERN_SEARCH_URL") or SEARCH_URL, metavar="URL", help="search page used to identify devices, {q} is the query: HTML (DuckDuckGo) or JSON (SearXNG) (or )")
    ap.add_argument("--set-password", metavar="USER", help="create or replace the login user (asks for the password), then exit")
    ap.add_argument("--disable-login", action="store_true", help="remove the login user, then exit (lost password)")
    ap.add_argument("--version", action="version", version=f"LANtern {VERSION}")
    a = ap.parse_args()
    DB, SUBNETS, AUTO_DISCOVER, NO_WEB, SEARCH_URL = Path(a.db), a.subnet, not a.no_discover, a.no_web, a.search_url
    LOOPBACK = a.host in ("127.0.0.1", "localhost", "::1")
    if a.set_password:
        pw = getpass.getpass("Password: ")
        if pw != getpass.getpass("Repeat: "):
            die("the passwords differ")
        set_user(db(), a.set_password, pw)
        sys.exit(f"Login enabled for {a.set_password}")
    if a.disable_login:
        c = db()
        c.execute("DELETE FROM users")
        c.commit()
        sys.exit("Login disabled")
    user, pw = os.environ.get("LANTERN_USER", "").strip(), os.environ.get("LANTERN_PASSWORD", "")
    if user and pw:  # provisioning for containers: the environment wins over what was set in the UI
        c = db()
        if not login_ok(c, user, pw):
            try:
                set_user(c, user, pw)
            except ValueError as e:
                die(f"$LANTERN_USER / $LANTERN_PASSWORD: {e}")
    if not LOOPBACK and not db().execute("SELECT 1 FROM users").fetchone():
        die("--host outside this machine needs a login: run with --set-password USER first")
    for n in SUBNETS:
        if ipaddress.ip_network(n, strict=False).prefixlen < 22:
            die(f"--subnet {n}: too large, use /22 or smaller")
    port = a.port_pos or a.port
    print(f"LANtern {VERSION}: http://{a.host}:{port}", flush=True)
    ThreadingHTTPServer((a.host, port), H).serve_forever()
