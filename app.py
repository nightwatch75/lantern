#!/usr/bin/env python3
"""LANtern: LAN inventory and radar (standard library only). Usage: python3 app.py [port]"""
import argparse, getpass, hashlib, hmac, secrets, time, csv, io, ipaddress, json, os, re, socket, sqlite3, subprocess, sys, urllib.request, uuid, zipfile
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = "0.8.0"
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
FIELDS = ("name", "ip", "mac", "vendor", "type", "notes", "reserved", "icon", "color")  # icon, color: look of this device, empty = the category one
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
    c.execute("CREATE TABLE IF NOT EXISTS rules (id INTEGER PRIMARY KEY, field TEXT NOT NULL, pattern TEXT NOT NULL, category TEXT NOT NULL)")
    if not c.execute("SELECT 1 FROM rules").fetchone():
        c.executemany("INSERT INTO rules (field,pattern,category) VALUES (?,?,?)", RULES)
    if not c.execute("SELECT 1 FROM oui").fetchone() and OUI_SYSTEM.exists():
        with open(OUI_SYSTEM, encoding="utf-8", errors="replace") as fh:
            c.executemany("INSERT OR IGNORE INTO oui VALUES (?,?)", re.findall(r"^([0-9A-F]{6})\s+\(base 16\)\s+(.+?)\s*$", fh.read(), re.M))
        c.execute("INSERT OR REPLACE INTO meta VALUES ('oui_source', 'system database'), ('oui_updated', datetime('now','localtime'))")
    c.commit()
    for col in ("ports", "scanned_at", "icon", "color"):  # migration from versions without these columns
        if col not in [r[1] for r in c.execute("PRAGMA table_info(devices)")]:
            c.execute(f"ALTER TABLE devices ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
    if not c.execute("SELECT 1 FROM devices").fetchone():
        c.executemany("INSERT INTO devices (name,ip,mac,vendor,type,notes,reserved) VALUES (?,?,?,?,?,?,?)", json.loads(SEED_FILE.read_text()) if SEED_FILE.exists() else [])
        c.commit()
    return c


SCAN_PORTS = ("21,22,23,25,53,80,81,110,111,123,135,139,143,161,443,445,515,554,631,993,1080,1883,1900,3000,3306,"
              "3389,5000,5001,5005,5006,5353,5555,5900,6668,7000,8000,8008,8009,8080,8081,8443,8883,8888,9000,9100,"
              "9999,10001,49152,55443,62078")


def scan(ip):
    """Known TCP ports listening, e.g. '22/ssh,80/http'. Needs nmap (connect scan, no root)."""
    ipaddress.IPv4Address(ip)
    out = subprocess.run(["nmap", "-Pn", "-sT", "-n", "-T4", "--max-retries", "1", "--host-timeout", "40s",
                          "-p", SCAN_PORTS, "-oG", "-", ip], capture_output=True, text=True, timeout=60).stdout
    return ",".join(f"{p}/{n}" for p, n in re.findall(r"(\d+)/open/tcp//([^/]*)/", out))


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


EXPORT_HEAD = {"it": ["Nome", "IP", "MAC", "Produttore", "Tipo", "Stato", "Assegnazione IP", "Porte in ascolto", "Note"],
               "en": ["Name", "IP", "MAC", "Vendor", "Type", "Status", "IP assignment", "Listening ports", "Notes"]}
ASSIGN = {"it": ["Dinamico", "Reservation", "Fisso"], "en": ["Dynamic", "Reservation", "Static"]}
STATUS = {"it": {"on": "Online", "off": "Offline", "conflict": "MAC diverso", None: "N/D"},
          "en": {"on": "Online", "off": "Offline", "conflict": "MAC mismatch", None: "N/A"}}


def export_rows(c, lang="it"):
    labels = dict(c.execute("SELECT key, label FROM categories"))
    return [EXPORT_HEAD[lang]] + [[d["name"], d["ip"], d["mac"], d["vendor"], labels.get(d["type"], d["type"]), STATUS[lang][d["status"]],
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


def add_new(c, name, ip, mac, vendor="", type="", notes="", reserved=0):
    """Insert a device unless its MAC is already known; vendor and category come from OUI and rules when missing."""
    s = suggest(c, mac, name, "")
    return c.execute("INSERT OR IGNORE INTO devices (name,ip,mac,vendor,type,notes,reserved) VALUES (?,?,?,?,?,?,?)",
                     (name or s["vendor"] or f"Device {ip}", ip, mac, vendor or s["vendor"], type or s["category"] or "iot", notes, reserved)).rowcount


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
    added = sum(add_new(c, names[mac], ip, mac) for mac, ip in found.items())
    c.commit()
    return {"found": len(found), "added": added}


COLUMNS = {"name": ("name", "nome", "hostname", "host name", "device"), "ip": ("ip", "ip address", "address", "ipv4"),
           "mac": ("mac", "mac address", "hardware address", "mac_address"), "vendor": ("vendor", "produttore", "manufacturer"),
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
                         r.get("notes", "")[:200], ASSIGN_IN.get(r.get("reserved", "").lower(), 0))
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
                return self.send(200, {"login": has_login, "user": self.user()})
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
                devs = [d for d in c.execute(f"SELECT id, ip FROM devices WHERE ip != '' AND id IN ({','.join('?' * len(ids))})", ids)]
                if not devs:
                    return self.send(404, {"error": "device has no IP or does not exist"})
                with ThreadPoolExecutor(8) as ex:  # sqlite: threads read, the main thread writes
                    found = list(ex.map(lambda d: scan(d["ip"]), devs))
                res = []
                for d, ports in zip(devs, found):
                    c.execute("UPDATE devices SET ports=?, scanned_at=datetime('now','localtime') WHERE id=?", (ports, d["id"]))
                    res.append(dict(c.execute("SELECT id, ports, scanned_at FROM devices WHERE id=?", (d["id"],)).fetchone()))
                c.commit()
                return self.send(200, res)
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
                return self.send(200, discover(db()))
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
                c.execute("INSERT INTO devices (name,ip,mac,vendor,type,notes,reserved,icon,color) VALUES (:name,:ip,:mac,:vendor,:type,:notes,:reserved,:icon,:color)", r)
            elif method == "PUT" and did:
                b = self.body()
                r = check_type(c, clean(b))
                c.execute("UPDATE devices SET name=:name,ip=:ip,mac=:mac,vendor=:vendor,type=:type,notes=:notes,reserved=:reserved,icon=:icon,color=:color WHERE id=:id", {**r, "id": did})
                if b.get("family"):  # forced: also replaces a look the others already have
                    # the page sends the look as it shows it (category values filled in), so the others end up looking the same
                    look = b.get("family_look") or {}
                    icon, color = str(look.get("icon", r["icon"])).strip(), str(look.get("color", r["color"])).strip().lower()
                    check_look(icon, color)
                    others = family(c, did)[1]
                    c.executemany("UPDATE devices SET icon=?, color=? WHERE id=?", [(icon, color, i) for i, _ in others])
                    c.commit()
                    return self.send(200, {"ok": True, "family": len(others)})
            elif method == "DELETE" and did:
                c.execute("DELETE FROM devices WHERE id=?", (did,))
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
    ap.add_argument("--set-password", metavar="USER", help="create or replace the login user (asks for the password), then exit")
    ap.add_argument("--disable-login", action="store_true", help="remove the login user, then exit (lost password)")
    ap.add_argument("--version", action="version", version=f"LANtern {VERSION}")
    a = ap.parse_args()
    DB, SUBNETS, AUTO_DISCOVER = Path(a.db), a.subnet, not a.no_discover
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
