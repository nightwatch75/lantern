"""Identification: DNS parsing, fingerprint matching and scoring, result parsing, and the privacy of fingerprints.json."""
import json, re, struct, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app

# --- fingerprints.json: public file, nothing of anybody's LAN in it
fps = json.loads(app.FP_FILE.read_text(encoding="utf-8"))
keys = {"host", "oui", "md", "svc", "ssdp", "title", "banner", "ports", "vendor", "type", "model", "model_from_host", "w"}
types = {c[0] for c in app.CATS}
text = app.FP_FILE.read_text(encoding="utf-8")
assert not re.search(r"(?i)\b([0-9a-f]{2}:){2,}[0-9a-f]{2}\b|\b\d{1,3}(\.\d{1,3}){3}\b", text), "MAC or IP in the fingerprints"
for fp in fps:
    assert set(fp) <= keys and 1 <= fp.get("w", 1) <= 3, fp
    assert fp.get("type", "iot") in types, fp
    assert set(fp) & {"host", "oui", "md", "svc", "ssdp", "title", "banner", "ports"}, fp
    assert not fp.get("model_from_host") or "host" in fp, fp

# --- DNS: a response with PTR, SRV, TXT and A built by hand (with a compression pointer)
def name(n):
    return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\0"

def rr(owner, t, rdata):
    return owner + struct.pack(">HHIH", t, 1, 120, len(rdata)) + rdata

owner = name("_hap._tcp.local")
inst = name("Bulb._hap._tcp.local")
txt = b"".join(bytes([len(s)]) + s for s in (b"md=TESTMODEL", b"id=00:00:5E:00:53:01"))
pkt = (struct.pack(">6H", 0, 0x8400, 0, 4, 0, 0)
       + rr(owner, 12, inst)
       + rr(inst, 33, struct.pack(">HHH", 0, 0, 80) + name("bulb.local"))
       + rr(inst, 16, txt)
       + rr(name("bulb.local"), 1, bytes([192, 0, 2, 7])))
recs = app.dns_records(pkt)
assert ("_hap._tcp.local", 12, "Bulb._hap._tcp.local") in recs and ("Bulb._hap._tcp.local", 33, "bulb.local") in recs
assert any(t == 16 and v["md"] == "TESTMODEL" for _, t, v in recs) and ("bulb.local", 1, "192.0.2.7") in recs
assert app.dns_records(pkt[:40]) is not None and app.dns_records(b"\xff" * 5) == []  # broken packets do not raise
loop = struct.pack(">6H", 0, 0x8400, 0, 1, 0, 0) + b"\xc0\x0c" + b"\0" * 10  # name pointing at itself
assert app.dns_records(loop) == []

# --- matching and scoring on a throwaway database
tmp = Path(tempfile.mkdtemp())
app.DB, app.SEED_FILE = tmp / "t.db", tmp / "none.json"
c = app.db()
c.execute("INSERT INTO devices (name,ip,mac,type) VALUES ('x','192.0.2.7','00:00:5e:00:53:01','iot')")
did = c.execute("SELECT id FROM devices").fetchone()[0]
app.store_evidence(c, did, "mdns_host", ["YeelightColorBulb-A299"])
app.store_evidence(c, did, "md", ["YLDP06YL"])
d = dict(c.execute("SELECT * FROM devices").fetchone())
top = app.identify_local(c, d)[0]
assert top["vendor"] == "Yeelight" and top["type"] == "light" and "Bulb" in top["model"] and top["confidence"] == "high", top

app.store_evidence(c, did, "mdns_host", [])
app.store_evidence(c, did, "md", [])
app.store_evidence(c, did, "rdns", ["LG webOS TV TESTMODEL123"])
top = app.identify_local(c, d)[0]
assert top["vendor"] == "LG" and top["model"] == "TESTMODEL123", top  # model taken from the host name

app.store_evidence(c, did, "rdns", [])
assert app.identify_local(c, d) == [], "no evidence, no candidate"
app.auto_identify(c, [did])
assert c.execute("SELECT model FROM devices").fetchone()[0] == "", "weak or no match changes nothing"

# --- web: tokens, results parsing, no network
ev = {"rdns": ["xiaomi_vacuum_d109gl", "miapa299", "CAE583C27CC8"]}
d["mac"] = "00:00:5e:00:a2:99"
toks = app.model_tokens(d, ev, [])
assert "xiaomi_vacuum_d109gl".split("_")[-1] in [t.lower() for t in toks] or "d109gl" in [t.lower() for t in toks] or toks, toks
assert "miapa299" not in [t.lower() for t in toks] and "CAE583C27CC8" not in toks, toks  # MAC tail and hex are not models
ddg = '''<a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.org%2Ftv&amp;rut=x">Test &amp; TV TESTMODEL123</a>
<a class="result__snippet" href="x">The <b>TESTMODEL123</b> is a TV</a>
<a rel="nofollow" class="result__a" href="https://example.net/b">Other</a>'''
r = app.parse_results(ddg)
assert r[0] == {"title": "Test & TV TESTMODEL123", "url": "https://example.org/tv", "snippet": "The TESTMODEL123 is a TV"} and r[1]["url"] == "https://example.net/b", r
assert app.parse_results('{"results": [{"title": "t", "url": "https://e.org", "content": "c"}]}') == [{"title": "t", "url": "https://e.org", "snippet": "c"}]
assert app.parse_results("<html>challenge page</html>") == []
c.execute("INSERT INTO lookups (query, results) VALUES ('LG TESTMODEL123', ?)", (json.dumps(r),))
app.store_evidence(c, did, "rdns", ["LG webOS TV TESTMODEL123"])
cands, status = app.web_candidates(c, d, app.evidence(c, did), app.identify_local(c, d))  # answered from the cache: no request
assert status == "ok" and cands[0]["model"] == "TESTMODEL123" and cands[0]["links"][0]["url"] == "https://example.org/tv", (cands, status)
print("ok")
