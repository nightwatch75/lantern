"""Self-check for the per-device icon and color: python3 tests/test_look.py"""
import os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ["LANTERN_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
import app

app.SEED_FILE = app.DIR / "no-seed.json"
base = {"name": "x", "mac": "00:11:22:33:44:55"}
assert app.clean(base)["icon"] == "" and app.clean(base)["color"] == ""  # empty = category look
assert app.clean({**base, "icon": "camera", "color": "#E53935"})["color"] == "#e53935"
for bad in ({"icon": "no way!"}, {"color": "red"}, {"color": "#12345"}):
    try:
        app.clean({**base, **bad})
        raise SystemExit(f"expected ValueError for {bad}")
    except ValueError:
        pass
c = app.db()  # the columns exist on a fresh database
assert {"icon", "color"} <= {r[1] for r in c.execute("PRAGMA table_info(devices)")}
# family: same producer by OUI; a local MAC has none
c.execute("INSERT OR REPLACE INTO oui VALUES ('DC4F22', 'Espressif Inc.')")
ids = {}
for name, mac in (("a", "dc:4f:22:57:45:a7"), ("b", "dc:4f:22:57:66:18"), ("c", "00:11:22:33:44:55"), ("d", "da:47:32:44:ad:12")):
    ids[name] = c.execute("INSERT INTO devices (name, mac) VALUES (?, ?)", (name, mac)).lastrowid
vendor, others = app.family(c, ids["a"])
assert vendor == "Espressif Inc." and others == [(ids["b"], "b")]
assert app.family(c, ids["c"]) == ("", []) or app.family(c, ids["c"])[1] == []  # nobody else shares its producer
assert app.family(c, ids["d"]) == ("", [])  # locally administered
app.check_look("", "")
for bad in (("a b", ""), ("", "red")):
    try:
        app.check_look(*bad)
        raise SystemExit(f"expected ValueError for {bad}")
    except ValueError:
        pass
print("ok")
