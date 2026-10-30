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
print("ok")
