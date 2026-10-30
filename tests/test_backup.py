"""Backups, restore and the scan port list, on a throwaway database."""
import sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app

tmp = Path(tempfile.mkdtemp())
app.DB, app.SEED_FILE = tmp / "t.db", tmp / "none.json"

for bad in ("0", "70000", "22,abc", "5-3", "1-2000"):
    try:
        app.clean_ports(bad)
        raise SystemExit(f"accepted {bad}")
    except ValueError:
        pass
assert app.clean_ports(" 22, 80 ,8000-8100,") == "22,80,8000-8100" and app.clean_ports("") == ""

c = app.db()
assert app.scan_ports(c) == app.SCAN_PORTS
c.execute("INSERT INTO devices (name,mac) VALUES ('a','00:00:5e:00:53:01')")
app.set_user(c, "u", "password1")
c.commit()
name = app.bk_new("first")
with app.contextlib.closing(app.sqlite3.connect(app.bk_path(name))) as x:
    assert not x.execute("SELECT 1 FROM sqlite_master WHERE name='users'").fetchone(), "login must not be in a backup"
assert app.bk_list()[0]["note"] == "first"

c.execute("INSERT INTO devices (name,mac) VALUES ('b','00:00:5e:00:53:02')")
c.execute("DELETE FROM categories")
c.commit()
app.bk_restore(name)
c = app.db()
assert [r[0] for r in c.execute("SELECT name FROM devices")] == ["a"]
assert c.execute("SELECT COUNT(*) FROM categories").fetchone()[0] > 0
assert c.execute("SELECT 1 FROM users").fetchone(), "restore must keep the login"
assert len(app.bk_list()) == 2, "restore takes an automatic backup first"

for bad in ("../x.db", "lantern-1.db", "lantern-20250101-000000.db"):
    try:
        app.bk_path(bad)
        raise SystemExit(f"accepted {bad}")
    except ValueError:
        pass
try:
    app.bk_import(b"not a database")
    raise SystemExit("imported garbage")
except ValueError:
    pass
n2 = app.bk_import(app.bk_path(name).read_bytes(), "from file")
assert n2 != name and app.bk_list()[0]["note"] == "from file"
print("ok")
