"""Self-check for the importers: python3 test_import.py"""
import os, tempfile
os.environ["LANTERN_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
import app

app.SEED_FILE = app.DIR / "no-seed.json"  # never test against your own seed
c = app.db()
csv_text = "Name;IP;MAC;Vendor;Type;Status;IP assignment;Listening ports;Notes\nTv;192.168.1.5;AA-BB-CC-00-00-01;LG;TV;Online;Static;;n\nbad;;zz;;;;;;\n"
assert app.import_rows(c, csv_text) == {"read": 2, "added": 1, "skipped": 1}
d = dict(c.execute("SELECT * FROM devices WHERE mac='aa:bb:cc:00:00:01'").fetchone())
assert (d["mac"], d["type"], d["reserved"], d["ip"]) == ("aa:bb:cc:00:00:01", "tv", 2, "192.168.1.5")
assert app.import_rows(c, csv_text)["added"] == 0  # known MAC untouched
xml = '<nmaprun><host><address addr="192.168.1.9" addrtype="ipv4"/><address addr="B8:27:EB:00:00:09" addrtype="mac" vendor="Raspberry Pi"/><hostnames><hostname name="pi"/></hostnames></host><host><address addr="192.168.1.10" addrtype="ipv4"/></host></nmaprun>'
assert app.import_rows(c, xml) == {"read": 2, "added": 1, "skipped": 1}
assert c.execute("SELECT name, vendor FROM devices WHERE mac='b8:27:eb:00:00:09'").fetchone()[:] == ("pi", "Raspberry Pi")
try:
    app.import_rows(c, "a,b\n1,2")
    raise SystemExit("expected ValueError")
except ValueError:
    pass
print("ok")
