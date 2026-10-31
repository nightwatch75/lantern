"""First-run discovery flag: a seed must not hide it, an older database must not trigger it."""
import sqlite3, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app

tmp = Path(tempfile.mkdtemp())
flags = lambda c: [r[0] for r in c.execute("SELECT key FROM meta WHERE key IN ('discovered','fresh')")]

app.SEED_FILE = tmp / "seed.json"
app.SEED_FILE.write_text('[["R","192.0.2.1","00:00:5e:00:53:01","","router","",0]]')
app.DB = tmp / "new.db"
for _ in range(3):  # every request opens the database again
    c = app.db()
assert flags(c) == ["fresh"] and c.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1

app.DB = tmp / "old.db"
x = sqlite3.connect(app.DB)
x.execute("CREATE TABLE devices (id INTEGER PRIMARY KEY, name TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '', mac TEXT NOT NULL UNIQUE, vendor TEXT NOT NULL DEFAULT '', type TEXT NOT NULL DEFAULT 'iot', notes TEXT NOT NULL DEFAULT '', reserved INTEGER NOT NULL DEFAULT 0)")
x.execute("INSERT INTO devices (name,mac) VALUES ('a','00:00:5e:00:53:09')")
x.commit()
x.close()
assert flags(app.db()) == ["discovered"]
print("ok")
