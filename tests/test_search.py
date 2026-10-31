"""Search engines: request building, answer parsing, the key stays out of backups."""
import contextlib, json, sqlite3, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app

u, h = app.engine_request({"engine": "searxng", "url": "http://10.0.0.5:8888/search/", "key": ""}, "a b")
assert u == "http://10.0.0.5:8888/search?q=a+b&format=json", u
assert app.engine_request({"engine": "searxng", "url": "http://x:1", "key": ""}, "q")[0] == "http://x:1/search?q=q&format=json"
u, h = app.engine_request({"engine": "brave", "url": "", "key": "TOK"}, "pi")
assert h["X-Subscription-Token"] == "TOK" and "q=pi" in u
assert app.engine_request({"engine": "custom", "url": "https://s/?q={q}", "key": ""}, "a b")[0] == "https://s/?q=a+b"
assert app.engine_request({"engine": "ddg", "url": "ignored", "key": ""}, "x")[0].startswith("https://html.duckduckgo.com/")

b = json.dumps({"web": {"results": [{"title": "T", "url": "https://b/1", "description": "D"}]}})
assert app.parse_results(b) == [{"title": "T", "url": "https://b/1", "snippet": "D"}]
assert app.parse_results(json.dumps({"results": [{"title": "T", "url": "u", "content": "C"}]}))[0]["snippet"] == "C"

with tempfile.TemporaryDirectory() as d:
    app.DB = Path(d) / "lantern.db"
    with contextlib.closing(app.db()) as c:
        assert app.engine_conf(c)["engine"] == "ddg"
        c.execute("INSERT INTO meta VALUES ('search_engine','brave'),('search_key','SECRET')")
        c.commit()
        assert app.engine_conf(c)["key"] == "SECRET"
        try:
            app.web_lookup(c, "x", {"engine": "brave", "url": "", "key": ""})
            raise SystemExit("no key must fail")
        except app.WebError:
            pass
    name = app.bk_new("t")
    with contextlib.closing(sqlite3.connect(app.bk_path(name))) as x:
        assert not x.execute("SELECT 1 FROM meta WHERE key='search_key'").fetchone()
        assert x.execute("SELECT 1 FROM meta WHERE key='search_engine'").fetchone()
    app.bk_restore(name)
    with contextlib.closing(app.db()) as c:
        assert app.engine_conf(c)["key"] == "SECRET"  # a restore keeps the key
print("ok")
