"""Self-check for the password hashing and user rules: python3 tests/test_auth.py"""
import os, tempfile
os.environ["LANTERN_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import app

app.SEED_FILE = app.DIR / "no-seed.json"
c = app.db()
h = app.hash_pw("correct horse")
assert h.startswith("scrypt$") and "correct horse" not in h and h != app.hash_pw("correct horse")  # salted
assert app.check_pw(h, "correct horse") and not app.check_pw(h, "wrong") and not app.check_pw("garbage", "x")
app.set_user(c, "max", "correct horse")
assert app.login_ok(c, "max", "correct horse") and not app.login_ok(c, "max", "nope") and not app.login_ok(c, "ghost", "correct horse")
app.set_user(c, "max2", "another pass 1")  # replaces the only user
assert [r[0] for r in c.execute("SELECT username FROM users")] == ["max2"]
for bad in (("a b", "longenough"), ("", "longenough"), ("max", "short")):
    try:
        app.set_user(c, *bad)
        raise SystemExit(f"expected ValueError for {bad}")
    except ValueError:
        pass
print("ok")
