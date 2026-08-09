"""Security and behaviour tests for MinitAI Web.

These are the tests that matter for a public deployment: can one user reach
another user's meeting, can an unauthenticated visitor reach anything, does the
app fail shut when misconfigured. Run before every deploy.
"""
import io
import os
import sys
import types
import json
import time

os.environ["INVITE_CODES"] = "alpha-code-111,beta-code-222"
os.environ["MINITAI_SECRET"] = "test-secret-do-not-use-in-production"
os.environ["GROQ_API_KEY"] = "test-key"
os.environ["MINITAI_DATA"] = "/tmp/minitai_web_test"
os.environ["APPDATA"] = "/tmp/minitai_engine_test"   # keep engine data out of the repo
os.environ["MINITAI_DAILY_MINUTES"] = "240"

import shutil
shutil.rmtree("/tmp/minitai_web_test", ignore_errors=True)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS, FAIL = [], []
def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name, flush=True)

import app as A

def client():
    return A.app.test_client()

def signin(c, code="alpha-code-111"):
    return c.post("/login", json={"code": code})

# ---------------------------------------------------------------- auth
c = client()
check("Anonymous cannot upload", c.post("/upload").status_code == 401)
check("Anonymous cannot read a job", c.get("/job/anything").status_code == 401)
check("Wrong invite code is rejected",
      c.post("/login", json={"code": "not-a-code"}).status_code == 401)
check("Empty invite code is rejected",
      c.post("/login", json={"code": ""}).status_code == 401)
check("Valid invite code signs in", signin(c).status_code == 200)
check("/me reports signed in", c.get("/me").get_json()["signed_in"] is True)
c.post("/logout")
check("Logout clears the session", c.get("/me").get_json()["signed_in"] is False)

# fail shut when no invites are configured
_old = os.environ["INVITE_CODES"]
os.environ["INVITE_CODES"] = ""
check("No invite codes configured => closed, not open",
      client().post("/login", json={"code": "anything"}).status_code == 403)
os.environ["INVITE_CODES"] = _old

# ---------------------------------------------------- user isolation
a, b = client(), client()
signin(a, "alpha-code-111")
signin(b, "beta-code-222")
uid_a = A._user_id_for("alpha-code-111")
uid_b = A._user_id_for("beta-code-222")
check("Different invite codes get different identities", uid_a != uid_b)
check("Invite code is not recoverable from the id",
      "alpha-code-111" not in uid_a and len(uid_a) == 16)

# a file belonging to A
out_a = A.user_dir(uid_a, "out")
secret_name = "2026-08-09_10-00_minutes.docx"
with open(os.path.join(out_a, secret_name), "w") as f:
    f.write("CONFIDENTIAL MEETING OF USER A")

tok_a = A.make_token(uid_a, secret_name)
check("Owner can download with a valid token", a.get("/get/" + tok_a).status_code == 200)
check("Other user CANNOT use the owner's token", b.get("/get/" + tok_a).status_code == 403)
check("Anonymous CANNOT use a valid token", client().get("/get/" + tok_a).status_code == 403)

# the old local-app hole: guessing a filename
tok_forged = A.make_token(uid_b, secret_name)     # B signs A's filename
check("Guessing a filename does not reach another user's file",
      b.get("/get/" + tok_forged).status_code == 404)

# tampering
bad = tok_a[:-4] + "AAAA"
check("Tampered token is rejected", client().get("/get/" + bad).status_code == 403)
check("Garbage token is rejected", client().get("/get/notatoken").status_code == 403)
expired = A.make_token(uid_a, secret_name, ttl=-10)
check("Expired token is rejected", a.get("/get/" + expired).status_code == 403)

# path traversal through the token
trav = A.make_token(uid_a, "../../../../etc/passwd")
r = a.get("/get/" + trav)
check("Path traversal inside a signed token is contained", r.status_code == 404)

# ------------------------------------------------------------ jobs
A._set("job-of-a", uid=uid_a, state="done", progress=100, files={})
check("Owner can read their job", a.get("/job/job-of-a").status_code == 200)
check("Other user cannot read that job", b.get("/job/job-of-a").status_code == 404)
check("Job status never leaks internal paths",
      "audio" not in (a.get("/job/job-of-a").get_json() or {}))

# ------------------------------------------------------------ upload guards
check("Upload with no file is rejected",
      a.post("/upload", data={}, content_type="multipart/form-data").status_code == 400)
r = a.post("/upload", data={"audio": (io.BytesIO(b"x" * 4000), "notes.pdf")},
           content_type="multipart/form-data")
check("Unsupported file type is rejected", r.status_code == 400)
r = a.post("/upload", data={"audio": (io.BytesIO(b"x" * 10), "tiny.wav")},
           content_type="multipart/form-data")
check("Empty/corrupt file is rejected", r.status_code == 400)

# service not configured
_k = os.environ.pop("GROQ_API_KEY")
r = a.post("/upload", data={"audio": (io.BytesIO(b"x" * 4000), "m.wav")},
           content_type="multipart/form-data")
check("No API key => clear 503, not a crash", r.status_code == 503)
os.environ["GROQ_API_KEY"] = _k

# ------------------------------------------------------------ quota
ok, used = A.check_and_add_quota(uid_a, 100)
check("Quota accrues", ok and used == 100)
ok, _ = A.check_and_add_quota(uid_a, 500)
check("Quota blocks over-use", ok is False)
ok, _ = A.check_and_add_quota(uid_b, 10)
check("One user's quota does not affect another", ok is True)

# ------------------------------------------------------------ headers/health
h = client().get("/")
check("Home page renders", h.status_code == 200 and b"MinitAI" in h.data)
check("Clickjacking header set", h.headers.get("X-Frame-Options") == "DENY")
check("MIME sniffing disabled", h.headers.get("X-Content-Type-Options") == "nosniff")
check("CSP present", "default-src" in (h.headers.get("Content-Security-Policy") or ""))
check("Referrer suppressed", h.headers.get("Referrer-Policy") == "no-referrer")
hp = client().get("/health").get_json()
check("Health endpoint works", hp.get("ok") is True)
check("Health endpoint leaks no secrets",
      "GROQ" not in json.dumps(hp) and os.environ["GROQ_API_KEY"] not in json.dumps(hp))

# ------------------------------------------------------------ page content
page = h.data.decode()
check("Page states audio is uploaded", "sent to an AI service" in page)
check("Page states files are deleted", "removed after" in page)
check("Page points confidential users to the desktop version",
      "desktop version" in page and "never uploads" in page)
check("Page loads nothing from the internet", "http://" not in page and "https://" not in page)

# ---------------------------------------------- Groq request shape
# The first live deploy failed with HTTP 400 on BOTH json_schema and
# json_object: OpenAI-compatible JSON modes require the literal word "json"
# in the messages, and the rewritten system prompt had removed every mention.
import cloud as _cl2, json as _j2
_sent = []
class _FakeResp:
    status_code = 200
    def __init__(s, body): s._b = body
    def json(s):
        return {"choices": [{"message": {"content": _j2.dumps({"meeting_title": "T"})}}]}
def _cap(url, **kw):
    _sent.append(kw.get("json") or {})
    return _FakeResp(kw.get("json"))
_op3 = _cl2.requests.post
_cl2.requests.post = _cap
_okey = _cl2.get_key
_cl2.get_key = lambda d: "test-key"
_cl2._chat_model = "llama-3.3-70b-versatile"
try:
    _cl2.analyze("Mesyuarat bermula.", "/tmp",
                 "You write official meeting minutes.", A.engine.ANALYSIS_SCHEMA)
    _msgs = " ".join(m["content"] for m in _sent[0]["messages"])
    check("Groq request mentions 'json' (required by JSON mode)",
          "json" in _msgs.lower())
    check("Groq request names the required keys",
          "meeting_title" in _msgs and "action_items" in _msgs)
    check("Most-constrained response_format tried first",
          _sent[0].get("response_format", {}).get("type") == "json_schema")
finally:
    _cl2.requests.post = _op3
    _cl2.get_key = _okey

# A model that rejects json_schema must be retried, not abandoned
_calls2 = []
def _picky(url, **kw):
    b = kw.get("json") or {}
    _calls2.append((b.get("response_format") or {}).get("type"))
    if (b.get("response_format") or {}).get("type") == "json_schema":
        class _400:
            status_code = 400
            def json(s): return {"error": {"message": "response_format not supported"}}
        return _400()
    return _FakeResp(b)
_cl2.requests.post = _picky
_cl2.get_key = lambda d: "test-key"
try:
    _cl2.analyze("Mesyuarat.", "/tmp", "Minutes.", A.engine.ANALYSIS_SCHEMA)
    check(f"Falls back when a format is rejected ({_calls2})",
          _calls2[0] == "json_schema" and _calls2[1] == "json_object")
except Exception as _e:
    check(f"Falls back when a format is rejected ({_e})", False)
finally:
    _cl2.requests.post = _op3
    _cl2.get_key = _okey

# Prose or code fences around the JSON must not kill the meeting
class _Fenced:
    status_code = 200
    def json(s):
        return {"choices": [{"message": {"content":
                "Here you go:\n```json\n{\"meeting_title\": \"Ujian\"}\n```"}}]}
_cl2.requests.post = lambda url, **kw: _Fenced()
_cl2.get_key = lambda d: "test-key"
try:
    _r2 = _cl2.analyze("x", "/tmp", "y", A.engine.ANALYSIS_SCHEMA)
    check("Code-fenced JSON is still parsed", _r2.get("meeting_title") == "Ujian")
finally:
    _cl2.requests.post = _op3
    _cl2.get_key = _okey

print("\n" + "=" * 46)
print(f"RESULT: {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("FAILURES:", FAIL)
    sys.exit(1)
print("ALL CLOUD CHECKS PASSED")
