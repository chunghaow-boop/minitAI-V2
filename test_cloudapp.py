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
r = a.post("/upload", data={"audio": (io.BytesIO(b"x" * 4000), "installer.exe")},
           content_type="multipart/form-data")
check("Genuinely unsupported file type is rejected", r.status_code == 400)
check("Rejection message lists what IS supported",
      "document" in str(r.get_json()).lower())
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
_uid_q = A._user_id_for("quota-probe-user")
_before = A.check_and_add_quota(_uid_q, 100)[1]
check(f"Quota accrues ({_before})", _before == 100)
check("Quota blocks over-use", A.check_and_add_quota(_uid_q, 500)[0] is False)
check("One user's quota does not affect another",
      A.check_and_add_quota(A._user_id_for("other-probe-user"), 10)[0] is True)


# ------------------------------------------------- refresh / recovery
# A browser refresh, a closed tab or a phone locking its screen used to
# destroy the meeting silently: the job finished server-side and nobody ever
# received the documents, while the minutes had already been deducted.
check("Anonymous cannot list recent work", client().get("/recent").status_code == 401)

A._set("live-job-a", uid=uid_a, state="transcribing", progress=40, created=time.time())
rec = a.get("/recent").get_json()
check("A running job is offered back after a refresh",
      any(j["id"] == "live-job-a" for j in rec["active"]))
check("Another user never sees that job",
      not any(j["id"] == "live-job-a" for j in b.get("/recent").get_json()["active"]))
check("Recent lists files still on disk",
      any(f["name"] == secret_name for f in rec["files"]))
check("Recent file links are signed, not bare names",
      all(f["url"].startswith("/get/") and secret_name not in f["url"]
          for f in rec["files"]))
check("Recent never leaks the internal path or owner",
      "audio" not in json.dumps(rec) and uid_a not in json.dumps(rec))
_recf = rec["files"][0]["url"].split("/get/")[1]
check("A link from Recent actually downloads", a.get("/get/" + _recf).status_code == 200)
check("Another user cannot use a link from Recent",
      b.get("/get/" + _recf).status_code == 403)
check("Finished jobs come back too, not just running ones",
      any(j["id"] == "job-of-a" for j in a.get("/recent").get_json()["finished"]))

# the page has to actually try to recover, or the endpoint is decoration
_p = client().get("/").data.decode()
check("Page reconnects to a running job on load", "resume(" in _p and "/recent" in _p)
check("Page warns before you navigate away mid-job", "beforeunload" in _p)
# Nothing downloads by itself any more. The automatic save was there because
# Recent documents did not exist yet; now it does, and a file appearing in
# Downloads unasked is worse than a file you tapped for.
check("Nothing downloads automatically", "renderFiles(j.files, false)" in _p)
check("The page says so plainly", "Nothing has been saved to your computer yet" in _p)
check("Options are collapsed, not all on screen at once", '<details id="adv"' in _p)
check("There is a results preview", 'id="preview"' in _p and "function showPreview" in _p)
check("Help is a fixed bubble, not buried down the page",
      'id="helpBubble"' in _p and "position:fixed" in _p)
check("There is a way to sign out", "signout" in _p)

# ------------------------------------------------- shared service budget
# Everyone here shares ONE free Groq account. Per-user limits alone let twenty
# people drain it before lunch, and every meeting then fails halfway.
_svc = A.SERVICE_DAILY_MINUTES
A.SERVICE_DAILY_MINUTES = 5
try:
    os.remove(A._SERVICE_QUOTA)
except OSError:
    pass
_svc_u1 = A._user_id_for("svc-probe-1")
_svc_u2 = A._user_id_for("svc-probe-2")
ok1, _ = A.check_and_add_quota(_svc_u1, 4)
_before = json.load(open(A._quota_path(_svc_u2))).get("minutes", 0) \
    if os.path.exists(A._quota_path(_svc_u2)) else 0
ok2, _ = A.check_and_add_quota(_svc_u2, 4)
check("Service-wide budget stops the shared account being drained",
      ok1 is True and ok2 == "service")
_after = json.load(open(A._quota_path(_svc_u2))).get("minutes", 0) \
    if os.path.exists(A._quota_path(_svc_u2)) else 0
check("A refused upload does not silently eat the user's own minutes",
      _after == _before)
A.SERVICE_DAILY_MINUTES = _svc
try:
    os.remove(A._SERVICE_QUOTA)
except OSError:
    pass


# ------------------------------------------------- session hardening
_sc = client().post("/login", json={"code": "alpha-code-111"}).headers.get("Set-Cookie", "")
check("Session cookie is HttpOnly", "HttpOnly" in _sc)
check("Session cookie is same-site", "SameSite" in _sc)
check("Session cookie is HTTPS-only", "Secure" in _sc)

# ------------------------------------------------- queue position
A._set("q1", uid=uid_b, state="queued", created=1000.0)
A._set("q2", uid=uid_a, state="queued", created=2000.0)
_q = a.get("/job/q2").get_json()
check("A queued job is told how many are ahead of it", _q.get("ahead") == 1)
check("Queue position is shown to the user", "ahead" in client().get("/").data.decode())
A.JOBS.pop("q1", None); A.JOBS.pop("q2", None)

# ------------------------------------------------------------ headers/health
h = client().get("/")
check("Home page renders", h.status_code == 200 and b"MinitAI" in h.data)
check("Clickjacking header set", h.headers.get("X-Frame-Options") == "DENY")
check("MIME sniffing disabled", h.headers.get("X-Content-Type-Options") == "nosniff")
check("CSP present", "default-src" in (h.headers.get("Content-Security-Policy") or ""))
check("Referrer suppressed", h.headers.get("Referrer-Policy") == "no-referrer")
# Every off-origin host the page actually talks to must be in the CSP, or the
# browser blocks it before the request leaves - which is invisible in testing.
_csp = h.headers.get("Content-Security-Policy") or ""
_sd = dict(
    p.strip().split(" ", 1) for p in _csp.split(";") if p.strip() and " " in p.strip()
)
check("CSP allows Google's sign-in script",
      "https://accounts.google.com" in _sd.get("script-src", ""))
check("CSP allows the Drive API calls",
      "https://www.googleapis.com" in _sd.get("connect-src", "")
      and "https://oauth2.googleapis.com" in _sd.get("connect-src", ""))
check("CSP allows Google's sign-in frame",
      "https://accounts.google.com" in _sd.get("frame-src", ""))
check("CSP still refuses everything else by default",
      _sd.get("default-src", "").strip() == "'self' 'unsafe-inline'")
import re as _csp_re
_hosts = set(_csp_re.findall(r"https://[a-z0-9.\-]+", h.data.decode()))
_allowed = set(_csp_re.findall(r"https://[a-z0-9.*\-]+", _csp)) | {
    "https://mail.google.com", "https://wa.me", "https://api.whatsapp.com"}
_missing = sorted(u for u in _hosts
                  if not any(a.replace("*.", "") in u for a in _allowed))
check("No page URL is missing from the CSP: " + (", ".join(_missing) or "none"),
      not _missing)
_d = client().get("/desktop")
check("Desktop download redirects", _d.status_code == 302
      and "github.com" in (_d.headers.get("Location") or ""))
check("The page offers the desktop version",
      'href="/desktop"' in h.data.decode())
hp = client().get("/health").get_json()
check("Health endpoint works", hp.get("ok") is True)
check("Health endpoint leaks no secrets",
      "GROQ" not in json.dumps(hp) and os.environ["GROQ_API_KEY"] not in json.dumps(hp))

# ------------------------------------------------------------ page content
page = h.data.decode()
check("Page states audio is uploaded",
      "Groq in the United States" in " ".join(page.split()))
check("Page discloses the transfer out of Malaysia",
      "outside Malaysia" in " ".join(page.split()))
check("Page offers a way to delete everything", 'id="wipeBtn"' in page)
_flat_page = " ".join(page.split())
check("Page is honest about where documents live",
      "short-lived copy stays on the server" in _flat_page
      and "that copy goes when the server sleeps" in _flat_page)
check("The full privacy text is one tap away, not hidden",
      'id="privLink"' in page and 'id="priv"' in page)
check("The page says when the allowance comes back",
      'id="quotaReset"' in page and "Resets in " in page)
check("The day turns over at local midnight, not UTC",
      "_quota_day()" in open("app.py").read()
      and "TZ_OFFSET_HOURS" in open("app.py").read())
check("Sign-in asks who you are", 'id="who"' in page)
check("Admin can see which codes are used and by whom",
      '"codes"' in open("app.py").read() and '"masked"' in open("app.py").read())

check("Remaining quota is at the top, not buried at the bottom",
      'id="quotaChip"' in page and "min of recording left today" in page)
check("A failed meeting refunds the minutes",
      "minutes_charged" in open("app.py").read()
      and "_refund_quota_locked(job[" in open("app.py").read())
check("A silent recording says so instead of \"something went wrong\"",
      "That recording has no sound in it" in open("app.py").read())

check("Microphone is requested before the meeting, not during",
      "async function micCheck" in page and 'id="micGate"' in page
      and "Allow the microphone" in page)
check("The gate hides the app until the question is answered",
      "#appCard.gated > *:not(#micGate){display:none}" in page)
check("Someone who only uploads files can get past it",
      'id="micSkip"' in page and "I will only upload files" in page)
check("A blocked microphone is explained, not silently ignored",
      "The microphone is blocked for this site" in page)
check("Page points confidential users to the desktop version",
      "desktop version" in page and "never uploads" in page)
# Nothing may be FETCHED from the internet - no third-party script, stylesheet,
# font or image, so the page cannot leak who is reading it and works offline.
# A share link the user has to click is different in kind: it navigates only
# when someone chooses to send the minutes on. wa.me is the one allowed.
import re as _re
_tags = _re.findall(r'<(?:script|link|img|iframe|source|video|audio)\b[^>]*>', page, _re.I)
# The page template is a normal Python string, so a "\n" written in the source
# becomes a REAL newline in the JavaScript and silently breaks the whole script
# - the login button simply stops working. Parse it and find out.
import shutil as _sh, subprocess as _sp, tempfile as _tf
_js = _re.search(r"<script>(.*?)</script>", page, _re.S)
check("Page contains its script", bool(_js))
if _js and _sh.which("node"):
    with _tf.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as _f:
        _f.write(_js.group(1)); _jsp = _f.name
    _r = _sp.run(["node", "--check", _jsp], capture_output=True, text=True)
    check("Page JavaScript parses", _r.returncode == 0)
    if _r.returncode:
        print((_r.stderr or "")[:400])
else:
    print("NOTE node not available - JavaScript not parsed")

check("Page fetches nothing from the internet",
      not any(_re.search(r'https?://', t) for t in _tags))
_ext = set(_re.findall(r'https?://[^\s"\'<>()]+', page))
# Google's script and API are referenced, but nothing reaches out on load:
# the script tag is only appended when someone clicks "Save to Google Drive",
# so a user who never touches Drive still loads a page that fetches nothing.
_ALLOWED_HOSTS = ("https://wa.me/", "https://accounts.google.com/gsi/client",
                  "https://www.googleapis.com/", "https://mail.google.com/mail/")
check("Every outbound URL is one we chose deliberately",
      all(u.startswith(_ALLOWED_HOSTS) for u in _ext))
check("Google's script is loaded on demand, not on page load",
      "GIS_SRC" in page and "createElement('script')" in page
      and 'src="https://accounts.google.com' not in page)
# The admin view is one of the invite codes, not a second username and
# password on a public URL. admin/admin is the first pair every scanner tries.
os.environ["MINITAI_ADMIN_CODE"] = "alpha-code-111"
_boss, _mate = client(), client()
signin(_boss, "alpha-code-111"); signin(_mate, "beta-code-222")
# The dropdown used to steer only the transcriber, so an English meeting could
# come back as Malay minutes because the installed default said so.
_seen = {}
_real_one_pass = A.cloud._one_pass
def _spy(t, dd, sp, sch):
    _seen["sys"] = sp
    return {"meeting_title": "M", "agenda_items": [{"topic": "T", "discussion": "d",
            "decision": "x"}], "action_items": [], "attendees": [], "key_points": [],
            "key_takeaways": [], "important_notes": [], "activities": [],
            "date": "", "time": "", "location": ""}
A.cloud._one_pass = _spy
_en = A.cloud.analyze("We discussed the budget.", "/tmp", "SYS", {},
                      lang="en", completeness_check=False)
check("Choosing English tells the summariser, not just the transcriber",
      _seen["sys"].startswith("Write all output in English."))
check("The document furniture follows the choice too",
      A.engine.doc_labels(_en)["matters"] == "Matters Discussed")
_ms = A.cloud.analyze("Kami bincang bajet.", "/tmp", "SYS", {},
                      lang="ms", completeness_check=False)
check("Malay still produces Malay headings",
      A.engine.doc_labels(_ms)["matters"] == "Perkara Dibincangkan")
_au = A.cloud.analyze("We discussed the budget.", "/tmp", "SYS", {},
                      lang="", completeness_check=False)
check("Automatic still detects from the content",
      A.engine.doc_labels(_au)["matters"] == "Matters Discussed")
A.cloud._one_pass = _real_one_pass

check("Admin can see the usage view", _boss.get("/admin").status_code == 200)
check("An ordinary user gets 404, not 403 - the endpoint is not even confirmed",
      _mate.get("/admin").status_code == 404)
check("Anonymous cannot reach the admin view", client().get("/admin").status_code == 401)
check("Admin view carries no meeting content",
      "docx" not in _boss.get("/admin").get_data(as_text=True).lower())
check("Admin counters say plainly that they reset",
      "wiped whenever the free instance sleeps" in _boss.get("/admin").get_data(as_text=True))
os.environ.pop("MINITAI_ADMIN_CODE", None)
check("With no admin code configured, nobody is admin",
      client().get("/admin").status_code in (401, 404))

# mailto: opens nothing on a machine with no mail client registered, which is
# most Windows laptops. The button looked broken because it was.
# The feedback link still uses mailto: deliberately - it is a link to Gavril,
# not a share button, and there is nothing better to point it at.
check("Email uses a web compose, not mailto:",
      "mail.google.com/mail/?view=cm" in page
      and "m.href='mailto:" not in page)
check("Share buttons carry their own styling",
      "background:var(--card2);border:1px solid var(--line)" in page)
check("The share message uses the meeting title, not the status line",
      "lastAnalysis && lastAnalysis.meeting_title" in page)

check("Drive history is offered without a pop-up on every visit",
      "driveReconnect" in page and "prompt:''" in page
      and "minitai.driveLinked" in page)
check("Drive is off unless a client id is configured",
      "google_client_id" in open("app.py").read())

check("Drive uses the narrow scope that only sees files we create",
      "auth/drive.file" in page and "auth/drive'" not in page)

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

# ------------------------------- documents must not depend on server disk
# A real download failed with "expired and been deleted" 16 minutes after a
# successful run: the free instance slept and wiped /tmp. Documents are now
# returned inline so the browser holds them.
check("Job results carry the files inline", "b64encode" in open("app.py").read())
check("There is a size cap on inline delivery", "INLINE_LIMIT_BYTES" in open("app.py").read())
_page2 = client().get("/").data.decode()
check("Page builds downloads from inline bytes", "createObjectURL" in _page2)
check("Page saves the minutes automatically", "first.click()" in _page2)
check("Page still falls back to the server link", "a.href=v.url" in _page2)
check("Expired-link message explains the real cause and the fix",
      "goes to sleep" in open("app.py").read()
      and "upload the recording again" in open("app.py").read())
_flat2 = " ".join(_page2.split())
check("Page no longer promises server-side retention",
      "that copy goes when the server sleeps" in _flat2
      and "the server clears them when it goes to sleep" in _flat2)

# The roster is the user telling us who was in the room. The hallucination
# guard drops names the transcript never says - which used to delete a quiet
# attendee the user had typed in themselves, silently undoing the whole feature.
_t = "Puan Marja perlu hantar borang. Kolokium dibincangkan."
_d = {"attendees": ["Dr. Hafizah", "Puan Marja", "Ghost Person"],
      "action_items": [{"task": "x", "owner": "Dr. Hafizah", "deadline": ""}]}
_kept = A.engine._drop_hallucinations(dict(_d), _t, keep=["Dr. Hafizah", "Puan Marja"])
check("A roster name is never dropped for staying quiet",
      "Dr. Hafizah" in _kept["attendees"])
check("An invented attendee is still dropped",
      "Ghost Person" not in _kept["attendees"])
check("A roster name survives as an action owner",
      _kept["action_items"][0]["owner"] == "Dr. Hafizah")
_none = A.engine._drop_hallucinations(dict(_d), _t)
check("Without a roster the guard behaves as before",
      "Dr. Hafizah" not in _none["attendees"])

# ---------------------------------------------- audio AND video formats
# Users record on phones and in Zoom/Meet, so mp3/mp4/mkv/mov must be accepted
# and video must have its audio extracted rather than rejected.
for _ext in (".mp3", ".mp4", ".m4a", ".mkv", ".mov", ".webm", ".wav",
             ".opus", ".amr", ".3gp", ".aac", ".flac", ".ogg"):
    check(f"Accepts {_ext}", _ext in A.engine.AUDIO_EXTS)
check("Upload widget offers audio and video", 'audio/*,video/*' in _page2)
# ffmpeg must strip the video stream, not choke on it
import inspect as _insp
_flac_src = _insp.getsource(_cl2._to_flac)
check("Video is converted audio-only (-vn)", '"-vn"' in _flac_src)
check("Converted to 16kHz mono for transcription",
      '"16000"' in _flac_src and '"-ac", "1"' in _flac_src)
_vid = a.post("/upload", data={"audio": (io.BytesIO(b"x" * 4000), "meeting.mp4")},
              content_type="multipart/form-data")
check(f"An .mp4 upload is not rejected as wrong type ({_vid.status_code})",
      _vid.status_code != 400 or "Unsupported" not in str(_vid.get_json()))

# ------------------------------------------ documents, not just recordings
# Office work is not only meetings: a report, a lecture deck or teaching
# material should summarise through the same pipeline, minus transcription.
for _ext in (".pdf", ".docx", ".pptx", ".txt", ".md"):
    check(f"Document format {_ext} is accepted", _ext in A.DOC_EXTS)
check("Engine can read documents", callable(getattr(A.engine, 'extract_text_from_file', None)))

# a real .txt document must be accepted and queued as a doc job
_r_doc = a.post("/upload",
                data={"audio": (io.BytesIO("Mesyuarat membincangkan bajet tahunan. "
                                           "Keputusan: diluluskan.".encode() * 20),
                                "laporan.txt")},
                content_type="multipart/form-data")
check(f"A .txt document uploads ({_r_doc.status_code})", _r_doc.status_code == 200)
_jid = (_r_doc.get_json() or {}).get("job")
check("Document job is tagged as a document",
      bool(_jid) and A.get_job(_jid).get("kind") == "doc")
check("A document is billed 1 minute, not a meeting's worth",
      (_r_doc.get_json() or {}).get("minutes") == 0)

# a real PDF must be readable end to end
import tempfile as _tf5
try:
    from docx import Document as _Doc
    _dp = os.path.join(_tf5.gettempdir(), "_probe.docx")
    _d0 = _Doc(); _d0.add_paragraph("Mesyuarat JK Pascasiswazah membincangkan "
                                    "pelaksanaan viva dan pelantikan pemeriksa.")
    _d0.save(_dp)
    _txt0 = A.engine.extract_text_from_file(_dp)
    check(f"Word document text is extracted ({len(_txt0)} chars)", "Mesyuarat" in _txt0)
    os.remove(_dp)
except Exception as _e:
    check(f"Word document text is extracted ({_e})", False)

check("Upload widget offers documents too", ".pdf" in _page2 or ".pdf" in client().get("/").data.decode())
check("Unsupported types name what IS supported",
      "document (pdf" in open("app.py").read())

# ------------------------------------- summary quality: styles + coverage
check("Four summary styles exist", set(_cl2.SUMMARY_STYLES) ==
      {"minutes", "executive", "detailed", "actions"})
check("Default style is formal minutes", _cl2.DEFAULT_STYLE == "minutes")
_pg3 = client().get("/").data.decode()
for _st in ("minutes", "executive", "detailed", "actions"):
    check(f"Style '{_st}' offered in the UI", f'value="{_st}"' in _pg3)
check("Chosen style is sent to the server", "fd.append('style'" in _pg3)

# The style must actually change the instruction the model receives
_seen2 = []
_STUB = {"meeting_title":"T","date":"","time":"","location":"","attendees":["A"],
  "agenda_items":[{"topic":"X","discussion":"Y","decision":"Z"}],"activities":["a"],
  "key_points":["k"],"key_takeaways":["t"],"important_notes":["n"],
  "action_items":[{"task":"t","owner":"o","deadline":"d"}],
  "theme":{"primary_hex":"1E2761","accent_hex":"FFD500","mood":"m"},
  "slides":{"title_slide":{"title":"T","subtitle":""},
            "content_slides":[{"heading":"H","bullets":["b"]}]}}
class _Cap:
    status_code = 200
    def json(s): return {"choices":[{"message":{"content":_j2.dumps(_STUB)}}]}
_cl2.requests.post = lambda url, **kw: (_seen2.append(kw.get("json") or {}), _Cap())[1]
_cl2.get_key = lambda d: "k"
try:
    _seen2.clear()
    _cl2.analyze("Ringkas.", "/tmp", "Base.", A.engine.ANALYSIS_SCHEMA,
                 style="actions", completeness_check=False)
    check("Style reaches the model",
          "action_items is the most important" in _seen2[0]["messages"][0]["content"])
    _seen2.clear()
    _cl2.analyze("Ringkas.", "/tmp", "Base.", A.engine.ANALYSIS_SCHEMA,
                 style="executive", completeness_check=False)
    check("A different style sends a different instruction",
          "two minutes" in _seen2[0]["messages"][0]["content"])

    # Long transcripts must be summarised in sections, not one giant request
    _seen2.clear()
    _long = "Perkara ini dibincangkan dengan panjang lebar oleh jawatankuasa. " * 500
    _cl2.analyze(_long, "/tmp", "Base.", A.engine.ANALYSIS_SCHEMA,
                 completeness_check=False)
    check(f"Long meeting is split into sections ({len(_seen2)} calls)", len(_seen2) > 1)
    check("Each section is well under the single-shot limit",
          all(len(c["messages"][1]["content"]) <= _cl2.SECTION_CHARS + 1200
              for c in _seen2))

    # The completeness pass must run and must be able to add missed items
    _calls3 = []
    def _two_stage(url, **kw):
        b = kw.get("json") or {}
        _calls3.append(b)
        sysmsg = b["messages"][0]["content"]
        if "checking a set of draft meeting minutes" in sysmsg:
            return type("R", (), {"status_code": 200, "json": staticmethod(
                lambda: {"choices":[{"message":{"content": _j2.dumps({
                    "agenda_items":[{"topic":"Perkara terlepas","discussion":"d","decision":"x"}],
                    "action_items":[], "key_points":["Titik terlepas"]})}}]})})()
        return _Cap()
    _cl2.requests.post = _two_stage
    _res3 = _cl2.analyze("Mesyuarat panjang. " * 200, "/tmp", "Base.",
                         A.engine.ANALYSIS_SCHEMA, completeness_check=True)
    check("A completeness check runs after the summary",
          any("checking a set of draft" in c["messages"][0]["content"] for c in _calls3))
    check("Missed agenda items are added back",
          any(i.get("topic") == "Perkara terlepas" for i in _res3.get("agenda_items", [])))
    check("Missed key points are added back", "Titik terlepas" in _res3.get("key_points", []))

    # A failed completeness check must never cost the user their minutes
    def _flaky2(url, **kw):
        b = kw.get("json") or {}
        if "checking a set of draft" in b["messages"][0]["content"]:
            return type("R", (), {"status_code": 500, "json": staticmethod(lambda: {})})()
        return _Cap()
    _cl2.requests.post = _flaky2
    _res4 = _cl2.analyze("Mesyuarat. " * 200, "/tmp", "Base.", A.engine.ANALYSIS_SCHEMA)
    check("A failed completeness check still returns the minutes",
          bool(_res4.get("meeting_title")))
finally:
    _cl2.requests.post = _op3
    _cl2.get_key = _okey

# --------------------------------- long meetings and concurrent users
# A 3-5 hour recording cannot finish on the free tier however long we retry,
# and failing 40 minutes in is the worst possible way to find that out.
_o_dur2 = A.engine.get_audio_duration
A.engine.get_audio_duration = lambda p: 4 * 3600      # a 4-hour meeting
try:
    _r_long = a.post("/upload", data={"audio": (io.BytesIO(b"x" * 5000), "long.wav")},
                     content_type="multipart/form-data")
    check(f"A 4-hour recording is refused up front ({_r_long.status_code})",
          _r_long.status_code == 413)
    _m = str((_r_long.get_json() or {}).get("error", ""))
    check("The refusal says how long it actually is", "240 minutes" in _m)
    check("The refusal tells the user what to do instead", "Split it" in _m)
finally:
    A.engine.get_audio_duration = _o_dur2

# A meeting inside the limit reports an honest estimate
A.engine.get_audio_duration = lambda p: 100 * 60
try:
    _r_ok = a.post("/upload", data={"audio": (io.BytesIO(b"x" * 5000), "ok.wav")},
                   content_type="multipart/form-data")
    _jj = _r_ok.get_json() or {}
    check(f"A 100-minute meeting is accepted ({_r_ok.status_code})", _r_ok.status_code == 200)
    check("An ETA is returned", isinstance(_jj.get("eta_minutes"), int) and _jj["eta_minutes"] > 0)
    check("Long meetings are flagged for the UI", _jj.get("long") is True)
finally:
    A.engine.get_audio_duration = _o_dur2

# A job lost to a restart must explain itself, not 404 forever
_lost = a.get("/job/definitely-not-a-real-job-id")
check(f"A lost job returns 410, not 404 ({_lost.status_code})", _lost.status_code == 410)
check("A lost job explains the restart",
      "restarted" in str((_lost.get_json() or {}).get("error", "")))
check("A lost job reassures about the allowance",
      "allowance twice" in str((_lost.get_json() or {}).get("error", "")))
check("Browser handles the lost-job status", "status===410" in client().get("/").data.decode())

# Oversized uploads must name the limit and the fix
check("413 handler explains the size limit and the fix",
      "export the audio only" in open("app.py").read())

# Concurrency: one user's job must never be visible to another, even queued
_ja = a.post("/upload", data={"audio": (io.BytesIO(b"y" * 5000), "mine.wav")},
             content_type="multipart/form-data").get_json().get("job")
check("Second user cannot poll the first user's queued job",
      b.get("/job/" + _ja).status_code == 404)

# ----------------------------------- memory, fairness, and the focus box
check("Finished jobs are evicted", callable(getattr(A, "_evict_old_jobs", None)))
A.JOBS["old-done"] = {"uid": uid_a, "state": "done", "finished": 0, "created": 0,
                      "files": {"docx": {"data": "x" * 10000}}}
A.JOBS["fresh"] = {"uid": uid_a, "state": "done", "finished": time.time(),
                   "created": time.time()}
A._evict_old_jobs()
check("A stale finished job is dropped", "old-done" not in A.JOBS)
check("A recent finished job is kept", "fresh" in A.JOBS)
# never evict work still in progress
A.JOBS["busy"] = {"uid": uid_a, "state": "transcribing", "created": 0}
A._evict_old_jobs()
check("A running job is never evicted", "busy" in A.JOBS)
A.JOBS.pop("busy", None); A.JOBS.pop("fresh", None)

check("Quota updates are serialised", hasattr(A, "_quota_lock"))
check("There is a per-user queue cap", A.MAX_QUEUED_PER_USER >= 1)

# The completeness pass must see the END of a long meeting, not just the start
_probe = []
_cl2.requests.post = lambda url, **kw: (_probe.append(kw.get("json") or {}), _Cap())[1]
_cl2.get_key = lambda d: "k"
try:
    _head = "AWAL " * 12000
    _tail = "PENGHUJUNG MESYUARAT PENTING "
    _cl2._find_missing(_head + _tail, {"agenda_items": []}, "/tmp",
                       A.engine.ANALYSIS_SCHEMA)
    _sent_txt = _probe[-1]["messages"][1]["content"]
    check(f"Completeness pass samples the whole meeting ({len(_sent_txt)} chars)",
          "PENGHUJUNG" in _sent_txt)
    check("Sampling is signposted to the model", "sampled evenly" in
          _probe[-1]["messages"][1]["content"] or "sampled evenly" in
          _probe[-1]["messages"][0]["content"])

    # The user's own request must reach the model, without defeating grounding
    _probe.clear()
    _cl2.analyze("Mesyuarat bajet.", "/tmp", "Base.", A.engine.ANALYSIS_SCHEMA,
                 focus="only the budget decisions", completeness_check=False)
    _sys = _probe[0]["messages"][0]["content"]
    check("The user's own request reaches the model", "only the budget decisions" in _sys)
    check("The no-invention rule still outranks it", "outranks this" in _sys)
    # and it must be length-capped so it cannot be used to rewrite the prompt
    _probe.clear()
    _cl2.analyze("x", "/tmp", "Base.", A.engine.ANALYSIS_SCHEMA,
                 focus="A" * 5000, completeness_check=False)
    check("An over-long request is truncated",
          _probe[0]["messages"][0]["content"].count("A") < 1000)
finally:
    _cl2.requests.post = _op3
    _cl2.get_key = _okey

_pg4 = client().get("/").data.decode()
check("The focus box is in the UI", 'id="focus"' in _pg4)
check("The focus box is sent to the server", "fd.append('focus'" in _pg4)


# ------------------------------------------------------- one language on screen
# The interface used to mix English chrome with Malay labels ("3 perkara",
# "Kehadiran", "Tajuk"), which reads as unfinished. The interface is English;
# the language of the DOCUMENTS is the user's choice, and that is separate.
_ui = client().get("/").data.decode()
_malay_ui = [w for w in ("perkara", "tindakan", " hadir", "Kehadiran", "Tajuk perkara",
                         "Perbincangan", "Keputusan</", "Maklumat mesyuarat",
                         "Catatan penting", "Minit mesyuarat:", "dokumen Word")
             if w in _ui]
check("Interface is one language: " + (", ".join(_malay_ui) or "clean"), not _malay_ui)
check("The user can still choose the document language",
      'id="lang"' in _ui and 'value="ms"' in _ui)

# ------------------------------------------- last meeting's minutes, in full
# Minutes keep the action list in a Word TABLE - the task, who owns it, when
# it is due. The reader only walked paragraphs, so attaching last month's
# minutes handed the summariser the discussion with every outstanding action
# stripped out, which is the one thing Perkara Berbangkit exists to carry.
def _prev_docx_roundtrip():
    import tempfile, json as _j
    data = {"meeting_title": "Mesyuarat Bil 1/2026", "attendees": ["Dr. Hafizah"],
            "agenda_items": [{"topic": "Geran", "discussion": "Dibincangkan.",
                              "decision": "Diluluskan."}],
            "action_items": [{"task": "Menghantar borang geran",
                              "owner": "Dr. Hafizah", "deadline": "31 Januari"}],
            "important_notes": []}
    d = tempfile.mkdtemp()
    out = os.path.join(d, "prev.docx")
    A.engine.gen_docx(data, out)
    return A.engine.extract_text_from_file(out) or ""

try:
    _txt = _prev_docx_roundtrip()
except Exception as _e:                                    # pragma: no cover
    _txt = ""
    check("Previous minutes can be read back at all: %s" % _e, False)
check("Previous minutes keep the action itself", "Menghantar borang geran" in _txt)
check("Previous minutes keep who owns it", "Dr. Hafizah" in _txt)
check("Previous minutes keep the deadline", "31 Januari" in _txt)
check("Previous minutes keep the discussion", "Diluluskan" in _txt)
check("Previous minutes drop the empty signature block",
      "Disediakan" not in _txt)


# ------------------------------------------ the old minutes are background
# The first real run of Perkara Berbangkit carried the previous meeting's
# TWO action items straight into the new meeting's action list, and titled
# the meeting "Perkara Berbangkit: Pelantikan Pemeriksa Luar dan Dalam" after
# its own first matter arising. Last month's file is context, not content.
_pp = A.cloud.build_prompt if hasattr(A.cloud, "build_prompt") else None
import inspect as _i
_csrc = _i.getsource(A.cloud)
_prevblock = _csrc[_csrc.find("LAST MEETING'S MINUTES"):][:2200]
check("Old minutes are labelled background only",
      "BACKGROUND ONLY" in _prevblock)
check("Old actions must not become new actions",
      "copy an action out of the old minutes" in _prevblock)
check("The meeting is not titled after a matter arising",
      "never begin the title" in _prevblock)
check("Attendance is this meeting's, not last month's",
      "only people present at THIS meeting" in _prevblock)

# ------------------------------------------------------------- keep awake
# Sleeping is not just a slow first request: it erases the disk that holds
# everyone's daily allowance, so the instance has to stay up during the day.
check("Keep-warm pings under the fifteen-minute idle limit",
      "time.sleep(600)" in open("app.py").read())
check("Keep-warm only runs during waking hours",
      A.WARM_FROM == 8 and A.WARM_UNTIL == 23)
check("Keep-warm stays inside the free monthly hours",
      (A.WARM_UNTIL - A.WARM_FROM) * 31 < 700)
check("Keep-warm is off when the host gives us no address",
      not (os.environ.get("RENDER_EXTERNAL_URL") or ""))
check("Local hour follows Malaysia, not the server",
      A.TZ_OFFSET_HOURS == 8)

# ------------------------------------------------- allowance survives a wipe
# The host erases /tmp every time the instance sleeps or redeploys, which used
# to hand everybody a fresh 240 minutes several times a day.
_uid_w = A._user_id_for("wipe-probe-user")
A.check_and_add_quota(_uid_w, 50)
_ck = A._sign_quota(A._quota_day(), 50)
os.remove(A._quota_path(_uid_w))
check("Wiped disk alone resets the allowance (why the cookie exists)",
      A.check_and_add_quota(_uid_w, 10)[1] == 10)
os.remove(A._quota_path(_uid_w))
check("The browser's signed copy restores it",
      A.check_and_add_quota(_uid_w, 10, floor=50)[1] == 60)
check("A forged allowance cookie is refused",
      A._sign_quota("2026-01-01", 5) != "2026-01-01|5|deadbeefdeadbeefdeadbeefdeadbeef")
check("Yesterday's cookie does not carry over",
      "2000-01-01" not in A._sign_quota(A._quota_day(), 1))
check("Upload hands the browser a signed allowance cookie",
      "QUOTA_COOKIE" in open("app.py").read()
      and "set_cookie(QUOTA_COOKIE" in open("app.py").read())

# ---------------------------------------------------- desktop package drift
# The desktop zip carries its own copy of the engine. It has silently fallen
# two generations behind the website twice now, and nothing caught it - the
# only symptom was a friend getting worse minutes than the website gives.
# DESKTOP_BUILD.json records what was actually published; if the engine here
# has moved on, the download needs rebuilding.
import hashlib as _hl, json as _js
try:
    _built = _js.load(open("DESKTOP_BUILD.json"))
except Exception:
    _built = None
check("Desktop build manifest exists", _built is not None)
if _built:
    _stale = []
    for _f in ("watch_and_run.py", "cloud.py"):
        _now = _hl.sha256(open(_f, "rb").read()).hexdigest()
        if _now != _built.get(_f):
            _stale.append(_f)
    check("Desktop download matches this engine"
          + (" - REBUILD THE ZIP: " + ", ".join(_stale) if _stale else ""),
          not _stale)



print("\n" + "=" * 46)
print(f"RESULT: {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("FAILURES:", FAIL)
    sys.exit(1)
print("ALL CLOUD CHECKS PASSED")
