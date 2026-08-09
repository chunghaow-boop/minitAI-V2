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
check("Only one file downloads automatically (browsers block the rest)",
      _p.count("first.click()") == 1)
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
hp = client().get("/health").get_json()
check("Health endpoint works", hp.get("ok") is True)
check("Health endpoint leaks no secrets",
      "GROQ" not in json.dumps(hp) and os.environ["GROQ_API_KEY"] not in json.dumps(hp))

# ------------------------------------------------------------ page content
page = h.data.decode()
check("Page states audio is uploaded",
      "an AI service in the United" in " ".join(page.split()))
check("Page discloses the transfer out of Malaysia",
      "outside Malaysia" in " ".join(page.split()))
check("Page offers a way to delete everything", 'id="wipeBtn"' in page)
_flat_page = " ".join(page.split())
check("Page is honest about where documents live",
      "copy stays on the server" in _flat_page
      and "that copy goes when the server sleeps" in _flat_page
      and "Save them somewhere you will find them again" in _flat_page)
check("Page points confidential users to the desktop version",
      "desktop version" in page and "never uploads" in page)
# Nothing may be FETCHED from the internet - no third-party script, stylesheet,
# font or image, so the page cannot leak who is reading it and works offline.
# A share link the user has to click is different in kind: it navigates only
# when someone chooses to send the minutes on. wa.me is the one allowed.
import re as _re
_tags = _re.findall(r'<(?:script|link|img|iframe|source|video|audio)\b[^>]*>', page, _re.I)
check("Page fetches nothing from the internet",
      not any(_re.search(r'https?://', t) for t in _tags))
_ext = set(_re.findall(r'https?://[^\s"\'<>()]+', page))
check("The only outbound link is the WhatsApp share",
      all(u.startswith("https://wa.me/") for u in _ext))

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

print("\n" + "=" * 46)
print(f"RESULT: {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("FAILURES:", FAIL)
    sys.exit(1)
print("ALL CLOUD CHECKS PASSED")
