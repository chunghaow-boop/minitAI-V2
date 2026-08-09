"""MinitAI Web - the hosted version.

Deliberately a SEPARATE app from the local web.py. The local app is correct for
one person on their own machine: no login, one global job lock, and any file in
the output folder downloadable by anyone who knows its name. Every one of those
is a confidentiality hole the moment the app is public, so this version does not
inherit them.

What it reuses: the document generators and the analysis schema from
watch_and_run.py, and the Groq engine from cloud.py. What it replaces: storage,
authentication, concurrency and download authorisation.

Design notes for whoever maintains this:
  * Free hosting has an EPHEMERAL disk. Files can vanish on restart, so nothing
    here assumes a document written now still exists in an hour.
  * The Groq key comes from the GROQ_API_KEY environment variable, never a file
    in the repo.
  * Each user gets an isolated directory. Downloads are authorised by a signed
    token, not by filename.
"""
import io
import os
import re
import json
import time
import queue
import shutil
import hmac
import base64
import hashlib
import logging
import secrets
import tempfile
import threading

from flask import (Flask, request, jsonify, send_file, session,
                   render_template_string, abort)

# --- shared engine --------------------------------------------------------
# watch_and_run.py and cloud.py live beside this file. They are copies of the
# desktop app's modules; when those change, copy them across and re-run the
# tests. MINITAI_ENGINE_DIR still works if you prefer a separate folder.
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_ENGINE = os.environ.get("MINITAI_ENGINE_DIR")
if _ENGINE:
    sys.path.insert(0, _ENGINE)
import watch_and_run as engine          # document generation + schema
import cloud                            # Groq transcription + summarisation

APP_VERSION = "web-1.0.0"

DATA_ROOT = os.environ.get("MINITAI_DATA", os.path.join(tempfile.gettempdir(), "minitai-web"))
os.makedirs(DATA_ROOT, exist_ok=True)

# Retention: a hosted notetaker should not sit on people's meetings. Files are
# deleted after this many hours whether or not the user downloaded them.
RETENTION_HOURS = int(os.environ.get("MINITAI_RETENTION_HOURS", "24"))
MAX_UPLOAD_MB = int(os.environ.get("MINITAI_MAX_UPLOAD_MB", "300"))
MAX_MINUTES_PER_USER_PER_DAY = int(os.environ.get("MINITAI_DAILY_MINUTES", "240"))
# Documents are returned inside the job result up to this total size, so the
# user still gets them after the free instance sleeps and clears its disk.
INLINE_LIMIT_BYTES = int(os.environ.get("MINITAI_INLINE_LIMIT_MB", "8")) * 1024 * 1024

# Documents, not just recordings. A PDF, a lecture deck or a Word report can be
# summarised with the SAME pipeline minus transcription - the engine already
# knows how to read them. Text-only jobs cost no transcription quota and finish
# in seconds.
DOC_EXTS = (".pdf", ".pptx", ".ppt", ".docx", ".txt", ".md")

# Groq's free tier allows roughly 2 hours of audio per rolling hour and about
# 8 hours per day. A 4-hour recording therefore CANNOT finish in one go - it
# will hit the cap halfway and fail after forty minutes of the user waiting.
# Refuse it up front, with a number and a way forward, instead of wasting
# their time and their daily allowance.
GROQ_AUDIO_SECONDS_PER_HOUR = int(os.environ.get("GROQ_ASH", "7200"))
LONG_MEETING_WARN_MINUTES = int(os.environ.get("MINITAI_WARN_MINUTES", "100"))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

# A stable secret keeps logins and download tokens valid across restarts.
# Without one set, sessions silently reset on every deploy.
_SECRET = os.environ.get("MINITAI_SECRET")
if not _SECRET:
    _SECRET = secrets.token_hex(32)
    logging.warning("MINITAI_SECRET is not set - logins reset on every restart")
app.secret_key = _SECRET

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")


# =========================================================================
# Access control - invite codes
# =========================================================================
def _invite_codes():
    """Codes from the INVITE_CODES env var, comma separated.

    No codes configured means the app is CLOSED, not open. Failing shut is the
    only safe default for something holding other people's meetings.
    """
    raw = os.environ.get("INVITE_CODES", "")
    return {c.strip() for c in raw.split(",") if c.strip()}


def _user_id_for(code):
    """A stable, non-reversible id per invite code, so one person's files are
    never mixed with another's and the code itself is never stored."""
    return hashlib.sha256((code + _SECRET).encode()).hexdigest()[:16]


def current_user():
    return session.get("uid")


def require_user():
    uid = current_user()
    if not uid:
        abort(401)
    return uid


def user_dir(uid, *parts):
    d = os.path.join(DATA_ROOT, "u_" + re.sub(r"[^a-f0-9]", "", uid)[:16], *parts)
    os.makedirs(d, exist_ok=True)
    return d


# =========================================================================
# Download authorisation - signed tokens, never bare filenames
# =========================================================================
def make_token(uid, filename, ttl=6 * 3600):
    exp = int(time.time()) + ttl
    payload = f"{uid}|{filename}|{exp}"
    sig = hmac.new(_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    raw = f"{payload}|{sig}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def read_token(tok):
    try:
        pad = "=" * (-len(tok) % 4)
        raw = base64.urlsafe_b64decode(tok + pad).decode()
        uid, filename, exp, sig = raw.split("|")
    except Exception:
        return None
    payload = f"{uid}|{filename}|{exp}"
    good = hmac.new(_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(good, sig):
        return None
    if int(exp) < time.time():
        return None
    return uid, filename


# =========================================================================
# Job queue - one worker, so a burst of uploads cannot exhaust the free tier
# =========================================================================
JOBS = {}
_jobs_lock = threading.Lock()
_work = queue.Queue()


def _set(job_id, **kw):
    with _jobs_lock:
        JOBS.setdefault(job_id, {}).update(kw)


def get_job(job_id):
    with _jobs_lock:
        return dict(JOBS.get(job_id) or {})


def _worker():
    while True:
        job_id = _work.get()
        try:
            _run_job(job_id)
        except Exception as e:                       # never kill the worker
            logging.exception("job failed")
            _set(job_id, state="error",
                 error="Something went wrong processing this meeting. "
                       "Please try again.", detail=type(e).__name__)
        finally:
            _work.task_done()


def _run_job(job_id):
    job = get_job(job_id)
    uid, audio_path = job["uid"], job["audio"]
    out = user_dir(uid, "out")
    try:
        if job.get("kind") == "doc":
            _set(job_id, state="reading", progress=30)
            dur = 0
            text = engine.extract_text_from_file(audio_path)
        else:
            _set(job_id, state="transcribing", progress=0)
            dur = engine.get_audio_duration(audio_path)

            def prog(i, n):
                _set(job_id, progress=int(i * 90 / max(1, n)))

            text = cloud.transcribe(audio_path, DATA_ROOT, engine._ffmpeg_exe(),
                                    language=job.get("lang") or None,
                                    prompt=job.get("hints") or None,
                                    duration=dur, progress=prog)
        _set(job_id, state="summarising", progress=92)
        data = cloud.analyze(text, DATA_ROOT, engine.SYSTEM_PROMPT,
                             engine.ANALYSIS_SCHEMA,
                             style=job.get("style") or cloud.DEFAULT_STYLE)
        if not engine._validate_analysis(data):
            raise RuntimeError("empty summary")
        data = engine._drop_hallucinations(data, text)

        _set(job_id, state="writing", progress=96)
        stamp = time.strftime("%Y-%m-%d_%H-%M")
        docx = os.path.join(out, f"{stamp}_minutes.docx")
        pptx = os.path.join(out, f"{stamp}_slides.pptx")
        txt = os.path.join(out, f"{stamp}_transcript.txt")
        engine.gen_docx(data, docx)
        engine.gen_pptx(data, pptx)
        with open(txt, "w", encoding="utf-8") as f:
            f.write(text)

        files = {}
        inline_budget = INLINE_LIMIT_BYTES
        for k, p in (("docx", docx), ("pptx", pptx), ("transcript", txt)):
            name = os.path.basename(p)
            entry = {"name": name,
                     "url": "/get/" + make_token(uid, name)}
            try:
                size = os.path.getsize(p)
                if size <= inline_budget:
                    with open(p, "rb") as fh:
                        entry["data"] = base64.b64encode(fh.read()).decode()
                    inline_budget -= size
            except OSError:
                pass
            files[k] = entry
        _set(job_id, state="done", progress=100, files=files,
             title=data.get("meeting_title", ""), minutes=int((dur or 0) / 60))
    finally:
        try:
            os.remove(audio_path)      # audio is never kept
        except OSError:
            pass


threading.Thread(target=_worker, daemon=True).start()


# =========================================================================
# Quota + retention
# =========================================================================
def _quota_path(uid):
    return os.path.join(user_dir(uid), "quota.json")


def check_and_add_quota(uid, minutes):
    today = time.strftime("%Y-%m-%d")
    p = _quota_path(uid)
    try:
        d = json.load(open(p))
    except Exception:
        d = {}
    if d.get("day") != today:
        d = {"day": today, "minutes": 0}
    if d["minutes"] + minutes > MAX_MINUTES_PER_USER_PER_DAY:
        return False, d["minutes"]
    d["minutes"] += minutes
    try:
        json.dump(d, open(p, "w"))
    except OSError:
        pass
    return True, d["minutes"]


def _reaper():
    """Delete everything older than RETENTION_HOURS. A hosted notetaker holding
    meetings forever is a liability, not a feature."""
    while True:
        cutoff = time.time() - RETENTION_HOURS * 3600
        try:
            for root, dirs, files in os.walk(DATA_ROOT):
                for f in files:
                    if f == "quota.json":
                        continue
                    p = os.path.join(root, f)
                    try:
                        if os.path.getmtime(p) < cutoff:
                            os.remove(p)
                    except OSError:
                        pass
        except Exception:
            logging.exception("reaper")
        time.sleep(3600)


threading.Thread(target=_reaper, daemon=True).start()


# =========================================================================
# Routes
# =========================================================================
@app.after_request
def _headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Content-Security-Policy"] = \
        "default-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    return r


@app.errorhandler(413)
def _too_big(e):
    return jsonify({"error":
        f"That file is larger than {MAX_UPLOAD_MB} MB. For a long meeting, "
        f"export the audio only (not the video) - an hour of audio is around "
        f"30 MB, while an hour of video can be over a gigabyte."}), 413


@app.route("/health")
def health():
    """For the host's uptime check. Reveals nothing about users."""
    return jsonify({"ok": True, "version": APP_VERSION,
                    "engine": bool(os.environ.get("GROQ_API_KEY")),
                    "invites_configured": bool(_invite_codes())})


@app.route("/login", methods=["POST"])
def login():
    code = (request.json or {}).get("code", "").strip()
    codes = _invite_codes()
    if not codes:
        return jsonify({"error": "This site is not accepting sign-ins yet."}), 403
    # Constant-time compare against every code, so response timing cannot be
    # used to discover a valid one.
    ok = False
    for c in codes:
        if hmac.compare_digest(c, code):
            ok = True
            break
    if not ok:
        time.sleep(1.0)          # slow down guessing
        return jsonify({"error": "That invite code is not valid."}), 401
    session["uid"] = _user_id_for(code)
    session.permanent = True
    return jsonify({"ok": True})


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/me")
def me():
    uid = current_user()
    if not uid:
        return jsonify({"signed_in": False})
    today = time.strftime("%Y-%m-%d")
    try:
        q = json.load(open(_quota_path(uid)))
        used = q.get("minutes", 0) if q.get("day") == today else 0
    except Exception:
        used = 0
    return jsonify({"signed_in": True, "used_minutes": used,
                    "daily_limit": MAX_MINUTES_PER_USER_PER_DAY,
                    "retention_hours": RETENTION_HOURS})


@app.route("/upload", methods=["POST"])
def upload():
    uid = require_user()
    if not os.environ.get("GROQ_API_KEY"):
        return jsonify({"error": "The service is not configured yet. "
                                 "Please contact the administrator."}), 503
    f = request.files.get("audio")
    if not f or not f.filename:
        return jsonify({"error": "No audio file received."}), 400
    ext = os.path.splitext(f.filename)[1].lower()
    is_doc = ext in DOC_EXTS
    if not is_doc and ext not in engine.AUDIO_EXTS:
        return jsonify({"error": f"Unsupported file type: {ext}. Upload a "
                                 f"recording (mp3, mp4, m4a, wav...) or a "
                                 f"document (pdf, docx, pptx, txt)."}), 400

    inbox = user_dir(uid, "in")
    safe = f"{int(time.time())}_{secrets.token_hex(4)}{ext}"
    path = os.path.join(inbox, safe)
    f.save(path)
    if os.path.getsize(path) < 1024:
        os.remove(path)
        return jsonify({"error": "That file is empty or corrupt."}), 400

    # A document has no duration; charge it a single minute so one person
    # cannot upload a thousand PDFs, but do not bill it like a long meeting.
    dur = 0 if is_doc else (engine.get_audio_duration(path) or 0)
    # A recording longer than the provider's hourly allowance can never
    # complete, however patiently we retry. Say so now.
    if not is_doc and dur > GROQ_AUDIO_SECONDS_PER_HOUR:
        os.remove(path)
        return jsonify({"error":
            f"That recording is {int(dur / 60)} minutes long, which is more "
            f"than the free service can transcribe in one go "
            f"(about {GROQ_AUDIO_SECONDS_PER_HOUR // 60} minutes). "
            f"Split it into two halves and upload them separately - the "
            f"minutes for each half will still be complete."}), 413

    ok, used = check_and_add_quota(uid, 1 if is_doc else (int(dur / 60) or 1))
    if not ok:
        os.remove(path)
        return jsonify({"error": f"You have used {used} of your "
                                 f"{MAX_MINUTES_PER_USER_PER_DAY} minutes today. "
                                 f"The allowance resets at midnight."}), 429

    job_id = secrets.token_urlsafe(12)
    _set(job_id, uid=uid, audio=path, kind=("doc" if is_doc else "audio"),
         state="queued", progress=0,
         lang=(request.form.get("lang") or "").strip(),
         style=(request.form.get("style") or cloud.DEFAULT_STYLE).strip(),
         hints=(request.form.get("hints") or "").strip()[:400],
         created=time.time())
    _work.put(job_id)
    mins = int(dur / 60)
    # Roughly a quarter of real time end to end, plus a floor for short files.
    eta = max(1, round(mins / 4)) if mins else 1
    return jsonify({"job": job_id, "queued_ahead": max(0, _work.qsize() - 1),
                    "minutes": mins, "eta_minutes": eta,
                    "long": mins >= LONG_MEETING_WARN_MINUTES})


@app.route("/job/<job_id>")
def job_status(job_id):
    uid = require_user()
    j = get_job(job_id)
    if not j:
        # Jobs live in memory. A free instance that restarts loses them, and
        # the browser would otherwise poll a 404 forever with no explanation.
        return jsonify({"state": "lost",
                        "error": "The server restarted while this was being "
                                 "processed, so it was lost. Please upload "
                                 "again - it will not count against your "
                                 "allowance twice."}), 410
    if j.get("uid") != uid:               # never confirm another user's job
        return jsonify({"error": "Not found"}), 404
    return jsonify({k: v for k, v in j.items() if k not in ("uid", "audio")})


@app.route("/get/<token>")
def get_file(token):
    """Downloads are authorised by a signed token tied to the user, not by
    filename. In the local app any known filename was downloadable - harmless
    for one person, a data leak the moment there are twenty."""
    parsed = read_token(token)
    if not parsed:
        return "Link expired or invalid", 403
    uid, filename = parsed
    if current_user() != uid:
        return "Not yours", 403
    full = os.path.join(user_dir(uid, "out"), os.path.basename(filename))
    if not os.path.exists(full):
        return ("This link has expired. The free server clears its storage when "
                "it goes to sleep, so finished documents do not live here for "
                "long. Please upload the recording again - it only takes a "
                "minute, and your browser downloads the files immediately when "
                "they are ready."), 404
    return send_file(full, as_attachment=True)


@app.route("/")
def index():
    return render_template_string(PAGE, signed_in=bool(current_user()),
                                  retention=RETENTION_HOURS)


PAGE = """<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MinitAI</title>
<style>
:root{--bg:#0A0E1A;--card:#151B2C;--card2:#1A2236;--line:#252E44;--txt:#E8ECF5;
--muted:#8B94A9;--blue:#4C82F7;--green:#34D399;--amber:#FBBF24;--red:#F87171;
--f:'Segoe UI Variable Text','Segoe UI',system-ui,-apple-system,Roboto,Arial,sans-serif;
--fd:'Segoe UI Variable Display','Segoe UI Semibold','Segoe UI',system-ui,Arial,sans-serif;}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font-family:var(--f);min-height:100vh;
padding:20px;display:flex;justify-content:center}
.wrap{width:100%;max-width:620px}
h1{font-family:var(--fd);font-size:26px;letter-spacing:-.5px;margin-bottom:4px}
.sub{color:var(--muted);font-size:14px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px;margin-bottom:16px}
label{display:block;font-size:13px;color:var(--muted);margin:12px 0 6px}
input,select{width:100%;background:var(--card2);color:var(--txt);border:1px solid var(--line);
border-radius:10px;padding:12px;font-size:15px;font-family:var(--f)}
button{width:100%;background:var(--blue);color:#fff;border:0;border-radius:11px;
padding:14px;font-size:15px;font-weight:600;font-family:var(--f);cursor:pointer;margin-top:14px}
button:disabled{opacity:.5;cursor:not-allowed}
#drop{border:2px dashed var(--line);border-radius:12px;padding:34px 16px;text-align:center;
color:var(--muted);cursor:pointer;font-size:14px}
#drop.on{border-color:var(--blue);color:var(--txt)}
.bar{height:6px;background:var(--card2);border-radius:6px;overflow:hidden;margin-top:14px}
.bar>i{display:block;height:100%;width:0;background:var(--blue);transition:width .4s}
a.file{display:block;background:var(--card2);border:1px solid var(--line);border-radius:10px;
padding:13px;margin-top:9px;color:var(--txt);text-decoration:none;font-size:14px}
a.file:hover{border-color:var(--blue)}
.msg{font-size:13px;margin-top:12px;line-height:1.5}
.err{color:var(--red)} .ok{color:var(--green)} .warn{color:var(--amber)}
.note{font-size:12px;color:var(--muted);line-height:1.6;margin-top:14px}
.hide{display:none}
</style></head><body><div class="wrap">
<h1>MinitAI</h1>
<div class="sub">Meeting audio in. Professional minutes out.</div>

<div class="card {{ 'hide' if signed_in else '' }}" id="loginCard">
  <label for="code">Invite code</label>
  <input id="code" type="password" autocomplete="one-time-code" placeholder="Enter your invite code">
  <button id="loginBtn">Sign in</button>
  <div class="msg err hide" id="loginMsg"></div>
</div>

<div class="card {{ '' if signed_in else 'hide' }}" id="appCard">
  <div id="drop">Tap to choose a file &mdash; or drop it here<br>
    <span style="font-size:12px">
      <b>Recording</b>: mp3, mp4, m4a, wav, mov, mkv, phone voice memos &mdash;
      video has its audio pulled out automatically.<br>
      <b>Document</b>: pdf, docx, pptx, txt &mdash; summarise a report, a lecture
      deck or teaching material. No recording needed.</span></div>
  <input id="file" type="file" class="hide"
         accept="audio/*,video/*,.pdf,.docx,.pptx,.ppt,.txt,.md">

  <label for="lang">Language spoken in the meeting</label>
  <select id="lang">
    <option value="">Detect automatically</option>
    <option value="ms" selected>Malay / Manglish</option>
    <option value="en">English</option>
    <option value="zh">Mandarin</option>
    <option value="ta">Tamil</option>
  </select>

  <label for="style">What kind of document do you want?</label>
  <select id="style">
    <option value="minutes" selected>Formal minutes &mdash; full official record</option>
    <option value="executive">Executive summary &mdash; decisions and consequences only</option>
    <option value="detailed">Detailed report &mdash; capture everything, nothing left out</option>
    <option value="actions">Action list &mdash; who does what, by when</option>
  </select>

  <label for="hints">Names and acronyms (optional, helps spelling)</label>
  <input id="hints" placeholder="e.g. UMS, FSSK, Dr Aminah, Bil 1/2026">

  <button id="go" disabled>Choose a recording first</button>
  <div class="bar hide" id="barWrap"><i id="bar"></i></div>
  <div class="msg" id="msg"></div>
  <div id="files"></div>
  <div class="note" id="quota"></div>
  <div class="note">Your audio is sent to an AI service to be processed, then
    deleted. Your documents are handed straight to your browser and are not
    stored on the server, so save them somewhere you will find them again.
    For confidential meetings, use the desktop version, which never uploads
    anything.</div>
</div>
<script>
const $=i=>document.getElementById(i);
let file=null, poll=null;

async function api(u,o){const r=await fetch(u,o);let j={};try{j=await r.json()}catch(e){}
  return {ok:r.ok,status:r.status,j};}

$('loginBtn').onclick=async()=>{
  const code=$('code').value.trim(); if(!code)return;
  $('loginBtn').disabled=true;
  const {ok,j}=await api('/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({code})});
  $('loginBtn').disabled=false;
  if(ok){$('loginCard').classList.add('hide');$('appCard').classList.remove('hide');loadMe();}
  else{$('loginMsg').textContent=j.error||'Sign in failed.';$('loginMsg').classList.remove('hide');}
};
$('code').addEventListener('keydown',e=>{if(e.key==='Enter')$('loginBtn').click();});

$('drop').onclick=()=>$('file').click();
$('drop').ondragover=e=>{e.preventDefault();$('drop').classList.add('on');};
$('drop').ondragleave=()=>$('drop').classList.remove('on');
$('drop').ondrop=e=>{e.preventDefault();$('drop').classList.remove('on');pick(e.dataTransfer.files[0]);};
$('file').onchange=e=>pick(e.target.files[0]);
function pick(f){if(!f)return;file=f;
  $('drop').innerHTML=f.name+'<br><span style="font-size:12px">'+(f.size/1048576).toFixed(1)+' MB</span>';
  $('go').disabled=false;$('go').textContent='Make the minutes';}

$('go').onclick=async()=>{
  if(!file)return;
  $('go').disabled=true;$('files').innerHTML='';
  $('msg').className='msg';$('msg').textContent='Uploading\\u2026';
  $('barWrap').classList.remove('hide');$('bar').style.width='4%';
  const fd=new FormData();fd.append('audio',file);
  fd.append('lang',$('lang').value);fd.append('hints',$('hints').value);
  fd.append('style',$('style').value);
  const {ok,j}=await api('/upload',{method:'POST',body:fd});
  if(!ok){fail(j.error||'Upload failed.');return;}
  $('msg').textContent=j.queued_ahead>0
    ? 'Waiting \\u2014 '+j.queued_ahead+' meeting(s) ahead of yours\\u2026'
    : 'Processing\\u2026 about '+Math.max(1,Math.round(j.minutes/4))+' min';
  poll=setInterval(()=>check(j.job),2500);
};
function fail(t){clearInterval(poll);$('msg').className='msg err';$('msg').textContent=t;
  $('barWrap').classList.add('hide');$('go').disabled=false;}

const NICE={queued:'Waiting in the queue\\u2026',transcribing:'Listening to the recording\\u2026',
  summarising:'Writing the summary\\u2026',writing:'Building your documents\\u2026'};
async function check(id){
  const {ok,j,status}=await api('/job/'+id);
  if(status===410){fail(j.error||'That job was lost. Please upload again.');return;}
  if(!ok){fail('Lost track of that job. Please try again.');return;}
  if(j.progress!=null)$('bar').style.width=Math.max(4,j.progress)+'%';
  if(j.state==='error'){fail(j.error||'Something went wrong.');return;}
  if(j.state==='done'){
    clearInterval(poll);
    $('msg').className='msg ok';
    $('msg').textContent='Done'+(j.title?' \\u2014 '+j.title:'');
    const L={docx:'Word document (.docx)',pptx:'Slides (.pptx)',transcript:'Full transcript (.txt)'};
    const MIME={docx:'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                pptx:'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                transcript:'text/plain'};
    $('files').innerHTML='';
    Object.entries(j.files||{}).forEach(([k,v])=>{
      const a=document.createElement('a');
      a.className='file'; a.download=v.name; a.textContent='Download '+L[k];
      if(v.data){
        // Held in the browser, not on the server. Survives the server sleeping.
        const bin=atob(v.data); const buf=new Uint8Array(bin.length);
        for(let i=0;i<bin.length;i++)buf[i]=bin.charCodeAt(i);
        a.href=URL.createObjectURL(new Blob([buf],{type:MIME[k]||'application/octet-stream'}));
      } else { a.href=v.url; }
      $('files').appendChild(a);
    });
    $('files').insertAdjacentHTML('beforeend',
      '<div class="note">Saved to your downloads automatically. '
      +'These files are not kept on the server.</div>');
    // Save immediately - the user may not click for another hour, by which
    // time a free instance has slept and cleared everything.
    Object.entries(j.files||{}).forEach(([k,v],i)=>{
      if(!v.data)return;
      const a=$('files').children[i];
      setTimeout(()=>{try{a.click();}catch(e){}}, 300*(i+1));
    });
    $('go').disabled=false;loadMe();return;
  }
  $('msg').textContent=NICE[j.state]||'Working\\u2026';
}
async function loadMe(){const {j}=await api('/me');
  if(j.signed_in)$('quota').textContent='Used '+j.used_minutes+' of '+j.daily_limit+' minutes today.';}
if(!$('appCard').classList.contains('hide'))loadMe();
</script></div></body></html>"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
