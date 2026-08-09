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
# The site is served over HTTPS by the host. Marking the cookie secure stops a
# stray http:// link ever putting someone's session on the wire in clear, and
# HttpOnly keeps it out of reach of any script that manages to run on the page.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("MINITAI_INSECURE_COOKIES") != "1",
)

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
# Finished jobs hold base64 copies of the Word, PowerPoint and transcript
# files. Kept forever on a 512 MB instance that is a slow memory leak, so old
# jobs are evicted once the browser has had a fair chance to collect them.
JOBS = {}
JOB_TTL_SECONDS = int(os.environ.get("MINITAI_JOB_TTL", "1800"))   # 30 minutes
MAX_JOBS_RETAINED = int(os.environ.get("MINITAI_MAX_JOBS", "60"))
_jobs_lock = threading.Lock()
_work = queue.Queue()
# A queue nobody can flood: one person cannot park fifty meetings ahead of
# everyone else.
MAX_QUEUED_PER_USER = int(os.environ.get("MINITAI_MAX_QUEUED", "3"))


def _evict_old_jobs():
    """Drop finished jobs that are past their TTL, and cap the total kept."""
    now = time.time()
    with _jobs_lock:
        for jid in [j for j, v in JOBS.items()
                    if v.get("state") in ("done", "error", "lost")
                    and now - v.get("finished", now) > JOB_TTL_SECONDS]:
            JOBS.pop(jid, None)
        if len(JOBS) > MAX_JOBS_RETAINED:
            oldest = sorted(JOBS.items(),
                            key=lambda kv: kv[1].get("created", 0))
            for jid, _v in oldest[:len(JOBS) - MAX_JOBS_RETAINED]:
                JOBS.pop(jid, None)


def _set(job_id, **kw):
    if kw.get("state") in ("done", "error"):
        kw.setdefault("finished", time.time())
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
            try:
                _evict_old_jobs()
            except Exception:
                pass


def _seed(job):
    """What the transcriber is told to expect: the hint words and the roster.

    Correcting a name here, before transcription, works far better than trying
    to repair it afterwards - the decoder simply picks the spelling it was
    given.
    """
    bits = [(job.get("hints") or "").strip()]
    roster = (job.get("roster") or "").strip()
    if roster:
        bits.append(", ".join(x.strip() for x in roster.splitlines() if x.strip()))
    return ", ".join(b for b in bits if b)[:800]


def _package(uid, pairs):
    """Turn generated files into the payload the browser downloads from.

    Small files travel inline as base64 so they survive the server sleeping;
    the signed URL is the fallback for anything too big to inline.
    """
    files = {}
    inline_budget = INLINE_LIMIT_BYTES
    for k, p in pairs:
        name = os.path.basename(p)
        entry = {"name": name, "url": "/get/" + make_token(uid, name)}
        try:
            size = os.path.getsize(p)
            if size <= inline_budget:
                with open(p, "rb") as fh:
                    entry["data"] = base64.b64encode(fh.read()).decode()
                inline_budget -= size
        except OSError:
            pass
        files[k] = entry
    return files


def _run_job(job_id):
    job = get_job(job_id)
    uid, audio_path = job["uid"], job["audio"]
    out = user_dir(uid, "out")
    segments = []          # timings, when the source was audio rather than a document
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
                                    prompt=_seed(job) or None,
                                    duration=dur, progress=prog,
                                    segments_out=segments)
        _set(job_id, state="summarising", progress=92)
        data = cloud.analyze(text, DATA_ROOT, engine.SYSTEM_PROMPT,
                             engine.ANALYSIS_SCHEMA,
                             style=job.get("style") or cloud.DEFAULT_STYLE,
                             focus=job.get("focus") or "",
                             roster=job.get("roster") or "")
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
            # Timings make the transcript checkable against the recording
            # instead of something you have to take on trust.
            if segments:
                for at, line in segments:
                    f.write(f"[{int(at) // 60:02d}:{int(at) % 60:02d}] {line}\n")
            else:
                f.write(text)

        files = _package(uid, (("docx", docx), ("pptx", pptx), ("transcript", txt)))
        # The analysis goes back with the documents so the browser can show it
        # for editing and ask for a rebuild without paying for the meeting
        # twice. Keeping it client-side also means a server restart cannot
        # strand a correction half-made.
        _set(job_id, state="done", progress=100, files=files, analysis=data,
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


# Every invited person shares ONE free Groq account. Twenty people each
# allowed 240 minutes is 4,800 minutes a day against a free tier worth roughly
# 480 - so without this the account dies mid-afternoon and everyone's meeting
# fails halfway through with a rate-limit error. Refuse politely at the door
# instead, while there is still a whole allowance left tomorrow.
SERVICE_DAILY_MINUTES = int(os.environ.get("MINITAI_SERVICE_DAILY_MINUTES", "400"))
_SERVICE_QUOTA = os.path.join(DATA_ROOT, "service_quota.json")


def _service_quota_locked(minutes):
    today = time.strftime("%Y-%m-%d")
    try:
        d = json.load(open(_SERVICE_QUOTA))
    except Exception:
        d = {}
    if d.get("day") != today:
        d = {"day": today, "minutes": 0}
    if d["minutes"] + minutes > SERVICE_DAILY_MINUTES:
        return False, d["minutes"]
    d["minutes"] += minutes
    try:
        json.dump(d, open(_SERVICE_QUOTA, "w"))
    except OSError:
        pass
    return True, d["minutes"]


_quota_lock = threading.Lock()


def check_and_add_quota(uid, minutes):
    """Serialised: gunicorn runs 8 request threads, so two simultaneous uploads
    could otherwise both read the old total and one would overwrite the other."""
    with _quota_lock:
        ok, used = _check_and_add_quota_locked(uid, minutes)
        if not ok:
            return False, used
        svc_ok, _svc = _service_quota_locked(minutes)
        if not svc_ok:
            _refund_quota_locked(uid, minutes)
            return "service", used
        return True, used


def _refund_quota_locked(uid, minutes):
    """Give the minutes back when the upload is refused after being charged."""
    p = _quota_path(uid)
    try:
        d = json.load(open(p))
        d["minutes"] = max(0, d.get("minutes", 0) - minutes)
        json.dump(d, open(p, "w"))
    except Exception:
        pass


def _check_and_add_quota_locked(uid, minutes):
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
    if ok == "service":
        os.remove(path)
        return jsonify({"error":
            "MinitAI has used up today's free transcription allowance, which "
            "everyone here shares. It resets after midnight. Your own minutes "
            "have not been touched - please try again tomorrow, or use the "
            "desktop version, which has no limit."}), 429
    if not ok:
        os.remove(path)
        return jsonify({"error": f"You have used {used} of your "
                                 f"{MAX_MINUTES_PER_USER_PER_DAY} minutes today. "
                                 f"The allowance resets at midnight."}), 429

    with _jobs_lock:
        mine = sum(1 for v in JOBS.values()
                   if v.get("uid") == uid and v.get("state") in
                   ("queued", "transcribing", "reading", "summarising", "writing"))
    if mine >= MAX_QUEUED_PER_USER:
        os.remove(path)
        return jsonify({"error": f"You already have {mine} recordings being "
                                 f"processed. Wait for those to finish first."}), 429

    job_id = secrets.token_urlsafe(12)
    _set(job_id, uid=uid, audio=path, kind=("doc" if is_doc else "audio"),
         state="queued", progress=0,
         lang=(request.form.get("lang") or "").strip(),
         style=(request.form.get("style") or cloud.DEFAULT_STYLE).strip(),
         focus=(request.form.get("focus") or "").strip()[:600],
         hints=(request.form.get("hints") or "").strip()[:400],
         roster=(request.form.get("roster") or "").strip()[:1200],
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
    out = {k: v for k, v in j.items() if k not in ("uid", "audio")}
    if out.get("state") == "queued":
        # One meeting is processed at a time. Saying "third in line" is the
        # difference between waiting patiently and assuming it has hung.
        with _jobs_lock:
            ahead = sum(1 for k, v in JOBS.items()
                        if v.get("state") == "queued"
                        and v.get("created", 0) < j.get("created", 0))
        out["ahead"] = ahead
    return jsonify(out)


@app.route("/regenerate", methods=["POST"])
def regenerate():
    """Rebuild the documents from a corrected summary.

    One wrong name used to mean re-running the whole meeting and spending the
    allowance again. Nothing here touches the AI service, so it costs nothing
    and is not charged. The summary comes from the browser rather than server
    memory, so a restart between generating and correcting does not lose it.
    """
    uid = require_user()
    payload = request.get_json(silent=True) or {}
    data = payload.get("analysis")
    if not isinstance(data, dict):
        return jsonify({"error": "Nothing to rebuild."}), 400
    # Same coercion every other path goes through: whatever the browser sends,
    # the generators see the shape they expect.
    data = engine.normalise_analysis(data)
    if not engine._validate_analysis(data):
        return jsonify({"error": "That summary is empty - nothing to put in a "
                                 "document."}), 400
    out = user_dir(uid, "out")
    stamp = time.strftime("%Y-%m-%d_%H-%M")
    docx = os.path.join(out, f"{stamp}_minutes_edited.docx")
    pptx = os.path.join(out, f"{stamp}_slides_edited.pptx")
    try:
        engine.gen_docx(data, docx)
        engine.gen_pptx(data, pptx)
    except Exception as e:
        logging.exception("regenerate failed")
        return jsonify({"error": f"Could not rebuild the documents: {e}"}), 500
    return jsonify({"files": _package(uid, (("docx", docx), ("pptx", pptx))),
                    "title": data.get("meeting_title", "")})


@app.route("/wipe", methods=["POST"])
def wipe():
    """Delete everything this user has here, now, without waiting for retention.

    Someone who has just put a confidential meeting through the wrong version
    should not have to wait hours, or take our word for it.
    """
    uid = require_user()
    removed = 0
    d = user_dir(uid)
    for root, _dirs, names in os.walk(d):
        for n in names:
            try:
                os.remove(os.path.join(root, n))
                removed += 1
            except OSError:
                pass
    with _jobs_lock:
        for jid in [j for j, v in JOBS.items() if v.get("uid") == uid
                    and v.get("state") in ("done", "error")]:
            JOBS.pop(jid, None)
    logging.info("wipe: %d file(s) removed for one user", removed)
    return jsonify({"ok": True, "removed": removed})


@app.route("/recent")
def recent():
    """Everything this user could still be waiting for or still collect.

    Without this, pressing refresh - or the phone locking the screen, or a
    tab being closed - silently destroyed the meeting: the job carried on
    server-side, finished, and nobody ever received the documents, while the
    minutes had already been deducted. Recovery has to come from the server,
    because the browser forgets everything on reload.
    """
    uid = require_user()
    with _jobs_lock:
        mine = [dict(v, id=k) for k, v in JOBS.items() if v.get("uid") == uid]
    mine.sort(key=lambda j: j.get("created", 0), reverse=True)
    active, finished = [], []
    for j in mine[:20]:
        row = {"id": j["id"], "state": j.get("state"),
               "progress": j.get("progress", 0), "title": j.get("title", ""),
               "created": j.get("created", 0)}
        (finished if j.get("state") in ("done", "error") else active).append(row)

    # Files still physically present. Survives the process restarting, which
    # in-memory jobs do not.
    out = user_dir(uid, "out")
    files = []
    try:
        for name in os.listdir(out):
            p = os.path.join(out, name)
            if os.path.isfile(p):
                files.append({"name": name, "when": os.path.getmtime(p),
                              "url": "/get/" + make_token(uid, name)})
    except OSError:
        pass
    files.sort(key=lambda f: f["when"], reverse=True)
    return jsonify({"active": active, "finished": finished,
                    "files": files[:12]})


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
/* --- live recording --- */
#recBar{display:flex;gap:9px;margin-top:10px}
button.rec{background:var(--card2);border:1px solid var(--line);color:var(--txt);
font-size:13px;padding:11px 8px;border-radius:10px}
button.rec:hover:not(:disabled){border-color:var(--blue)}
#recLive{border:1px solid var(--red);border-radius:12px;padding:14px;margin-top:10px;
text-align:center}
#recDot{display:inline-block;width:10px;height:10px;border-radius:50%;
background:var(--red);margin-right:8px;animation:pulse 1.4s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
#recTime{font-size:20px;font-variant-numeric:tabular-nums;color:var(--txt)}
#recStop{margin-top:8px;background:var(--red)}
#recMeter{height:8px;background:var(--card2);border-radius:6px;overflow:hidden;
margin-top:10px}
#recMeter>i{display:block;height:100%;width:0;background:var(--blue);
transition:width .1s linear}
/* --- edit before export --- */
#editForm{margin-top:10px}
#editForm .row{background:var(--card2);border:1px solid var(--line);
border-radius:10px;padding:10px;margin-top:8px}
#editForm .row .n{font-size:11px;color:var(--muted);margin-bottom:4px}
#editForm input,#editForm textarea{width:100%;background:var(--card);
border:1px solid var(--line);border-radius:8px;color:var(--txt);
font-size:13px;padding:8px;font-family:inherit;margin-bottom:6px}
#editForm textarea{min-height:52px;resize:vertical}
#editForm h4{font-size:12px;color:var(--muted);margin:16px 0 2px;
text-transform:uppercase;letter-spacing:.4px}
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

  <div id="recBar">
    <button type="button" class="rec" id="recMic">Record the room</button>
    <button type="button" class="rec" id="recTab">Record an online meeting</button>
  </div>
  <div class="note" id="recNote" style="margin-top:8px"></div>

  <div id="recLive" class="hide">
    <div><span id="recDot"></span><span id="recTime">0:00</span></div>
    <div id="recMeter"><i></i></div>
    <div class="note" style="margin-top:6px" id="recHint"></div>
    <div class="note hide" id="recQuiet">No sound is reaching the microphone.</div>
    <button type="button" class="rec" id="recPause"
            style="width:100%;margin-top:10px">Pause</button>
    <button type="button" id="recStop">Stop and use this recording</button>
  </div>

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

  <label for="focus">Anything specific you want from this meeting? (optional)</label>
  <div class="note" style="margin:0 0 6px">
    Ask in your own words and the summary will prioritise it. If the meeting
    did not cover it, MinitAI says nothing rather than making something up.</div>
  <input id="focus" maxlength="600"
         placeholder="e.g. only the budget decisions &middot; what was agreed about the intake &middot; every deadline given to me">

  <label for="hints">Names it might not know (optional)</label>
  <div class="note" style="margin:0 0 6px">
    MinitAI has never heard your colleagues' names or your department's
    abbreviations, so it guesses at the spelling. List them here and it will
    get them right.</div>
  <input id="hints" placeholder="e.g. UMS, FSSK, Dr Aminah, Prof Lim, Bil 1/2026">

  <label for="roster">Who was there? (optional)</label>
  <div class="note" style="margin:0 0 6px">One name per line. This fills the
    KEHADIRAN section, tells the transcriber how the names are spelt, and stops
    it inventing people who were only mentioned.</div>
  <textarea id="roster" rows="3"
    placeholder="Dr. Hafizah&#10;Prof. Madya Dr. Maurin&#10;Puan Marja"
    style="width:100%;background:var(--card2);border:1px solid var(--line);
           border-radius:10px;color:var(--txt);font-size:14px;padding:11px;
           font-family:inherit;resize:vertical"></textarea>

  <button id="go" disabled>Choose a recording first</button>
  <div class="bar hide" id="barWrap"><i id="bar"></i></div>
  <div class="msg" id="msg"></div>
  <div id="files"></div>

  <button type="button" class="rec hide" id="editOpen"
          style="width:100%;margin-top:10px">Fix something before you save</button>
  <div id="editWrap" class="hide">
    <div class="note" style="margin-top:12px">Correct anything that came out
      wrong, then rebuild. This does not use the AI service again, so it costs
      nothing and is not deducted from your allowance.</div>
    <div id="editForm"></div>
    <button type="button" id="editSave" style="margin-top:12px">Rebuild the documents</button>
    <button type="button" class="rec" id="editCancel"
            style="width:100%;margin-top:8px">Cancel</button>
  </div>

  <div class="note" id="quota"></div>
  <div id="recentWrap" class="hide">
    <label style="margin-top:18px">Recent documents</label>
    <div class="note" style="margin:0 0 6px">Still here if you closed the page
      or refreshed by accident. These sit on the server, and the server clears
      them when it goes to sleep &mdash; often within the hour, and after
      {{ retention }} hours at the latest. Save anything you want to keep.</div>
    <div id="recent"></div>
  </div>
  <div class="note" style="text-align:right">
    <a href="#" id="signout" style="color:var(--muted)">Sign out</a></div>
  <div class="note">Your audio is sent to <b>Groq, an AI service in the United
    States</b>, to be transcribed, then deleted there. That is a transfer of
    your recording outside Malaysia &mdash; by uploading, you are agreeing to it,
    and you should have everyone's agreement before recording them at all.
    Your documents are handed straight to your browser; a short-lived copy
    stays on the server so a refresh cannot lose them, and that copy goes when
    the server sleeps. Save them somewhere you will find them again.
    For confidential meetings, use the desktop version, which never uploads
    anything.</div>
  <button type="button" class="rec" id="wipeBtn"
          style="width:100%;margin-top:10px">Delete everything of mine on the server</button>
  <div class="note hide" id="wipeMsg"></div>
</div>
<script>
const $=i=>document.getElementById(i);
let file=null, poll=null, running=false;

async function api(u,o){const r=await fetch(u,o);let j={};try{j=await r.json()}catch(e){}
  return {ok:r.ok,status:r.status,j};}

$('loginBtn').onclick=async()=>{
  const code=$('code').value.trim(); if(!code)return;
  $('loginBtn').disabled=true;
  const {ok,j}=await api('/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({code})});
  $('loginBtn').disabled=false;
  if(ok){$('loginMsg').classList.add('hide');$('loginMsg').textContent='';
    $('loginCard').classList.add('hide');$('appCard').classList.remove('hide');loadMe();resume();}
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
  // Choosing a file while one is still running must NOT re-arm the button;
  // starting a second job would orphan the first one's progress.
  if(running){$('go').textContent='Still working on the last one\\u2026';return;}
  $('go').disabled=false;$('go').textContent='Make the minutes';}

// ---------------------------------------------------------------- recording
// Record straight into the page so nobody has to find a file on their phone
// and work out how to get it here. Screen capture is desktop only - no mobile
// browser implements it - so phones get the microphone, which is the right
// tool for a meeting held in a room anyway.
var rec=null, recChunks=[], recStreams=[], recTimer=null, recStart=0, recLock=null;
var recPaused=false, recPausedMs=0, recPauseAt=0, recAnalyser=null, recMeterTimer=null;
function recElapsed(){
  var end = recPaused ? recPauseAt : Date.now();
  return Math.max(0, Math.floor((end - recStart - recPausedMs)/1000));
}
var CAN_TAB = !!(navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia);
var CAN_MIC = !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);

function recMime(){
  var want=['audio/webm;codecs=opus','audio/webm','audio/mp4','audio/ogg;codecs=opus'];
  for(var i=0;i<want.length;i++){
    if(window.MediaRecorder && MediaRecorder.isTypeSupported(want[i])) return want[i];
  }
  return '';
}
if(!CAN_MIC || !window.MediaRecorder){
  $('recBar').classList.add('hide');
  $('recNote').textContent='This browser cannot record. Upload a file instead.';
} else if(!CAN_TAB){
  $('recTab').disabled=true;
  $('recNote').textContent='Recording an online meeting needs a laptop \\u2014 phones '
    +'cannot capture a call. On a phone, "Record the room" is the one to use.';
} else {
  $('recNote').textContent='Tell everyone you are recording before you start. '
    +'MinitAI does not announce itself the way Google Meet does.';
}

function fmt(s){
  var m=Math.floor(s/60), r=s%60;
  return m+':'+(r<10?'0':'')+r;
}

async function recStartMode(mode){
  if(rec||running) return;
  recChunks=[]; recStreams=[];
  var ac, dest, gotTab=false;
  try{
    ac=new (window.AudioContext||window.webkitAudioContext)();
    dest=ac.createMediaStreamDestination();
    if(mode==='tab'){
      // Chrome will not share audio without a video surface, so ask for both
      // and simply never record the picture.
      var ds=await navigator.mediaDevices.getDisplayMedia({video:true,audio:true});
      recStreams.push(ds);
      if(ds.getAudioTracks().length){
        ac.createMediaStreamSource(ds).connect(dest); gotTab=true;
      }
      var vt=ds.getVideoTracks()[0];
      if(vt) vt.onended=function(){ recStopNow(); };
    }
    var ms=await navigator.mediaDevices.getUserMedia({audio:true});
    recStreams.push(ms);
    ac.createMediaStreamSource(ms).connect(dest);
  }catch(e){
    recCleanup();
    $('msg').className='msg err';
    if(e.name==='NotAllowedError'){
      $('msg').textContent='Recording was blocked. Click the padlock next to the '
        +'web address, set Microphone to Allow, then try again.';
    } else if(e.name==='NotFoundError'){
      $('msg').textContent='No microphone found on this device.';
    } else if(!window.isSecureContext){
      $('msg').textContent='Recording needs a secure connection. Open the site '
        +'with a secure address and try again.';
    } else {
      $('msg').textContent='Could not start recording: '+(e.message||e.name);
    }
    return;
  }
  if(mode==='tab' && !gotTab){
    $('recHint').textContent='No meeting audio captured \\u2014 you did not tick '
      +'"Also share tab audio". Only your microphone is being recorded.';
  } else if(mode==='tab'){
    $('recHint').textContent='Recording the meeting and your microphone. Keep this '
      +'tab open.';
  } else {
    $('recHint').textContent='Recording the microphone. Keep this tab in front and '
      +'the screen on, or the phone will stop it.';
  }
  var mt=recMime();
  try{
    rec = mt ? new MediaRecorder(dest.stream,{mimeType:mt})
             : new MediaRecorder(dest.stream);
  }catch(e){
    recCleanup();
    $('msg').className='msg err';
    $('msg').textContent='This browser refused to record: '+(e.message||e.name);
    return;
  }
  rec.ondataavailable=function(e){ if(e.data && e.data.size) recChunks.push(e.data); };
  rec.onstop=recFinish;
  rec.start(5000);           // flush every 5s so a crash loses seconds, not hours
  if(navigator.wakeLock && navigator.wakeLock.request){
    navigator.wakeLock.request('screen').then(function(l){ recLock=l; },function(){});
  }
  // A level meter is the difference between recording a meeting and recording
  // ninety minutes of a muted microphone.
  try{
    recAnalyser=ac.createAnalyser(); recAnalyser.fftSize=512;
    ac.createMediaStreamSource(dest.stream).connect(recAnalyser);
    var mbuf=new Uint8Array(recAnalyser.frequencyBinCount), quiet=0;
    recMeterTimer=setInterval(function(){
      if(recPaused) return;
      recAnalyser.getByteTimeDomainData(mbuf);
      var peak=0;
      for(var i=0;i<mbuf.length;i++){ var v=Math.abs(mbuf[i]-128); if(v>peak)peak=v; }
      var pct=Math.min(100,Math.round(peak/128*260));
      $('recMeter').firstElementChild.style.width=pct+'%';
      quiet = pct<2 ? quiet+1 : 0;
      $('recQuiet').classList.toggle('hide', quiet<25);   // ~5 seconds of silence
    },200);
  }catch(e){}
  recPaused=false; recPausedMs=0; $('recPause').textContent='Pause';
  recStart=Date.now();
  $('recBar').classList.add('hide');
  $('recLive').classList.remove('hide');
  $('recTime').textContent='0:00';
  // How much recording this person can still have accepted today. Finding out
  // AFTER a two-hour meeting that it will be refused is the worst possible
  // moment, so warn while there is still time to wrap up.
  var budget=0;
  fetch('/me').then(function(r){ return r.json(); }).then(function(j){
    if(j && j.signed_in) budget=Math.max(0,(j.daily_limit||0)-(j.used_minutes||0));
  }).catch(function(){});
  recTimer=setInterval(function(){
    if(recPaused) return;
    var secs=recElapsed();
    $('recTime').textContent=fmt(secs);
    var mins=secs/60;
    if(budget && mins>budget){
      $('recTime').style.color='#F87171';
      $('recHint').textContent='Past your allowance for today ('+budget+' min). '
        +'This recording will be refused. Stop and split it, or try tomorrow.';
    } else if(budget && mins>budget-5){
      $('recHint').textContent='About '+Math.max(0,Math.round(budget-mins))
        +' min of your daily allowance left.';
    } else if(secs>6900){
      $('recTime').style.color='#FBBF24';
      $('recHint').textContent='Approaching the two-hour limit. Anything longer is '
        +'refused - stop soon and record the rest separately.';
    }
  },1000);
}

// A refresh or a closed tab loses the whole recording, because the audio is
// held in this page and nowhere else.
window.addEventListener('beforeunload',function(e){
  if(rec && rec.state!=='inactive'){ e.preventDefault(); e.returnValue=''; }
});

function recStopNow(){
  if(rec && rec.state!=='inactive') rec.stop();
}

function recFinish(){
  var mt=(rec && rec.mimeType) || 'audio/webm';
  var ext = mt.indexOf('mp4')>-1 ? '.mp4' : (mt.indexOf('ogg')>-1 ? '.ogg' : '.webm');
  var secs=Math.max(1, recElapsed());
  var blob=new Blob(recChunks,{type:mt.split(';')[0]});
  recCleanup();
  if(blob.size<2048){
    $('msg').className='msg err';
    $('msg').textContent='That recording came out empty. Check the microphone permission.';
    return;
  }
  var name='meeting-'+fmt(secs).replace(':','m')+'s'+ext;
  pick(new File([blob],name,{type:blob.type}));
  $('msg').className='msg';
  $('msg').textContent='Recording ready \\u2014 '+fmt(secs)+'. Press "Make the minutes".';
}

function recCleanup(){
  if(recTimer){ clearInterval(recTimer); recTimer=null; }
  if(recMeterTimer){ clearInterval(recMeterTimer); recMeterTimer=null; }
  recAnalyser=null; recPaused=false; recPausedMs=0;
  $('recQuiet').classList.add('hide');
  $('recDot').style.animationPlayState='running';
  $('recMeter').firstElementChild.style.width='0%';
  recStreams.forEach(function(s){ s.getTracks().forEach(function(t){ t.stop(); }); });
  recStreams=[]; rec=null;
  $('recTime').style.color='';
  if(recLock){ try{ recLock.release(); }catch(e){} recLock=null; }
  $('recLive').classList.add('hide');
  $('recBar').classList.remove('hide');
}

// ------------------------------------------------------- remembered settings
// It is the same committee every month, so retyping a dozen names each time is
// friction nobody tolerates - and an empty names box is why the transcript
// invents spellings. Kept in this browser only: the server's disk is wiped
// whenever the free instance sleeps, so it could not hold this if it tried.
(function(){
  var KEYS=['hints','lang','style','roster'];
  try{
    KEYS.forEach(function(k){
      var v=localStorage.getItem('minitai.'+k);
      if(v!==null && $(k)) $(k).value=v;
      if($(k)) $(k).addEventListener('change',function(){
        try{ localStorage.setItem('minitai.'+k,$(k).value); }catch(e){}
      });
    });
    ['hints','roster'].forEach(function(k){
      if($(k)) $(k).addEventListener('blur',function(){
        try{ localStorage.setItem('minitai.'+k,$(k).value); }catch(e){}
      });
    });
  }catch(e){}         // private browsing blocks storage; not worth failing over
})();

// Two taps rather than a browser confirm box: a native dialog blocks the page
// and cannot be styled, and this is a destructive action worth slowing down.
var wipeArmed=false;
$('wipeBtn').onclick=async function(){
  if(!wipeArmed){
    wipeArmed=true;
    $('wipeBtn').textContent='Tap again to delete everything permanently';
    setTimeout(function(){
      wipeArmed=false;
      $('wipeBtn').textContent='Delete everything of mine on the server';
    },6000);
    return;
  }
  wipeArmed=false; $('wipeBtn').disabled=true;
  $('wipeBtn').textContent='Deleting\u2026';
  try{
    var r=await fetch('/wipe',{method:'POST'});
    var j=await r.json();
    $('wipeMsg').classList.remove('hide');
    $('wipeMsg').textContent='Deleted '+(j.removed||0)+' file(s). Anything already '
      +'downloaded to this device is still yours.';
    $('files').innerHTML=''; $('recent').innerHTML='';
    $('recentWrap').classList.add('hide');
    $('editOpen').classList.add('hide'); $('editWrap').classList.add('hide');
  }catch(e){
    $('wipeMsg').classList.remove('hide');
    $('wipeMsg').textContent='Could not delete: '+(e.message||e);
  }
  $('wipeBtn').disabled=false;
  $('wipeBtn').textContent='Delete everything of mine on the server';
};

$('recMic').onclick=function(){ recStartMode('mic'); };
$('recTab').onclick=function(){ recStartMode('tab'); };
$('recPause').onclick=function(){
  if(!rec) return;
  if(recPaused){
    try{ rec.resume(); }catch(e){ return; }
    recPausedMs += Date.now()-recPauseAt; recPaused=false;
    $('recPause').textContent='Pause'; $('recDot').style.animationPlayState='running';
  } else {
    try{ rec.pause(); }catch(e){ return; }
    recPauseAt=Date.now(); recPaused=true;
    $('recPause').textContent='Resume'; $('recDot').style.animationPlayState='paused';
  }
};
$('recStop').onclick=recStopNow;

$('go').onclick=async()=>{
  if(!file||running)return;
  $('go').disabled=true;$('files').innerHTML='';
  $('msg').className='msg';$('msg').textContent='Uploading\\u2026';
  $('barWrap').classList.remove('hide');$('bar').style.width='4%';
  const fd=new FormData();fd.append('audio',file);
  fd.append('lang',$('lang').value);fd.append('hints',$('hints').value);
  fd.append('roster',$('roster').value);
  fd.append('style',$('style').value);
  fd.append('focus',$('focus').value);
  const {ok,j}=await api('/upload',{method:'POST',body:fd});
  if(!ok){fail(j.error||'Upload failed.');return;}
  $('msg').textContent=j.queued_ahead>0
    ? 'Waiting \\u2014 '+j.queued_ahead+' meeting(s) ahead of yours\\u2026'
    : 'Processing\\u2026 about '+Math.max(1,Math.round(j.minutes/4))+' min';
  watch(j.job);
};
// One place that starts polling, so resuming after a refresh behaves exactly
// like the original upload.
function watch(id){
  running=true; clearInterval(poll);
  $('go').disabled=true; $('barWrap').classList.remove('hide');
  poll=setInterval(()=>check(id),2500); check(id);
}
function fail(t){clearInterval(poll);running=false;$('msg').className='msg err';$('msg').textContent=t;
  $('barWrap').classList.add('hide');$('go').disabled=false;}
// Closing the page used to abandon the meeting with no warning at all.
window.addEventListener('beforeunload',e=>{
  if(!running)return;
  e.preventDefault(); e.returnValue='';
});

const NICE={queued:'Waiting in the queue\\u2026',transcribing:'Listening to the recording\\u2026',
  summarising:'Writing the summary\\u2026',writing:'Building your documents\\u2026'};
async function check(id,noAuto){
  const {ok,j,status}=await api('/job/'+id);
  if(status===410){fail(j.error||'That job was lost. Please upload again.');return;}
  if(!ok){fail('Lost track of that job. Please try again.');return;}
  if(j.progress!=null)$('bar').style.width=Math.max(4,j.progress)+'%';
  if(j.state==='error'){fail(j.error||'Something went wrong.');return;}
  if(j.state==='done'){
    clearInterval(poll); running=false;
    $('barWrap').classList.add('hide');
    $('msg').className='msg ok';
    $('msg').textContent='Done'+(j.title?' \\u2014 '+j.title:'');
    renderFiles(j.files, !noAuto);
    lastAnalysis = j.analysis || null;
    if(lastAnalysis) $('editOpen').classList.remove('hide');
    reset(); loadMe(); loadRecent(); return;
  }
  if(j.state==='queued'&&j.ahead>0){
    $('msg').textContent=j.ahead===1?'Next in line \\u2014 one meeting ahead of yours\\u2026'
      :'Waiting \\u2014 '+j.ahead+' meetings ahead of yours\\u2026'; return;}
  $('msg').textContent=NICE[j.state]||'Working\\u2026';
}
var lastAnalysis=null;
var FILE_LABEL={docx:'Word document (.docx)',pptx:'Slides (.pptx)',
                transcript:'Full transcript (.txt)'};
var FILE_MIME={docx:'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
               pptx:'application/vnd.openxmlformats-officedocument.presentationml.presentation',
               transcript:'text/plain'};

function renderFiles(files, autoSave){
  $('files').innerHTML='';
  var first=null;
  Object.entries(files||{}).forEach(function(pair){
    var k=pair[0], v=pair[1];
    var a=document.createElement('a');
    a.className='file'; a.download=v.name; a.textContent='Download '+(FILE_LABEL[k]||v.name);
    if(v.data){
      // Held in the browser, not on the server. Survives the server sleeping.
      var bin=atob(v.data), buf=new Uint8Array(bin.length);
      for(var i=0;i<bin.length;i++)buf[i]=bin.charCodeAt(i);
      a.href=URL.createObjectURL(new Blob([buf],{type:FILE_MIME[k]||'application/octet-stream'}));
      if(k==='docx')first=a;
    } else { a.href=v.url; }
    $('files').appendChild(a);
  });
  $('files').insertAdjacentHTML('beforeend',
    '<div class="note">The minutes save to your downloads automatically. '
    +'Tap the other two if you want them as well.</div>');
  addShare(files);
  // Only ONE automatic download. Browsers challenge the second and third
  // with a "allow multiple downloads?" prompt that people dismiss, and the
  // files were then lost. The rest stay one tap away, and Recent documents
  // below survives a refresh.
  if(first&&autoSave)setTimeout(function(){try{first.click();}catch(e){}},400);
}

// ------------------------------------------------------------------- sharing
// On a phone the share sheet can hand the actual .docx to WhatsApp. On a
// desktop it usually cannot, so those get a message with the meeting name and
// a reminder to attach the file they just downloaded - honest about the limit
// rather than silently sharing a link nobody else can open.
function blobFor(v){
  if(!v||!v.data) return null;
  var bin=atob(v.data), buf=new Uint8Array(bin.length);
  for(var i=0;i<bin.length;i++)buf[i]=bin.charCodeAt(i);
  return new Blob([buf],{type:FILE_MIME.docx});
}
function addShare(files){
  var v=(files||{}).docx; if(!v) return;
  var title=($('msg').textContent||'Minit mesyuarat').replace(/^Done \u2014 /,'');
  var wrap=document.createElement('div'); wrap.id='shareRow';
  wrap.style.cssText='display:flex;gap:9px;margin-top:10px';
  var blob=blobFor(v);
  var f=null;
  try{ if(blob) f=new File([blob],v.name,{type:blob.type}); }catch(e){}
  if(f && navigator.canShare && navigator.canShare({files:[f]})){
    var b=document.createElement('button');
    b.type='button'; b.className='rec'; b.textContent='Share the document';
    b.onclick=function(){ navigator.share({files:[f],title:title}).catch(function(){}); };
    wrap.appendChild(b);
  } else {
    var msg=encodeURIComponent('Minit mesyuarat: '+title
      +' \u2014 dokumen Word dilampirkan. (Dijana dengan MinitAI.)');
    var w=document.createElement('a');
    w.className='rec'; w.style.cssText='display:block;text-align:center;padding:11px 8px;'
      +'border-radius:10px;text-decoration:none;flex:1';
    w.target='_blank'; w.rel='noopener';
    w.href='https://wa.me/?text='+msg; w.textContent='Send on WhatsApp';
    var m=document.createElement('a');
    m.className='rec'; m.style.cssText=w.style.cssText;
    m.href='mailto:?subject='+encodeURIComponent('Minit mesyuarat: '+title)
      +'&body='+msg; m.textContent='Send by email';
    wrap.appendChild(w); wrap.appendChild(m);
    wrap.insertAdjacentHTML('afterend','');
  }
  $('files').appendChild(wrap);
  if(!(f && navigator.canShare && navigator.canShare({files:[f]}))){
    $('files').insertAdjacentHTML('beforeend',
      '<div class="note">WhatsApp and email cannot pick up the file by '
      +'themselves on a computer &mdash; attach the document you just '
      +'downloaded.</div>');
  }
}

// ------------------------------------------------------------- edit + rebuild
function esc(s){ return (s==null?'':String(s)).replace(/&/g,'&amp;')
  .replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function buildEditor(){
  var d=lastAnalysis||{}, h='';
  h+='<h4>Maklumat mesyuarat</h4>';
  [['meeting_title','Tajuk'],['date','Tarikh'],['time','Masa'],['location','Tempat']]
    .forEach(function(f){
      h+='<div class="n">'+f[1]+'</div><input data-f="'+f[0]+'" value="'+esc(d[f[0]])+'">';
    });
  h+='<div class="n">Kehadiran (pisahkan dengan koma)</div>'
    +'<input data-f="attendees" value="'+esc((d.attendees||[]).join(', '))+'">';
  h+='<h4>Perkara dibincangkan</h4>';
  (d.agenda_items||[]).forEach(function(it,i){
    h+='<div class="row" data-agenda="'+i+'">'
      +'<div class="n">'+(i+1)+'.0 Tajuk perkara</div><input data-a="topic" value="'+esc(it.topic)+'">'
      +'<div class="n">Perbincangan</div><textarea data-a="discussion">'+esc(it.discussion)+'</textarea>'
      +'<div class="n">Keputusan</div><textarea data-a="decision">'+esc(it.decision)+'</textarea>'
      +'</div>';
  });
  h+='<h4>Tindakan</h4>';
  (d.action_items||[]).forEach(function(it,i){
    h+='<div class="row" data-action="'+i+'">'
      +'<div class="n">Tindakan</div><input data-t="task" value="'+esc(it.task)+'">'
      +'<div class="n">Pegawai bertanggungjawab</div><input data-t="owner" value="'+esc(it.owner)+'">'
      +'<div class="n">Tarikh akhir</div><input data-t="deadline" value="'+esc(it.deadline)+'">'
      +'</div>';
  });
  h+='<h4>Catatan penting</h4>'
    +'<div class="n">Satu baris setiap catatan. Kosongkan baris untuk membuangnya.</div>'
    +'<textarea data-f="important_notes" style="min-height:90px">'
    +esc((d.important_notes||[]).join('\\n'))+'</textarea>';
  $('editForm').innerHTML=h;
}

function collectEditor(){
  var d=JSON.parse(JSON.stringify(lastAnalysis||{}));
  $('editForm').querySelectorAll('[data-f]').forEach(function(el){
    var f=el.getAttribute('data-f');
    if(f==='attendees') d.attendees=el.value.split(',').map(function(s){return s.trim();}).filter(Boolean);
    else if(f==='important_notes') d.important_notes=el.value.split('\\n').map(function(s){return s.trim();}).filter(Boolean);
    else d[f]=el.value.trim();
  });
  d.agenda_items=[];
  $('editForm').querySelectorAll('[data-agenda]').forEach(function(row){
    var g=function(k){var e=row.querySelector('[data-a="'+k+'"]');return e?e.value.trim():'';};
    if(g('topic')) d.agenda_items.push({topic:g('topic'),discussion:g('discussion'),decision:g('decision')});
  });
  d.action_items=[];
  $('editForm').querySelectorAll('[data-action]').forEach(function(row){
    var g=function(k){var e=row.querySelector('[data-t="'+k+'"]');return e?e.value.trim():'';};
    if(g('task')) d.action_items.push({task:g('task'),owner:g('owner'),deadline:g('deadline')});
  });
  return d;
}

$('editOpen').onclick=function(){
  buildEditor();
  $('editWrap').classList.remove('hide');
  $('editOpen').classList.add('hide');
};
$('editCancel').onclick=function(){
  $('editWrap').classList.add('hide');
  $('editOpen').classList.remove('hide');
};
$('editSave').onclick=async function(){
  var btn=$('editSave'); btn.disabled=true; btn.textContent='Rebuilding\\u2026';
  try{
    var body=JSON.stringify({analysis:collectEditor()});
    var r=await fetch('/regenerate',{method:'POST',headers:{'Content-Type':'application/json'},body:body});
    var j=await r.json();
    if(!r.ok) throw new Error(j.error||'Rebuild failed.');
    lastAnalysis=collectEditor();
    renderFiles(j.files,false);      // no auto-download; they asked for this one
    $('msg').className='msg ok';
    $('msg').textContent='Rebuilt'+(j.title?' \\u2014 '+j.title:'')+'. Tap to download.';
    $('editWrap').classList.add('hide'); $('editOpen').classList.remove('hide');
    loadRecent();
  }catch(e){
    $('msg').className='msg err'; $('msg').textContent=e.message||'Rebuild failed.';
  }
  btn.disabled=false; btn.textContent='Rebuild the documents';
};

// Back to a clean form, so nobody re-uploads the same meeting by accident and
// pays for it twice.
function reset(){
  file=null; $('file').value='';
  $('drop').innerHTML='Tap to choose another file &mdash; or drop it here';
  $('go').disabled=true; $('go').textContent='Choose a recording first';
}
async function loadMe(){const {j}=await api('/me');
  if(j.signed_in)$('quota').textContent='Used '+j.used_minutes+' of '+j.daily_limit+' minutes today.';}

async function loadRecent(){
  const {ok,j}=await api('/recent'); if(!ok||!j)return;
  const f=j.files||[];
  $('recentWrap').classList.toggle('hide',f.length===0);
  $('recent').innerHTML=f.map(x=>'<a class="file" href="'+x.url+'">'+x.name+'</a>').join('');
}

// Picking up where the page left off. A refresh, a closed tab, a phone that
// locked itself - the job is still running on the server, so re-attach to it
// instead of showing an empty form and losing the meeting.
async function resume(){
  const {ok,j}=await api('/recent'); if(!ok||!j)return;
  loadRecent();
  const a=(j.active||[])[0];
  if(a){
    $('msg').className='msg';
    $('msg').textContent='Picking up where you left off\\u2026';
    watch(a.id); return;
  }
  const d=(j.finished||[]).filter(x=>x.state==='done')[0];
  if(d){ check(d.id,true); }   // re-offers the links, no repeat download
}
$('signout').onclick=async e=>{e.preventDefault();
  if(running&&!confirm('A meeting is still being processed. Sign out anyway?'))return;
  running=false; await api('/logout',{method:'POST'}); location.reload();};
if(!$('appCard').classList.contains('hide')){loadMe();resume();}
</script></div></body></html>"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
