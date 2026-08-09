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

# Every counter below is only meaningful relative to this.
_STARTED_AT = time.time()

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
            job = get_job(job_id)
            # A failed meeting must not cost anyone their allowance. The
            # minutes were taken at upload; give them back.
            mins = int(job.get("minutes_charged") or 0)
            if mins:
                try:
                    with _quota_lock:
                        _refund_quota_locked(job["uid"], mins)
                    logging.info("job failed: refunded %d minute(s)", mins)
                except Exception:
                    logging.warning("could not refund after a failed job")
            # Our own RuntimeErrors carry a sentence written for the user.
            # Hiding it behind "something went wrong" throws away the only
            # useful thing we know - "no speech detected" tells them the
            # microphone was muted; the generic text tells them nothing.
            msg = str(e).strip()
            human = (isinstance(e, RuntimeError) and msg
                     and msg[0].isupper() and msg.endswith("."))
            if isinstance(e, RuntimeError) and "No speech detected" in msg:
                msg = ("That recording has no sound in it. The microphone was "
                       "probably muted or blocked \u2014 nothing was charged.")
                human = True
            elif human:
                msg += " Nothing was charged."
            _set(job_id, state="error",
                 error=msg if human else
                       "Something went wrong processing this meeting. "
                       "Please try again \u2014 nothing was charged.",
                 detail=type(e).__name__)
        finally:
            _work.task_done()
            try:
                _evict_old_jobs()
            except Exception:
                pass


def _previous_text(f):
    """Text of last meeting's minutes, if the user attached them.

    Read here and thrown away immediately: it only ever exists to give the
    summariser something to write Perkara Berbangkit from.
    """
    if not f or not f.filename:
        return ""
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in DOC_EXTS:
        return ""
    tmp = os.path.join(tempfile.gettempdir(),
                       f"prev_{secrets.token_hex(6)}{ext}")
    try:
        f.save(tmp)
        return (engine.extract_text_from_file(tmp) or "")[:20000]
    except Exception as e:
        logging.warning(f"previous minutes unreadable: {type(e).__name__}")
        return ""
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def _safe_name(title, stamp, suffix):
    """A filename someone can recognise in their Downloads folder.

    "2026-08-09_16-04_minutes.docx" tells you nothing when three of them are
    sitting there. "Mesyuarat Pasca Fakulti 2026-08-09 1604 minit.docx" does.
    """
    clean = re.sub(r"[^\w\s\-()]", "", (title or "").strip(), flags=re.UNICODE)
    clean = re.sub(r"\s+", " ", clean).strip()[:60]
    parts = [p for p in (clean, stamp.replace("_", " ")) if p]
    return " ".join(parts) + " " + suffix


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

            text = None
            if job.get("speakers") and cloud.diarisation_available():
                try:
                    _set(job_id, state="transcribing", progress=5)
                    text = cloud.transcribe_with_speakers(
                        audio_path, language=job.get("lang") or None)
                    logging.info("job: speaker labels via AssemblyAI")
                except Exception as e:
                    # Never lose a meeting to an optional extra.
                    logging.warning(f"diarisation failed, falling back: {type(e).__name__}")
                    text = None
            if text is None:
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
                             roster=job.get("roster") or "",
                             previous=job.get("previous") or "",
                             lang=job.get("lang") or "")
        if not engine._validate_analysis(data):
            raise RuntimeError("empty summary")
        data = engine._drop_hallucinations(
            data, text,
            keep=[n.strip() for n in (job.get("roster") or "").splitlines() if n.strip()])

        _set(job_id, state="writing", progress=96)
        stamp = time.strftime("%Y-%m-%d %H%M")
        base = data.get("meeting_title") or "Minit Mesyuarat"
        docx = os.path.join(out, _safe_name(base, stamp, "minit.docx"))
        pptx = os.path.join(out, _safe_name(base, stamp, "slaid.pptx"))
        txt = os.path.join(out, _safe_name(base, stamp, "transkrip.txt"))
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
# The server runs on UTC, so "today" ended at midnight UTC - which is 8am in
# Malaysia. Someone recording at 11pm was told to wait until tomorrow and then
# waited nine hours, not one. The day now turns over at local midnight.
TZ_OFFSET_HOURS = float(os.environ.get("MINITAI_TZ_OFFSET", "8"))


def _quota_day():
    return time.strftime("%Y-%m-%d", time.gmtime(time.time() + TZ_OFFSET_HOURS * 3600))


def _quota_reset_at():
    """Epoch second of the next local midnight, so the page can count down."""
    shifted = time.time() + TZ_OFFSET_HOURS * 3600
    midnight = (int(shifted) // 86400 + 1) * 86400
    return midnight - TZ_OFFSET_HOURS * 3600


def _profile_path(uid):
    return os.path.join(user_dir(uid), "profile.json")


def _save_profile(uid, name, org=None):
    """Remember who is using a code.

    Written to a disk that is wiped whenever the instance sleeps - so the
    browser re-sends the name on every sign-in and the record heals itself as
    people come back. Nothing here is authoritative; it is a courtesy so the
    help assistant can use someone's name and Gavril can see which codes are
    in use.
    """
    name = re.sub(r"\s+", " ", (name or "")).strip()[:60]
    org = re.sub(r"\s+", " ", (org or "")).strip()[:80]
    if not name and not org:
        return
    try:
        old = {}
        if os.path.exists(_profile_path(uid)):
            old = json.load(open(_profile_path(uid)))
        json.dump({"name": name or old.get("name", ""),
                   "org": org or old.get("org", ""),
                   "first_seen": old.get("first_seen") or time.time(),
                   "last_seen": time.time(),
                   "sign_ins": int(old.get("sign_ins") or 0) + 1},
                  open(_profile_path(uid), "w"))
    except Exception as e:
        logging.warning(f"could not save a profile: {type(e).__name__}")


def _load_profile(uid):
    try:
        return json.load(open(_profile_path(uid)))
    except Exception:
        return {}


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
    today = _quota_day()
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
    today = _quota_day()
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
    # Google sign-in and Drive are the only things allowed off-origin, and only
    # the exact hosts they need. Without these the Drive button silently fails
    # with "could not reach Google" - the browser refuses the script before the
    # request is ever made.
    r.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline' https://accounts.google.com "
        "https://apis.google.com https://ssl.gstatic.com "
        "https://www.gstatic.com; "
        "connect-src 'self' https://accounts.google.com "
        "https://oauth2.googleapis.com https://www.googleapis.com; "
        "frame-src https://accounts.google.com https://content.googleapis.com; "
        "img-src 'self' data: https://*.googleusercontent.com "
        "https://ssl.gstatic.com https://www.gstatic.com;"
    )
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
    _save_profile(session["uid"], (request.json or {}).get("name"),
                  (request.json or {}).get("org"))
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
    today = _quota_day()
    try:
        q = json.load(open(_quota_path(uid)))
        used = q.get("minutes", 0) if q.get("day") == today else 0
    except Exception:
        used = 0
    return jsonify({"signed_in": True, "used_minutes": used,
                    "daily_limit": MAX_MINUTES_PER_USER_PER_DAY,
                    "speakers_available": cloud.diarisation_available(),
                    # A browser OAuth client id is public by design - it is
                    # embedded in the page. There is no client secret in this
                    # flow and no token ever reaches this server, which is the
                    # point: the disk here is wiped whenever the free instance
                    # sleeps, so it is the last place to keep a Google token.
                    "google_client_id": (os.environ.get("GOOGLE_CLIENT_ID") or "").strip(),
                    "is_admin": _is_admin(uid),
                    "quota_resets_at": _quota_reset_at(),
                    "name": _load_profile(uid).get("name", ""),
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
         speakers=(request.form.get("speakers") == "1"),
         previous=_previous_text(request.files.get("prev")),
         minutes_charged=(1 if is_doc else (int(dur / 60) or 1)),
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
    stamp = time.strftime("%Y-%m-%d %H%M")
    base = data.get("meeting_title") or "Minit Mesyuarat"
    docx = os.path.join(out, _safe_name(base, stamp, "minit (dibetulkan).docx"))
    pptx = os.path.join(out, _safe_name(base, stamp, "slaid (dibetulkan).pptx"))
    try:
        engine.gen_docx(data, docx)
        engine.gen_pptx(data, pptx)
    except Exception as e:
        logging.exception("regenerate failed")
        return jsonify({"error": f"Could not rebuild the documents: {e}"}), 500
    return jsonify({"files": _package(uid, (("docx", docx), ("pptx", pptx))),
                    "title": data.get("meeting_title", "")})


MINITAI_FACTS = """
MinitAI turns a meeting recording into formal minutes (Word), a slide summary
and a full transcript. It is run by Gavril for about twenty friends, family and
colleagues. These are ALL the facts you have:

- Sign in with the personal invite code Gavril gave you. One code per person;
  your meetings are separate from everyone else's. Codes are not shared.
- Upload a recording (mp3, mp4, m4a, wav, mov, mkv, webm, phone voice memos) or
  press "Record the room" to record with the microphone. "Record an online
  meeting" captures a Meet or Zoom tab and only works on a laptop - no phone
  browser can capture a call.
- You can also upload a document (pdf, docx, pptx, txt) to summarise instead.
- First load of the day takes about a minute: the free server sleeps after 15
  minutes of no use and has to wake up. It is not broken.
- One meeting is processed at a time. Others queue and the page says how many
  are ahead.
- Recordings longer than about two hours are refused. Split them in half.
- There is a daily limit per person, shown at the bottom of the page. It counts
  the LENGTH of the recording, not how long you spend using the app.
- Files are handed to your browser. A copy sits on the server only until it
  sleeps, which can be within the hour. Save them when you get them.
- "Fix something before you save" lets you correct a name or a decision and
  rebuild the documents. That is free and does not use your allowance.
- Fill in "Who was there?" and "Names it might not know". It is the single
  biggest thing that improves spelling of names, because the transcriber is
  told the names before it starts.
- Audio is sent to Groq in the United States to be transcribed. That is a
  transfer outside Malaysia. Do not use it for confidential meetings - the
  desktop version never uploads anything.
- "Delete everything of mine on the server" wipes your files immediately.
"""


@app.route("/help", methods=["POST"])
def help_ask():
    """Answer questions about MinitAI, strictly from the facts above.

    Deliberately not a general assistant. A model improvising about an app it
    has never seen invents limits that do not exist, and the person asking
    believes it.
    """
    require_user()
    q = ((request.get_json(silent=True) or {}).get("q") or "").strip()[:400]
    if not q:
        return jsonify({"answer": "Ask me anything about using MinitAI."})
    who = _load_profile(current_user()).get("name", "")
    sys_p = ((f"You are speaking to {who}. Use their name once, naturally, not "
              f"in every sentence.\n\n" if who else "")
             + "You answer questions about a tool called MinitAI, using ONLY the "
             "facts below. If the answer is not in them, say exactly: \"I do not "
             "know - please ask Gavril.\" Never guess a limit, a price or a "
             "feature. Two or three sentences. Reply in the language of the "
             "question (Malay or English).\n\n" + MINITAI_FACTS)
    try:
        ans = cloud.ask_text(sys_p, q, DATA_ROOT)
    except Exception as e:
        logging.warning(f"help failed: {type(e).__name__}")
        return jsonify({"answer": "The help assistant is unavailable right now. "
                                  "Ask Gavril."})
    return jsonify({"answer": ans})


@app.route("/ask", methods=["POST"])
def ask_meeting():
    """Answer a question about a past meeting, from its transcript.

    The transcript is sent by the browser, which is the only place it reliably
    still exists - the server clears its disk whenever it sleeps.
    """
    require_user()
    body = request.get_json(silent=True) or {}
    q = (body.get("q") or "").strip()[:400]
    text = (body.get("transcript") or "")[:60000]
    if not q or not text.strip():
        return jsonify({"error": "Pick a meeting and ask a question."}), 400
    sys_p = ("Answer the question using ONLY this meeting transcript. If the "
             "meeting did not cover it, say so plainly rather than guessing. "
             "Quote what was actually said where it helps. Reply in the "
             "language of the question.\n\nTRANSCRIPT:\n" + text)
    try:
        return jsonify({"answer": cloud.ask_text(sys_p, q, DATA_ROOT)})
    except Exception as e:
        logging.warning(f"ask failed: {type(e).__name__}")
        return jsonify({"error": "Could not answer that just now."}), 503


def _is_admin(uid):
    """Admin is one of the invite codes, not a separate login.

    A second username and password on a public URL is a second thing that can
    be guessed, and the obvious choice - admin/admin - is the first pair every
    automated scanner on the internet tries. The invite codes are already long
    random strings that only Gavril hands out, so nominating one costs nothing
    and adds no new way in.
    """
    code = (os.environ.get("MINITAI_ADMIN_CODE") or "").strip()
    return bool(code) and uid == _user_id_for(code)


@app.route("/admin")
def admin_stats():
    """What is actually happening in MinitAI. Counts only - never anyone's
    meeting content, titles or file names."""
    uid = require_user()
    if not _is_admin(uid):
        abort(404)                     # never confirm the endpoint exists
    now = time.time()
    today = _quota_day()
    with _jobs_lock:
        jobs = list(JOBS.values())
    people, minutes = set(), 0
    for d in os.listdir(DATA_ROOT) if os.path.isdir(DATA_ROOT) else []:
        if not d.startswith("u_"):
            continue
        try:
            q = json.load(open(os.path.join(DATA_ROOT, d, "quota.json")))
            if q.get("day") == today and q.get("minutes"):
                people.add(d)
                minutes += int(q["minutes"])
        except Exception:
            pass
    try:
        svc = json.load(open(_SERVICE_QUOTA))
        svc_min = int(svc.get("minutes", 0)) if svc.get("day") == today else 0
    except Exception:
        svc_min = 0
    return jsonify({
        "counted_since": _STARTED_AT,
        "counted_for_seconds": int(now - _STARTED_AT),
        "warning": ("These counters live on a disk that is wiped whenever the "
                    "free instance sleeps. They show usage since the last "
                    "restart, not the true daily total. Groq's own console is "
                    "the only authoritative figure."),
        "today": {
            "people_who_used_it": len(people),
            "minutes_charged_to_people": minutes,
            "service_minutes_counted": svc_min,
            "service_daily_cap": SERVICE_DAILY_MINUTES,
            "per_person_cap": MAX_MINUTES_PER_USER_PER_DAY,
        },
        "jobs_in_memory": {
            "running": sum(1 for j in jobs if j.get("state") not in ("done", "error")),
            "done": sum(1 for j in jobs if j.get("state") == "done"),
            "failed": sum(1 for j in jobs if j.get("state") == "error"),
        },
        "codes": sorted(
            [{
                # The label is what Gavril needs to know which code to reissue;
                # the random half stays masked even here.
                "label": (c.split("-")[0] if "-" in c else c[:6]),
                "masked": (c.split("-")[0] + "-****" if "-" in c else c[:3] + "***"),
                "used": bool(_load_profile(_user_id_for(c))),
                "name": _load_profile(_user_id_for(c)).get("name", ""),
                "org": _load_profile(_user_id_for(c)).get("org", ""),
                "first_seen": _load_profile(_user_id_for(c)).get("first_seen", 0),
                "last_seen": _load_profile(_user_id_for(c)).get("last_seen", 0),
                "sign_ins": _load_profile(_user_id_for(c)).get("sign_ins", 0),
             } for c in _invite_codes()],
            key=lambda x: (not x["used"], x["label"])),
        "invite_codes_configured": len(_invite_codes()),
        "speaker_labels": cloud.diarisation_available(),
        "google_drive": bool((os.environ.get("GOOGLE_CLIENT_ID") or "").strip()),
        "retention_hours": RETENTION_HOURS,
    })


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
#recBar{display:flex;gap:9px}
button.rec{background:var(--card2);border:1px solid var(--line);color:var(--txt);
font-size:13px;padding:11px 8px;border-radius:10px}
button.rec.big{flex:1;padding:18px 10px;font-size:14px;font-weight:600;
display:flex;flex-direction:column;align-items:center;gap:7px;
background:linear-gradient(165deg,#232a3d,#1b2130);border-color:#33405c}
button.rec.big:hover:not(:disabled){border-color:var(--blue);
background:linear-gradient(165deg,#28324a,#1d2436)}
button.rec.big .ic{font-size:19px;color:var(--blue);line-height:1}
#recMic .ic{color:#F87171}
#orRow{display:flex;align-items:center;gap:10px;margin:14px 0 10px;
color:var(--muted);font-size:12px}
#orRow:before,#orRow:after{content:'';flex:1;height:1px;background:var(--line)}
#drop{padding:20px 16px}
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
/* --- the first thing anybody sees --- */
body:has(#loginCard:not(.hide)){background:
  radial-gradient(60rem 40rem at 15% -10%, #24356b 0%, transparent 60%),
  radial-gradient(50rem 34rem at 95% 8%, #3a2a5e 0%, transparent 55%),
  var(--bg);
  background-attachment:fixed}
#loginCard{animation:rise .5s cubic-bezier(.2,.8,.2,1) both}
@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
#welcome{text-align:center;margin-bottom:22px}
#welcome h2{font-size:19px;margin:12px 0 6px;color:var(--txt);font-weight:600}
#welcome p{font-size:13px;color:var(--muted);line-height:1.65;margin:0 auto;
max-width:32ch}
#hello{display:block;margin:0 auto}
#helloBody{transform-origin:48px 61px;animation:hover 4s ease-in-out infinite}
@keyframes hover{0%,100%{transform:translateY(0)}50%{transform:translateY(-4px)}}
#helloEyes{transform-origin:48px 40px;animation:botblink 5s infinite}
#helloTip{animation:tip 2.6s ease-in-out infinite}
@keyframes tip{0%,100%{opacity:.55}50%{opacity:1}}
#helloArm{transform-origin:80px 46px;animation:wave 3.4s ease-in-out infinite}
@keyframes wave{0%,72%,100%{transform:rotate(0)}
80%{transform:rotate(-24deg)}88%{transform:rotate(6deg)}}
#pills{display:flex;flex-wrap:wrap;gap:6px;justify-content:center;margin-top:14px}
#pills span{font-size:11px;color:#A9B6D4;background:var(--card2);
border:1px solid var(--line);border-radius:999px;padding:5px 10px}
#code:focus{outline:none;border-color:var(--blue);
box-shadow:0 0 0 3px rgba(74,110,224,.18)}
@media (prefers-reduced-motion:reduce){
  #helloBody,#helloEyes,#helloArm,#helloTip,#loginCard,#botBob{animation:none}}
/* --- the microphone gate --- */
#micGate{text-align:center;padding:22px 16px;background:var(--card2);
border:1px solid var(--line);border-radius:14px;margin-bottom:16px;
animation:rise .35s ease both}
#micGate h3{font-size:16px;margin:10px 0 6px;color:var(--txt)}
#micGate p{font-size:13px;color:var(--muted);line-height:1.65;margin:0 auto 14px;
max-width:38ch}
#micGate svg{display:block;margin:0 auto}
#appCard.gated > *:not(#micGate){display:none}
/* --- how much is left today --- */
#quotaChip{background:var(--card2);border:1px solid var(--line);border-radius:12px;
padding:11px 13px;margin-bottom:14px}
#quotaChip .qtop{display:flex;justify-content:space-between;align-items:baseline;
font-size:13px;margin-bottom:7px;gap:8px}
#quotaLeft{color:var(--txt);font-weight:600}
#quotaOf{color:var(--muted);font-size:12px;white-space:nowrap}
.qbar{height:6px;background:#171b26;border-radius:6px;overflow:hidden}
.qreset{font-size:11px;color:var(--muted);margin-top:7px}
.qbar>i{display:block;height:100%;width:0;background:var(--blue);
transition:width .5s ease}
#quotaChip.low .qbar>i{background:#FBBF24}
#quotaChip.out .qbar>i{background:var(--red)}
#quotaChip.out #quotaLeft{color:#F87171}
/* --- collapsed options --- */
#adv{margin-top:14px;border:1px solid var(--line);border-radius:12px;
padding:0 12px;background:var(--card2)}
#adv[open]{padding-bottom:10px}
#adv>summary{cursor:pointer;padding:13px 0;font-size:13px;color:var(--muted);
list-style:none}
#adv>summary::-webkit-details-marker{display:none}
#adv>summary::after{content:'\u00a0\u25be';float:right}
#adv[open]>summary::after{content:'\u00a0\u25b4'}
/* --- what you actually got --- */
#preview{background:var(--card2);border:1px solid var(--line);border-radius:12px;
padding:14px;margin-top:12px}
#preview h3{margin:0 0 2px;font-size:15px;color:var(--txt)}
#preview .meta{font-size:12px;color:var(--muted);margin-bottom:10px}
#preview ol{margin:0;padding-left:18px;font-size:13px;line-height:1.7}
#preview li{margin-bottom:2px}
#preview .dec{color:var(--muted)}
#preview .more{font-size:12px;color:var(--muted);margin-top:8px}
/* --- help bubble --- */
#helpBubble{position:fixed;right:18px;bottom:18px;width:60px;height:60px;
border-radius:50%;background:linear-gradient(160deg,#3B5BDB,#2B3EA8);border:0;
cursor:pointer;padding:0;display:flex;align-items:center;justify-content:center;
box-shadow:0 8px 22px rgba(0,0,0,.5);z-index:50;transition:transform .18s}
#helpBubble:hover{transform:translateY(-3px) scale(1.05)}
#botBob{transform-origin:24px 30px;animation:bob 3.6s ease-in-out infinite}
@keyframes bob{0%,100%{transform:translateY(0) rotate(0)}
50%{transform:translateY(-1.6px) rotate(-2deg)}}
#botEyes{animation:botblink 5.2s infinite}
@keyframes botblink{0%,94%,100%{transform:scaleY(1)}
96%{transform:scaleY(.12)}}
#botEyes{transform-origin:24px 24px}
#helpBubble:hover #botSmile{d:path('M19 32q5 3.6 10 0')}
#botPing{position:absolute;top:4px;right:4px;width:11px;height:11px;
border-radius:50%;background:#FFD500;box-shadow:0 0 0 2px #1a1d27}
#helpPanel{position:fixed;right:18px;bottom:84px;width:min(340px,calc(100vw - 36px));
background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;
box-shadow:0 10px 30px rgba(0,0,0,.5);z-index:50}
#helpHead{display:flex;justify-content:space-between;align-items:center;
font-size:14px;margin-bottom:8px}
#helpClose{cursor:pointer;color:var(--muted);font-size:20px;line-height:1}
#helpLog{max-height:230px;overflow-y:auto;font-size:13px;line-height:1.6;
margin-bottom:8px}
#helpLog .q{color:var(--muted);margin-top:8px}
#helpLog .a{color:var(--txt);margin-top:2px}
/* --- edit before export --- */
#editForm{margin-top:10px}
#editForm .row{background:var(--card2);border:1px solid var(--line);
border-radius:10px;padding:10px;margin-top:8px}
#editForm .row .n{font-size:11px;color:var(--muted);margin-bottom:4px}
#adminOut .row{background:var(--card2);border:1px solid var(--line);
border-radius:10px;padding:10px;margin-top:8px;font-size:13px}
#adminOut .n{font-size:12px;color:var(--muted);margin-top:4px}
#editForm input,#editForm textarea{width:100%;background:var(--card);
border:1px solid var(--line);border-radius:8px;color:var(--txt);
font-size:13px;padding:8px;font-family:inherit;margin-bottom:6px}
#editForm textarea{min-height:52px;resize:vertical}
#editForm h4{font-size:12px;color:var(--muted);margin:16px 0 2px;
text-transform:uppercase;letter-spacing:.4px}
</style></head><body><div class="wrap">
<h1>MinitAI<span id="h1name" style="font-weight:400;color:var(--muted)"></span></h1>
<div class="sub">Meeting audio in. Professional minutes out.</div>

<div class="card {{ 'hide' if signed_in else '' }}" id="loginCard">
  <div id="welcome">
    <svg viewBox="0 0 96 84" width="104" height="92" aria-hidden="true" id="hello">
      <ellipse cx="48" cy="78" rx="26" ry="4" fill="#000" opacity=".28"/>
      <g id="helloBody">
        <line x1="48" y1="12" x2="48" y2="19" stroke="#7E9BE0" stroke-width="2.4"/>
        <circle cx="48" cy="9" r="4" fill="#FFD500" id="helloTip"/>
        <rect x="20" y="19" width="56" height="42" rx="15" fill="#EAF0FF"/>
        <rect x="28" y="30" width="40" height="20" rx="10" fill="#161B29"/>
        <g id="helloEyes" fill="#8FB4FF">
          <circle cx="39" cy="40" r="4.4"/><circle cx="57" cy="40" r="4.4"/>
        </g>
        <path d="M41 54q7 4 14 0" stroke="#9FB2D8" stroke-width="2.2"
              fill="none" stroke-linecap="round"/>
        <rect x="11" y="33" width="7" height="13" rx="3.5" fill="#CBD9FF"/>
        <g id="helloArm"><rect x="78" y="33" width="7" height="13" rx="3.5"
             fill="#CBD9FF"/></g>
      </g>
    </svg>
    <h2>Minutes, without the typing.</h2>
    <p>Record a meeting in Malay or English. Get formal minutes, slides and a
      full transcript in a few minutes.</p>
    <div id="pills">
      <span>Malay &middot; English &middot; rojak</span>
      <span>Word + slides + transcript</span>
      <span>Nothing kept afterwards</span>
    </div>
  </div>
  <label for="who">Your name</label>
  <input id="who" autocomplete="name" placeholder="e.g. Dr. Hafizah" maxlength="60">
  <label for="org">Where you are from</label>
  <input id="org" placeholder="e.g. FSSK, UMS" maxlength="80">
  <label for="code">Invite code</label>
  <input id="code" type="password" autocomplete="one-time-code" placeholder="Enter your invite code">
  <button id="loginBtn">Sign in</button>
  <div class="msg err hide" id="loginMsg"></div>
  <div class="note" style="text-align:center">No code? Ask Gavril for yours.</div>
</div>

<div class="card {{ '' if signed_in else 'hide' }}" id="appCard">
  <div id="micGate" class="hide">
    <svg viewBox="0 0 24 32" width="34" height="44" aria-hidden="true">
      <rect x="7" y="1" width="10" height="17" rx="5" fill="#EAF0FF"/>
      <path d="M3 14a9 9 0 0 0 18 0" stroke="#8FB4FF" stroke-width="2.2"
            fill="none" stroke-linecap="round"/>
      <line x1="12" y1="23" x2="12" y2="29" stroke="#8FB4FF" stroke-width="2.2"
            stroke-linecap="round"/>
    </svg>
    <h3>Let MinitAI hear the meeting</h3>
    <p>Your browser will ask for the microphone. Say <b>Allow</b> once and it is
      remembered. Doing this now means you are not fumbling with permissions
      when the meeting has already started &mdash; and it is how we make sure you
      never record an hour of silence.</p>
    <button type="button" id="micAllow">Allow the microphone</button>
    <button type="button" class="rec" id="micSkip"
            style="width:100%;margin-top:8px">I will only upload files</button>
    <div class="note hide" id="micGateErr"></div>
  </div>

  <div id="quotaChip" class="hide">
    <div class="qtop"><span id="quotaLeft"></span><span id="quotaOf"></span></div>
    <div class="qbar"><i id="quotaFill"></i></div>
    <div class="qreset" id="quotaReset"></div>
  </div>
  <div id="recBar">
    <button type="button" class="rec big" id="recMic">
      <span class="ic">&#9679;</span>Record the room</button>
    <button type="button" class="rec big" id="recTab">
      <span class="ic">&#9974;</span>Record an online meeting</button>
  </div>
  <div class="note" id="recNote" style="margin-top:6px"></div>
  <div class="note hide" id="micWarn" style="margin-top:6px"></div>

  <label for="lang" style="margin-top:12px">Language spoken in the meeting</label>
  <select id="lang">
    <option value="" selected>Detect automatically</option>
    <option value="ms">Malay / Manglish</option>
    <option value="en">English</option>
    <option value="zh">Mandarin</option>
    <option value="ta">Tamil</option>
  </select>

  <div id="orRow"><span>or</span></div>
  <div id="drop">Choose a recording &mdash; or drop it here<br>
    <span style="font-size:12px">audio, video, or a PDF / Word / PowerPoint to
      summarise</span></div>
  <input id="file" type="file" class="hide"
         accept="audio/*,video/*,.pdf,.docx,.pptx,.ppt,.txt,.md">


  <div id="recLive" class="hide">
    <div><span id="recDot"></span><span id="recTime">0:00</span></div>
    <div id="recMeter"><i></i></div>
    <div class="note" style="margin-top:6px" id="recHint"></div>
    <div class="note hide" id="recQuiet">No sound is reaching the microphone.</div>
    <button type="button" class="rec" id="recPause"
            style="width:100%;margin-top:10px">Pause</button>
    <button type="button" id="recStop">Stop and use this recording</button>
  </div>

  <details id="adv">
  <summary>Meeting details and options</summary>



  <label for="style">What kind of document do you want?</label>
  <select id="style">
    <option value="minutes" selected>Formal minutes &mdash; full official record</option>
    <option value="executive">Executive summary &mdash; decisions and consequences only</option>
    <option value="detailed">Detailed report &mdash; capture everything, nothing left out</option>
    <option value="actions">Action list &mdash; who does what, by when</option>
  </select>

  <label for="focus">Anything specific you want from this meeting? (optional)</label>
  <div class="note" style="margin:0 0 6px">
    If the meeting did not cover it, MinitAI says nothing rather than
    inventing.</div>
  <input id="focus" maxlength="600"
         placeholder="e.g. only the budget decisions &middot; what was agreed about the intake &middot; every deadline given to me">

  <label for="hints">Names it might not know (optional)</label>
  <div class="note" style="margin:0 0 6px">
    Abbreviations, course codes, anything unusual.</div>
  <input id="hints" placeholder="e.g. UMS, FSSK, Dr Aminah, Prof Lim, Bil 1/2026">

  <label for="prev">Last meeting's minutes (optional)</label>
  <div class="note" style="margin:0 0 6px">Opens the summary with
    <b>Perkara Berbangkit</b>. Read once, never kept.</div>
  <input id="prev" type="file" accept=".pdf,.docx,.txt,.md"
         style="width:100%;background:var(--card2);border:1px solid var(--line);
                border-radius:10px;color:var(--muted);font-size:13px;padding:9px">

  <div id="spkWrap" class="hide">
    <label style="display:flex;align-items:center;gap:8px;margin-top:14px">
      <input type="checkbox" id="speakers" style="width:auto;margin:0">
      <span>Label who said what</span></label>
    <div class="note" style="margin:2px 0 0">Slower. Audio goes to AssemblyAI
      instead of Groq.</div>
  </div>

  <label for="roster">Who was there? (optional)</label>
  <div class="note" style="margin:0 0 6px">One per line. Fills KEHADIRAN and
    fixes the spelling.</div>
  <textarea id="roster" rows="3"
    placeholder="Dr. Hafizah&#10;Prof. Madya Dr. Maurin&#10;Puan Marja"
    style="width:100%;background:var(--card2);border:1px solid var(--line);
           border-radius:10px;color:var(--txt);font-size:14px;padding:11px;
           font-family:inherit;resize:vertical"></textarea>

  </details>

  <button id="go" disabled>Choose a recording first</button>
  <div class="bar hide" id="barWrap"><i id="bar"></i></div>
  <div class="msg" id="msg" role="status" aria-live="polite"></div>
  <div id="drivePast" class="hide">
    <label style="margin-top:4px">Your meetings in Google Drive</label>
    <div class="note" style="margin:0 0 6px">Saved permanently in your own Drive
      &mdash; these survive even though the server clears itself.</div>
    <div id="drivePastList"></div>
  </div>

  <div id="driveWrap" class="hide">
    <button type="button" class="rec" id="driveBtn"
            style="width:100%;margin-top:10px">Save a copy to my Google Drive</button>
    <label id="driveAutoWrap" style="display:flex;align-items:center;gap:8px;
           margin-top:8px;font-size:12px;color:var(--muted)">
      <input type="checkbox" id="driveAuto" style="width:auto;margin:0">
      <span>Do this automatically from now on</span></label>
    <div class="note hide" id="driveOut"></div>
  </div>

  <div id="preview" class="hide"></div>
  <div id="files"></div>

  <div id="recentWrap" class="hide">
    <label style="margin-top:18px">Recent documents</label>
    <div class="note" style="margin:0 0 6px">Still here if you closed the page
      or refreshed by accident. These sit on the server, and the server clears
      them when it goes to sleep &mdash; often within the hour, and after
      {{ retention }} hours at the latest. Save anything you want to keep.</div>
    <div id="recent"></div>

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

  <div class="note hide" id="quota"></div>

  <div id="adminWrap" class="hide">
    <label style="margin-top:18px">Admin</label>
    <button type="button" class="rec" id="adminBtn"
            style="width:100%">Show usage across everyone</button>
    <div id="adminOut" class="hide"></div>
  </div>

  <div id="histWrap" class="hide">
    <label style="margin-top:18px">Your past meetings</label>
    <div class="note" style="margin:0 0 6px">Kept in this browser only, never on
      the server. Clearing your browser data clears these.</div>
    <select id="histPick"></select>
    <input id="askQ" placeholder="Ask about this meeting, e.g. apa keputusan pasal yuran?"
           style="margin-top:8px">
    <button type="button" class="rec" id="askBtn"
            style="width:100%;margin-top:8px">Ask</button>
    <div class="note hide" id="askOut"></div>
  </div>


  </div>
  <div class="note" style="text-align:right">
    <a href="#" id="signout" style="color:var(--muted)">Sign out</a></div>
  <div class="note">Audio goes to <b>Groq in the United States</b> to be
    transcribed. Not for confidential meetings.
    <a href="#" id="privLink" style="color:var(--muted)">Privacy and your data</a></div>
  <div id="priv" class="hide">
    <div class="note">Sending your recording to Groq is a transfer outside
      Malaysia &mdash; by uploading you agree to it, and you should have
      everyone's agreement before recording them at all. Groq deletes the audio
      after transcribing. Documents are handed straight to your browser; a
      short-lived copy stays on the server so a refresh cannot lose them, and
      that copy goes when the server sleeps. For confidential meetings use the
      desktop version, which never uploads anything.</div>
    <button type="button" class="rec" id="wipeBtn"
            style="width:100%;margin-top:8px">Delete everything of mine on the server</button>
    <div class="note hide" id="wipeMsg"></div>
  </div>
</div>

<!-- Help lives in a corner, not in the page. The old version put it 3,200px
     down a 4,100px page: you pressed Ask, the answer rendered far below the
     fold, and it looked broken. -->
<button type="button" id="helpBubble" aria-label="Help">
  <svg id="bot" viewBox="0 0 48 48" width="40" height="40" aria-hidden="true">
    <g id="botBob">
      <line x1="24" y1="7" x2="24" y2="12" stroke="#BFD3FF" stroke-width="2"/>
      <circle cx="24" cy="5" r="2.6" fill="#FFD500"/>
      <rect x="8" y="12" width="32" height="24" rx="9" fill="#EAF0FF"/>
      <rect x="13" y="18" width="22" height="12" rx="6" fill="#1E2761"/>
      <g id="botEyes" fill="#8FB4FF">
        <circle cx="19.5" cy="24" r="2.7"/><circle cx="28.5" cy="24" r="2.7"/>
      </g>
      <path id="botSmile" d="M20 32.5q4 2.6 8 0" stroke="#9FB2D8"
            stroke-width="1.6" fill="none" stroke-linecap="round"/>
      <rect x="3" y="21" width="4" height="7" rx="2" fill="#CBD9FF"/>
      <rect x="41" y="21" width="4" height="7" rx="2" fill="#CBD9FF"/>
    </g>
  </svg>
  <span id="botPing" class="hide"></span></button>
<div id="helpPanel" class="hide">
  <div id="helpHead"><b>MinitAI help</b>
    <span id="helpClose" role="button" aria-label="Close">&times;</span></div>
  <div id="helpLog"></div>
  <input id="helpQ" placeholder="Tanya apa-apa / ask me anything">
  <button type="button" id="helpBtn">Ask</button>
  <div class="note" style="margin-top:8px">
    <a id="fbLink" href="#" style="color:var(--muted)">Tell Gavril something is wrong</a></div>
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
    body:JSON.stringify({code, name:($('who')||{}).value||'',
      org:($('org')||{}).value||''})});
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
  if(await micState()==='denied'){ micBlocked(); return; }
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

// ------------------------------------------------------------ microphone
// Ask once, on the way in. Discovering the browser has blocked the microphone
// AFTER an hour-long meeting is the worst possible moment to find out, and the
// prompt only appears when you press Record, which is exactly too late.
async function micState(){
  try{
    if(!navigator.permissions || !navigator.permissions.query) return 'unknown';
    var st = await navigator.permissions.query({name:'microphone'});
    return st.state;                       // granted | denied | prompt
  }catch(e){ return 'unknown'; }
}
function micBlocked(){
  $('micWarn').classList.remove('hide');
  $('micWarn').innerHTML='<b>The microphone is blocked for this site.</b> '
    +'Recording will capture nothing. Click the padlock in the address bar, '
    +'set Microphone to Allow, then reload.';
  $('recMic').disabled=true; $('recTab').disabled=true;
}
async function askMic(){
  try{
    var st=await navigator.mediaDevices.getUserMedia({audio:true});
    st.getTracks().forEach(function(t){ t.stop(); });   // we only wanted the yes
    $('micWarn').classList.add('hide');
    $('recMic').disabled=false;
    if(CAN_TAB) $('recTab').disabled=false;
    return true;
  }catch(e){ micBlocked(); return false; }
}
async function micCheck(){
  if(!CAN_MIC) return;
  var st=await micState();
  if(st==='denied'){ micBlocked(); return; }
  if(st==='granted'){ $('micWarn').classList.add('hide'); return; }
  // Not decided yet: ask now, in front of everything, rather than letting the
  // browser spring the question mid-meeting.
  var skipped=false;
  try{ skipped = localStorage.getItem('minitai.micSkip')==='1'; }catch(e){}
  if(skipped) return;
  $('micGate').classList.remove('hide');
  $('appCard').classList.add('gated');
}

function closeGate(){
  $('micGate').classList.add('hide');
  $('appCard').classList.remove('gated');
}

$('micAllow').onclick=async function(){
  $('micAllow').disabled=true; $('micAllow').textContent='Waiting for your answer\u2026';
  var ok=await askMic();
  $('micAllow').disabled=false; $('micAllow').textContent='Allow the microphone';
  if(ok){ closeGate(); return; }
  $('micGateErr').classList.remove('hide');
  $('micGateErr').innerHTML='Blocked. Click the padlock in the address bar, set '
    +'Microphone to Allow, then reload. You can still upload files without it.';
};
$('micSkip').onclick=function(){
  try{ localStorage.setItem('minitai.micSkip','1'); }catch(e){}
  closeGate();
};

// --------------------------------------------------------------- history
// Meetings are remembered in this browser because the server cannot keep them:
// its disk is wiped whenever the free instance sleeps.
var HIST_KEY='minitai.history', HIST_MAX=15;
function histLoad(){ try{ return JSON.parse(localStorage.getItem(HIST_KEY)||'[]'); }catch(e){ return []; } }
function histSave(list){ try{ localStorage.setItem(HIST_KEY,JSON.stringify(list)); }catch(e){} }
function histAdd(title, transcript){
  if(!transcript) return;
  var list=histLoad();
  list.unshift({t:title||'Mesyuarat', d:new Date().toISOString().slice(0,16).replace('T',' '),
                x:String(transcript).slice(0,60000)});
  while(list.length>HIST_MAX) list.pop();
  // Storage is finite; drop the oldest until it fits rather than throwing.
  for(;;){ try{ histSave(list); break; }catch(e){ if(list.length<2) break; list.pop(); } }
  histRender();
}
function histRender(){
  var list=histLoad(), sel=$('histPick');
  if(!list.length){ $('histWrap').classList.add('hide'); return; }
  $('histWrap').classList.remove('hide');
  sel.innerHTML='';
  list.forEach(function(m,i){
    var o=document.createElement('option'); o.value=i; o.textContent=m.d+'  -  '+m.t;
    sel.appendChild(o);
  });
}
$('askBtn').onclick=async function(){
  var list=histLoad(), m=list[parseInt($('histPick').value,10)||0];
  var q=$('askQ').value.trim();
  if(!m||!q){ return; }
  $('askOut').classList.remove('hide'); $('askOut').textContent='Thinking\u2026';
  try{
    var r=await fetch('/ask',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({q:q,transcript:m.x})});
    var j=await r.json();
    $('askOut').textContent=j.answer||j.error||'No answer.';
  }catch(e){ $('askOut').textContent='Could not ask just now.'; }
};

// ------------------------------------------------------------------ help
function helpSay(cls, text){
  var d=document.createElement('div'); d.className=cls; d.textContent=text;
  $('helpLog').appendChild(d); $('helpLog').scrollTop=$('helpLog').scrollHeight;
  return d;
}
$('helpBubble').onclick=function(){
  var p=$('helpPanel'); p.classList.toggle('hide');
  if(!p.classList.contains('hide')){
    if(!$('helpLog').children.length)
      helpSay('a','Hi! Ask me anything about MinitAI \u2014 in Malay or English.');
    $('helpQ').focus();
  }
};
$('helpClose').onclick=function(){ $('helpPanel').classList.add('hide'); };
$('helpBtn').onclick=async function(){
  var q=$('helpQ').value.trim(); if(!q) return;
  helpSay('q','You: '+q); $('helpQ').value='';
  var waiting=helpSay('a','Thinking\u2026');
  try{
    var r=await fetch('/help',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({q:q})});
    var j=await r.json();
    waiting.textContent=j.answer||'Ask Gavril.';
  }catch(e){ waiting.textContent='Help is unavailable right now. Ask Gavril.'; }
};
$('helpQ').addEventListener('keydown',function(e){ if(e.key==='Enter')$('helpBtn').click(); });

// Feedback goes straight to Gavril as an email rather than into a box on a
// server that wipes itself - a comment nobody ever reads is worse than none.
$('fbLink').onclick=function(e){
  e.preventDefault();
  var body=encodeURIComponent('What I was doing:\\n\\nWhat happened:\\n\\n'
    +'What I expected:\\n\\n---\\nBrowser: '+navigator.userAgent);
  window.location.href='mailto:chunghaow@gmail.com?subject='
    +encodeURIComponent('MinitAI feedback')+'&body='+body;
};

try{ histRender(); }catch(e){}
try{ micCheck(); }catch(e){}
// The server's disk is wiped when it sleeps, so the browser re-asserts the
// name on every sign-in and the record repairs itself.
try{
  [['who','minitai.name'],['org','minitai.org']].forEach(function(p){
    var v=localStorage.getItem(p[1]);
    if(v && $(p[0])) $(p[0]).value=v;
    if($(p[0])) $(p[0]).addEventListener('blur',function(){
      try{ localStorage.setItem(p[1], $(p[0]).value); }catch(e){}
    });
  });
}catch(e){}
try{ setTimeout(driveReconnect, 1200); }catch(e){}

// "Try again tomorrow" is useless without knowing when tomorrow starts.
var quotaResetAt=0;
function tickReset(){
  if(!quotaResetAt){ $('quotaReset').textContent=''; return; }
  var secs=Math.max(0, quotaResetAt - Date.now()/1000);
  if(secs<=0){ $('quotaReset').textContent='Refreshing\u2026'; loadMe(); return; }
  var h=Math.floor(secs/3600), m=Math.floor((secs%3600)/60);
  var when=new Date(quotaResetAt*1000)
    .toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
  $('quotaReset').textContent='Resets in '
    + (h ? h+' h ' + m + ' min' : m + ' min')
    + ' \u2014 at ' + when + ' your time.';
}
setInterval(tickReset, 30000);

$('adminBtn').onclick=async function(){
  var o=$('adminOut'); o.classList.remove('hide'); o.textContent='Loading\u2026';
  try{
    var j=await fetch('/admin').then(function(r){ return r.json(); });
    var t=j.today||{}, jb=j.jobs_in_memory||{};
    var mins=Math.floor((j.counted_for_seconds||0)/60);
    o.innerHTML=
      '<div class="row"><b>Today, since the last restart</b>'
      +'<div class="n">'+t.people_who_used_it+' of '+j.invite_codes_configured
      +' people &middot; '+t.minutes_charged_to_people+' min charged</div>'
      +'<div class="n">Service total '+t.service_minutes_counted+' / '
      +t.service_daily_cap+' min &middot; cap per person '+t.per_person_cap+' min</div>'
      +'<div class="n">Jobs: '+jb.running+' running, '+jb.done+' done, '
      +jb.failed+' failed</div></div>'
      +'<div class="row"><b>Invite codes</b>'
      + (j.codes||[]).map(function(c){
          var who = c.name || '';
          if(c.org) who += (who ? ' \u00b7 ' : '') + c.org;
          var when = c.first_seen
            ? new Date(c.first_seen*1000).toLocaleDateString() : '';
          var seen = c.last_seen
            ? new Date(c.last_seen*1000).toLocaleString([], {dateStyle:'short',
                                                            timeStyle:'short'}) : '';
          return '<div class="n">' + (c.used ? '\u25CF ' : '\u25CB ')
            + esc(c.masked) + ' \u2014 '
            + (c.used
                ? esc(who || 'used, no name given')
                  + (when ? '<br><span style="opacity:.7">joined ' + esc(when)
                            + ' \u00b7 last seen ' + esc(seen)
                            + ' \u00b7 ' + (c.sign_ins||0) + ' sign-ins</span>' : '')
                : 'never used')
            + '</div>';
        }).join('')
      +'</div>'
      +'<div class="row"><b>Switches</b><div class="n">'
      +'Speaker labels ' + (j.speaker_labels?'on':'off')
      +' &middot; Google Drive ' + (j.google_drive?'on':'off')
      +' &middot; retention ' + j.retention_hours + 'h</div></div>'
      +'<div class="note" style="color:#FBBF24">Counting for '+mins+' min. '
      + j.warning + '</div>';
  }catch(e){ o.textContent='Could not load the admin view.'; }
};

$('privLink').onclick=function(e){
  e.preventDefault(); $('priv').classList.toggle('hide');
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
  fd.append('speakers',$('speakers') && $('speakers').checked ? '1' : '0');
  if($('prev') && $('prev').files && $('prev').files[0]) fd.append('prev',$('prev').files[0]);
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
  $('barWrap').classList.add('hide');$('go').disabled=false;
  loadMe();}   // a failed job refunds the minutes; show that straight away
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
    renderFiles(j.files, false);   // nothing saves itself; you choose
    driveFiles = j.files;
    if(window.MINITAI_GOOGLE){
      $('driveWrap').classList.remove('hide');
      $('driveOut').classList.add('hide');
      if($('driveAuto').checked) driveSave(driveFiles, true);
    }
    lastAnalysis = j.analysis || null;
    if(lastAnalysis){ $('editOpen').classList.remove('hide'); showPreview(lastAnalysis); }
    try{
      var tv=(j.files||{}).transcript;
      if(tv && tv.data) histAdd(j.title, decodeURIComponent(escape(atob(tv.data))));
    }catch(e){}
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
    '<div class="note">Nothing has been saved to your computer yet \u2014 tap '
    +'whichever you want.</div>');
  addShare(files);
  // Only ONE automatic download. Browsers challenge the second and third
  // with a "allow multiple downloads?" prompt that people dismiss, and the
  // files were then lost. The rest stay one tap away, and Recent documents
  // below survives a refresh.
  if(first&&autoSave)setTimeout(function(){try{first.click();}catch(e){}},400);
}

// ------------------------------------------------------------ Google Drive
// Browser to Google directly. The token never touches the MinitAI server, and
// the scope is drive.file, which grants access ONLY to files this app puts
// there - it cannot see anything else in your Drive.
//
// Google's script is loaded lazily, on the first click. Someone who never uses
// Drive still loads a page that fetches nothing from the internet.
var GIS_SRC='https://accounts.google.com/gsi/client';
var driveToken=null, driveTokenClient=null, driveFiles=null, gisReady=null;

function loadGis(){
  // Only cache SUCCESS. Caching the rejection meant one failed attempt poisoned
  // every later click, so the button stayed broken even after the cause was
  // gone.
  if(window.google && google.accounts && google.accounts.oauth2)
    return Promise.resolve();
  if(gisReady) return gisReady;
  gisReady=new Promise(function(res,rej){
    var t=document.createElement('script');
    t.src=GIS_SRC; t.async=true; t.defer=true;
    t.onload=function(){ res(); };
    t.onerror=function(){
      gisReady=null;                       // let the next click try again
      rej(new Error("Google's sign-in script was blocked before it loaded. "
        + "This is almost always an ad or privacy blocker - check for a blocked "
        + "request to accounts.google.com and allow this site."));
    };
    document.head.appendChild(t);
    // Some blockers neither load nor fire onerror; they just swallow it.
    setTimeout(function(){
      if(!(window.google && google.accounts)){
        gisReady=null;
        rej(new Error("Google's sign-in script did not load. An ad or privacy "
          + "blocker is the usual cause - allow accounts.google.com for this site."));
      }
    }, 12000);
  });
  return gisReady;
}

async function driveAuth(clientId){
  if(driveToken) return driveToken;
  await loadGis();
  return new Promise(function(res,rej){
    try{
      driveTokenClient = google.accounts.oauth2.initTokenClient({
        client_id: clientId,
        scope: 'https://www.googleapis.com/auth/drive.file',
        callback: function(r){
          if(r && r.access_token){ driveToken=r.access_token; res(driveToken); }
          else rej(new Error('Google did not grant access.'));
        },
        error_callback: function(){ rej(new Error('Google sign-in was closed.')); }
      });
      driveTokenClient.requestAccessToken({prompt: driveToken ? '' : 'consent'});
    }catch(e){ rej(e); }
  });
}

// One folder, so a year of meetings is not scattered through My Drive.
async function driveFolder(token){
  var q=encodeURIComponent(
    "mimeType='application/vnd.google-apps.folder' and name='MinitAI' and trashed=false");
  var r=await fetch('https://www.googleapis.com/drive/v3/files?q='+q+'&fields=files(id)',
    {headers:{Authorization:'Bearer '+token}});
  var j=await r.json();
  if(j.files && j.files.length) return j.files[0].id;
  var mk=await fetch('https://www.googleapis.com/drive/v3/files',
    {method:'POST',headers:{Authorization:'Bearer '+token,
      'Content-Type':'application/json'},
     body:JSON.stringify({name:'MinitAI',
       mimeType:'application/vnd.google-apps.folder'})});
  return (await mk.json()).id;
}

async function blobOf(v){
  if(v.data){
    var bin=atob(v.data), buf=new Uint8Array(bin.length);
    for(var i=0;i<bin.length;i++)buf[i]=bin.charCodeAt(i);
    return new Blob([buf]);
  }
  // Too big to travel inline; fetch it back from the signed link.
  var r=await fetch(v.url);
  if(!r.ok) throw new Error('Could not read '+v.name);
  return await r.blob();
}

async function driveUpload(token, folder, name, blob, mime){
  var meta={name:name, parents:[folder]};
  var body=new FormData();
  body.append('metadata', new Blob([JSON.stringify(meta)],{type:'application/json'}));
  body.append('file', blob);
  var r=await fetch(
    'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,webViewLink',
    {method:'POST',headers:{Authorization:'Bearer '+token},body:body});
  if(!r.ok) throw new Error('Google rejected '+name+' ('+r.status+')');
  return await r.json();
}

async function driveSave(files, silent){
  var cid=(window.MINITAI_GOOGLE||'');
  if(!cid || !files) return;
  var out=$('driveOut'); out.classList.remove('hide');
  out.textContent='Saving to Google Drive\u2026';
  try{
    var token=await driveAuth(cid);
    var folder=await driveFolder(token);
    var links=[];
    for(var k in files){
      if(!files.hasOwnProperty(k)) continue;
      var v=files[k];
      var got=await driveUpload(token, folder, v.name, await blobOf(v),
                                FILE_MIME[k]||'application/octet-stream');
      if(got.webViewLink) links.push({name:v.name, url:got.webViewLink});
    }
    try{ localStorage.setItem('minitai.driveLinked','1'); }catch(e){}
    out.innerHTML='Saved to the <b>MinitAI</b> folder in your Google Drive'
      + (links.length ? ' \u2014 <a href="'+links[0].url
         +'" target="_blank" rel="noopener" style="color:var(--blue)">open it</a>.' : '.');
  }catch(e){
    out.textContent = (e && e.message ? e.message : 'Could not save to Drive.')
      + ' Your download links still work.';
    if(silent) $('driveAuto').checked=false;   // stop retrying quietly
  }
}

// Drive is where the history actually lives. The server wipes its disk every
// time it sleeps; your Drive does not. drive.file lets us list the files this
// app created and nothing else.
async function driveList(token){
  var folder=await driveFolder(token);
  var q=encodeURIComponent("'"+folder+"' in parents and trashed=false");
  var r=await fetch('https://www.googleapis.com/drive/v3/files?q='+q
    +'&orderBy=createdTime desc&pageSize=40'
    +'&fields=files(id,name,createdTime,webViewLink)',
    {headers:{Authorization:'Bearer '+token}});
  var j=await r.json();
  return j.files||[];
}

function renderDrivePast(files){
  if(!files || !files.length){ $('drivePast').classList.add('hide'); return; }
  // One row per meeting, not per file: three documents share a name.
  var seen={}, rows=[];
  files.forEach(function(f){
    var key=f.name.replace(/ (minit|slaid|transkrip)[^ ]*$/i,'');
    if(!seen[key]){ seen[key]={name:key, when:(f.createdTime||'').slice(0,10), parts:[]};
                    rows.push(seen[key]); }
    seen[key].parts.push(f);
  });
  var h='';
  rows.slice(0,12).forEach(function(m){
    h+='<a class="file" href="'+m.parts[0].webViewLink+'" target="_blank" rel="noopener">'
      + esc(m.name) + '<br><span style="font-size:12px;color:var(--muted)">'
      + esc(m.when) + ' &middot; ' + m.parts.length + ' file'
      + (m.parts.length===1?'':'s') + '</span></a>';
  });
  $('drivePastList').innerHTML=h;
  $('drivePast').classList.remove('hide');
}

// Only for people who have already connected once. Nobody gets a Google
// pop-up just for opening MinitAI.
async function driveReconnect(){
  var cid=(window.MINITAI_GOOGLE||'');
  var linked=false;
  try{ linked = localStorage.getItem('minitai.driveLinked')==='1'; }catch(e){}
  if(!cid || !linked) return;
  try{
    await loadGis();
    var token=await new Promise(function(res,rej){
      var tc=google.accounts.oauth2.initTokenClient({
        client_id:cid, scope:'https://www.googleapis.com/auth/drive.file',
        callback:function(r){ r && r.access_token ? res(r.access_token) : rej(0); },
        error_callback:function(){ rej(0); }});
      tc.requestAccessToken({prompt:''});      // silent; no dialog
    });
    driveToken=token;
    renderDrivePast(await driveList(token));
  }catch(e){ /* not signed in to Google right now; stay quiet */ }
}

$('driveBtn').onclick=async function(){
  await driveSave(driveFiles, false);
  try{ localStorage.setItem('minitai.driveLinked','1'); }catch(e){}
  if(driveToken){ try{ renderDrivePast(await driveList(driveToken)); }catch(e){} }
};
$('driveAuto').onchange=function(){
  try{ localStorage.setItem('minitai.driveAuto', $('driveAuto').checked?'1':'0'); }catch(e){}
};

// ---------------------------------------------------------------- preview
// Seeing what came out, before deciding whether to download it. Without this
// the only way to know if the minutes were any good was to open the file.
function showPreview(d){
  if(!d){ $('preview').classList.add('hide'); return; }
  var items=d.agenda_items||[], acts=d.action_items||[], att=d.attendees||[];
  var h='<h3>'+esc(d.meeting_title||'Minit Mesyuarat')+'</h3>';
  var bits=[];
  if(d.date) bits.push(esc(d.date));
  if(d.location) bits.push(esc(d.location));
  bits.push(items.length+(items.length===1?' perkara':' perkara'));
  bits.push(acts.length+(acts.length===1?' tindakan':' tindakan'));
  if(att.length) bits.push(att.length+' hadir');
  h+='<div class="meta">'+bits.join(' &middot; ')+'</div>';
  if(items.length){
    h+='<ol>';
    items.slice(0,6).forEach(function(it){
      h+='<li>'+esc(it.topic||'');
      if(it.decision) h+='<br><span class="dec">'+esc(it.decision).slice(0,90)+'</span>';
      h+='</li>';
    });
    h+='</ol>';
    if(items.length>6) h+='<div class="more">and '+(items.length-6)+' more in the document</div>';
  }
  $('preview').innerHTML=h;
  $('preview').classList.remove('hide');
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
var SHARE_CSS='display:flex;align-items:center;justify-content:center;'
  +'padding:11px 8px;border-radius:10px;text-decoration:none;flex:1 1 45%;'
  +'background:var(--card2);border:1px solid var(--line);color:var(--txt);'
  +'font-size:13px;cursor:pointer';
function shareMsg(title){
  return encodeURIComponent('Minit mesyuarat: '+title
    +' \u2014 dokumen Word dilampirkan. (Dijana dengan MinitAI.)');
}
function waLink(title){
  var w=document.createElement('a');
  w.className='rec'; w.style.cssText=SHARE_CSS; w.target='_blank'; w.rel='noopener';
  w.href='https://wa.me/?text='+shareMsg(title); w.textContent='Send on WhatsApp';
  return w;
}
function mailLink(title){
  var m=document.createElement('a');
  m.className='rec'; m.style.cssText=SHARE_CSS;
  m.target='_blank'; m.rel='noopener';
  // Not mailto: - most Windows laptops have no mail client registered, so the
  // link silently does nothing at all. Gmail's web compose always opens.
  m.href='https://mail.google.com/mail/?view=cm&fs=1&su='
    + encodeURIComponent('Minit mesyuarat: '+title) + '&body=' + shareMsg(title);
  m.textContent='Send by email';
  return m;
}

function copyBtn(title){
  var b=document.createElement('button');
  b.type='button'; b.className='rec'; b.style.cssText=SHARE_CSS;
  b.textContent='Copy the message';
  b.onclick=function(){
    var txt=decodeURIComponent(shareMsg(title));
    (navigator.clipboard ? navigator.clipboard.writeText(txt) : Promise.reject())
      .then(function(){ b.textContent='Copied \u2713';
             setTimeout(function(){ b.textContent='Copy the message'; },2000); },
            function(){ b.textContent='Could not copy'; });
  };
  return b;
}
function addShare(files){
  var v=(files||{}).docx; if(!v) return;
  var title=(lastAnalysis && lastAnalysis.meeting_title)
    || ($('msg').textContent||'').replace(/^Done( \u2014 )?/,'').trim()
    || 'Minit mesyuarat';
  var wrap=document.createElement('div'); wrap.id='shareRow';
  wrap.style.cssText='display:flex;gap:9px;margin-top:10px';
  var blob=blobFor(v);
  var f=null;
  try{ if(blob) f=new File([blob],v.name,{type:blob.type}); }catch(e){}
  if(f && navigator.canShare && navigator.canShare({files:[f]})){
    var b=document.createElement('button');
    b.type='button'; b.className='rec'; b.textContent='Share the document';
    b.onclick=function(){
      // Never swallow this. Desktop Chrome reports it can share a file and
      // then refuses, and a button that does nothing at all reads as broken.
      navigator.share({files:[f],title:title}).catch(function(err){
        if(err && err.name==='AbortError') return;      // they closed the sheet
        wrap.innerHTML='';
        wrap.appendChild(waLink(title)); wrap.appendChild(mailLink(title));
        $('files').insertAdjacentHTML('beforeend',
          '<div class="note">This browser would not hand the file over. Use '
          +'WhatsApp or email and attach the document you downloaded.</div>');
      });
    };
    wrap.appendChild(b);
  } else {
    wrap.appendChild(waLink(title)); wrap.appendChild(mailLink(title));
    wrap.appendChild(copyBtn(title));
  }
  wrap.style.flexWrap='wrap';
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
    showPreview(lastAnalysis);
    renderFiles(j.files,false);      // no auto-download; they asked for this one
    driveFiles=j.files;
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
  if(j.signed_in){
    // Knowing you have 12 minutes left BEFORE a two-hour meeting is the whole
    // point. At the bottom of the page it may as well not exist.
    var used=j.used_minutes||0, cap=j.daily_limit||0, left=Math.max(0,cap-used);
    var chip=$('quotaChip');
    chip.classList.remove('hide','low','out');
    $('quotaLeft').textContent = left>0
      ? left+' min of recording left today'
      : 'No recording time left today';
    $('quotaOf').textContent = used+' / '+cap+' used';
    $('quotaFill').style.width = (cap? Math.min(100, used*100/cap) : 0)+'%';
    if(left<=0) chip.classList.add('out');
    else if(left<=Math.max(10, cap*0.15)) chip.classList.add('low');
    quotaResetAt = j.quota_resets_at || 0;
    tickReset();
  }
  // Only offered when a key is actually configured, so nobody ticks a box
  // that silently does nothing.
  if($('spkWrap')) $('spkWrap').classList.toggle('hide', !j.speakers_available);
  window.MINITAI_GOOGLE = j.google_client_id || '';
  if(j.name && $('h1name')) $('h1name').textContent = ', ' + j.name;
  if($('adminWrap')) $('adminWrap').classList.toggle('hide', !j.is_admin);
  try{ $('driveAuto').checked = localStorage.getItem('minitai.driveAuto')==='1'; }catch(e){}}

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
