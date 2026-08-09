"""MinitAI cloud engine (optional).

Same job as the local engine, done on Groq's free tier instead of your own CPU:
fast, no install, works on any machine. Used only when a key is present AND
the internet is reachable. Every failure falls back to the local engine, so
turning this on can never make MinitAI stop working.

THE KEY NEVER LEAVES THIS MACHINE except in the Authorization header to Groq.
It is read from %APPDATA%\\MinitAI\\groq_key.txt or the GROQ_API_KEY variable.
It is never logged, never written to the diagnostic report, never sent anywhere
else.

PRIVACY: in cloud mode your audio IS uploaded to Groq. That is the trade for
speed and zero setup. Use local mode for anything confidential.
"""
import os
import json
import time
import logging

import requests

API_ROOT = "https://api.groq.com/openai/v1"
STT_MODEL = "whisper-large-v3-turbo"

# Chat models in preference order; the first one Groq actually serves is used.
# Discovered at runtime so a retired model name can never break the app.
_PREFERRED_CHAT = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "mixtral-8x7b-32768",
    "gemma2-9b-it",
]

# Free tier caps uploads at 25 MB. We send 16 kHz mono FLAC, which is roughly
# 5 MB for 10 minutes, and chunk anything longer.
MAX_UPLOAD_BYTES = 24 * 1024 * 1024
CLOUD_SEGMENT_SECONDS = 10 * 60

_key_cache = None
_chat_model = None


def _key_path(data_dir):
    return os.path.join(data_dir, "groq_key.txt")


def get_key(data_dir):
    """The API key, or "" if the user has not set one up."""
    global _key_cache
    if _key_cache is not None:
        return _key_cache
    key = (os.environ.get("GROQ_API_KEY") or "").strip()
    if not key:
        try:
            p = _key_path(data_dir)
            if os.path.exists(p):
                with open(p, encoding="utf-8") as f:
                    key = f.read().strip()
        except Exception as e:
            logging.warning(f"cloud: could not read the key file: {type(e).__name__}")
            key = ""
    # Only ever record the shape, never the value.
    if key:
        logging.info(f"cloud: key loaded ({len(key)} chars)")
    _key_cache = key
    return key


def _headers(key):
    return {"Authorization": f"Bearer {key}"}


def available(data_dir, timeout=4):
    """True only if a key exists AND Groq is reachable right now."""
    if not get_key(data_dir):
        return False
    try:
        r = requests.get(API_ROOT + "/models",
                         headers=_headers(get_key(data_dir)), timeout=timeout)
        return r.status_code == 200
    except Exception:
        return False


def pick_chat_model(data_dir):
    """First preferred chat model that Groq is actually serving today."""
    global _chat_model
    if _chat_model:
        return _chat_model
    try:
        r = requests.get(API_ROOT + "/models",
                         headers=_headers(get_key(data_dir)), timeout=10)
        served = {m.get("id", "") for m in (r.json().get("data") or [])}
        for want in _PREFERRED_CHAT:
            if want in served:
                _chat_model = want
                logging.info(f"cloud: chat model {want}")
                return want
        # Nothing preferred is available - take any non-audio model rather than fail.
        for m in sorted(served):
            if "whisper" not in m and "tts" not in m and "guard" not in m:
                _chat_model = m
                logging.info(f"cloud: falling back to chat model {m}")
                return m
    except Exception as e:
        logging.warning(f"cloud: model discovery failed: {type(e).__name__}")
    _chat_model = _PREFERRED_CHAT[0]
    return _chat_model


def _post_with_retry(url, key, *, files=None, data=None, json_body=None,
                     timeout=300, attempts=4):
    """POST with backoff on 429/5xx. Groq's free tier is rate limited, and a
    burst of chunks from one long meeting will hit it."""
    delay = 3
    last = None
    for i in range(attempts):
        try:
            r = requests.post(url, headers=_headers(key), files=files,
                              data=data, json=json_body, timeout=timeout)
        except Exception as e:
            last = f"network error: {type(e).__name__}"
            time.sleep(delay); delay = min(delay * 2, 40)
            continue
        if r.status_code == 200:
            return r
        if r.status_code == 401:
            raise RuntimeError("Your Groq key was rejected. Check groq_key.txt, "
                               "or create a new key at console.groq.com.")
        if r.status_code == 429:
            wait = delay
            try:
                wait = max(wait, float(r.headers.get("retry-after", 0)))
            except (TypeError, ValueError):
                pass
            logging.info(f"cloud: rate limited, waiting {wait:.0f}s "
                         f"(attempt {i + 1}/{attempts})")
            time.sleep(min(wait, 60)); delay = min(delay * 2, 40)
            last = "rate limited"
            continue
        if r.status_code >= 500:
            last = f"Groq server error {r.status_code}"
            time.sleep(delay); delay = min(delay * 2, 40)
            continue
        # 4xx that isn't auth or rate limit: our request is wrong, don't retry.
        raise RuntimeError(f"Groq rejected the request ({r.status_code}).")
    raise RuntimeError(f"Groq did not respond after {attempts} tries ({last}).")


def _to_flac(src, dst, ffmpeg_exe, start=None, length=None):
    """16 kHz mono FLAC - what Whisper wants, and small enough to upload.
    NOTE: -ss must come AFTER -i. Fast seek before -i silently produced
    1.5-second files on a long mp4 during testing."""
    import subprocess
    cmd = [ffmpeg_exe, "-hide_banner", "-loglevel", "error", "-y", "-i", src, "-vn"]
    if start is not None:
        cmd += ["-ss", str(int(start))]
    if length is not None:
        cmd += ["-t", str(int(length))]
    cmd += ["-ac", "1", "-ar", "16000", "-c:a", "flac", dst]
    subprocess.run(cmd, capture_output=True, timeout=1800, check=False)
    return os.path.exists(dst) and os.path.getsize(dst) > 1024


def transcribe(audio_path, data_dir, ffmpeg_exe, language=None,
               prompt=None, duration=None, progress=None):
    """Transcribe via Groq. Raises on failure so the caller can fall back."""
    key = get_key(data_dir)
    if not key:
        raise RuntimeError("No Groq key configured.")

    work = os.path.join(data_dir, f"_cloud_{int(time.time())}")
    os.makedirs(work, exist_ok=True)
    try:
        spans = [(None, None)]
        if duration and duration > CLOUD_SEGMENT_SECONDS:
            n = int(duration // CLOUD_SEGMENT_SECONDS) + 1
            spans = [(i * CLOUD_SEGMENT_SECONDS, CLOUD_SEGMENT_SECONDS)
                     for i in range(n)]
        parts, failed = [], []
        for i, (start, length) in enumerate(spans, 1):
            if progress:
                try:
                    progress(i, len(spans))
                except Exception:
                    pass
            piece = os.path.join(work, f"p{i:04d}.flac")
            if not _to_flac(audio_path, piece, ffmpeg_exe, start, length):
                failed.append(i)
                continue
            if os.path.getsize(piece) > MAX_UPLOAD_BYTES:
                failed.append(i)
                logging.warning(f"cloud: part {i} is too large to upload")
                continue
            fields = {"model": (None, STT_MODEL), "response_format": (None, "json")}
            if language:
                fields["language"] = (None, language)
            if prompt:
                fields["prompt"] = (None, prompt[:800])
            with open(piece, "rb") as fh:
                fields["file"] = (os.path.basename(piece), fh, "audio/flac")
                r = _post_with_retry(API_ROOT + "/audio/transcriptions", key,
                                     files=fields, timeout=600)
            parts.append((r.json().get("text") or "").strip())
            try:
                os.remove(piece)
            except OSError:
                pass

        if failed and len(failed) * 2 >= len(spans):
            raise RuntimeError("Most of the recording could not be uploaded.")
        text = " ".join(p for p in parts if p)
        if not text.strip():
            raise RuntimeError("No speech detected in audio.")
        return text
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)


def analyze(transcript_text, data_dir, system_prompt, schema):
    """Summarise via Groq, with the same JSON schema the local engine uses,
    so the document generators see an identical shape either way."""
    key = get_key(data_dir)
    if not key:
        raise RuntimeError("No Groq key configured.")
    body = {
        "model": pick_chat_model(data_dir),
        "messages": [{"role": "system", "content": system_prompt},
                     {"role": "user", "content": transcript_text}],
        "temperature": 0.2,
        "response_format": {"type": "json_schema",
                            "json_schema": {"name": "minutes",
                                            "schema": schema,
                                            "strict": False}},
    }
    try:
        r = _post_with_retry(API_ROOT + "/chat/completions", key,
                             json_body=body, timeout=300)
    except RuntimeError:
        # Some models reject json_schema but accept plain json_object.
        body["response_format"] = {"type": "json_object"}
        r = _post_with_retry(API_ROOT + "/chat/completions", key,
                             json_body=body, timeout=300)
    raw = (r.json().get("choices") or [{}])[0].get("message", {}).get("content", "")
    if not raw.strip():
        raise RuntimeError("The AI returned an empty response.")
    return json.loads(raw)
