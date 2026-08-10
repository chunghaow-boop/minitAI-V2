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


# --- Summary styles -------------------------------------------------------
# One prompt cannot serve a viva committee, a project stand-up and a policy
# paper equally well. The user picks; the shape of the JSON never changes, so
# the document generators are untouched.
SUMMARY_STYLES = {
    "minutes": (
        "Write formal meeting minutes suitable for an official file. Record "
        "every agenda item that was actually discussed, what was said, and what "
        "was decided. Keep the register formal and impersonal."),
    "executive": (
        "Write a short executive summary for someone who was not there and has "
        "two minutes. Lead with decisions and their consequences. Merge minor "
        "items together. Prefer four to six substantial agenda_items over a long "
        "list of small ones. Every action item still gets recorded."),
    "detailed": (
        "Write a thorough record. Capture every topic raised, including items "
        "mentioned only briefly, disagreements, and matters deferred without a "
        "decision. Longer discussion paragraphs are welcome. Nothing that was "
        "discussed should be absent."),
    "actions": (
        "Focus almost entirely on what has to happen next. action_items is the "
        "most important field: capture every task, who owns it and when it is "
        "due. Keep agenda_items brief - one line of context each. Leave "
        "key_takeaways and activities empty unless genuinely important."),
}
DEFAULT_STYLE = "minutes"

# A long transcript sent in one request loses its middle - the model attends to
# the start and end. Above this many characters we summarise in sections and
# merge, which is what stops agenda items going missing on a two-hour meeting.
MAP_REDUCE_OVER_CHARS = 12000
SECTION_CHARS = 9000
SECTION_OVERLAP = 400


def _split_sections(text, size=SECTION_CHARS, overlap=SECTION_OVERLAP):
    """Split on sentence boundaries, with a small overlap so a point made
    across a boundary is not lost by both sections."""
    sentences = [x.strip() for x in text.replace("\n", " ").split(". ") if x.strip()]
    out, cur = [], ""
    for sen in sentences:
        if len(cur) + len(sen) > size and cur:
            out.append(cur.strip())
            cur = cur[-overlap:] if overlap else ""
        cur += sen + ". "
    if cur.strip():
        out.append(cur.strip())
    return out or [text]


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
        # Groq's own message names the problem ("must contain the word 'json'",
        # "model decommissioned", ...). It describes the REQUEST, not the
        # meeting, so it is safe to log - but truncate in case a model echoes
        # input back.
        detail = ""
        try:
            detail = str((r.json().get("error") or {}).get("message", ""))[:200]
        except Exception:
            pass
        if detail:
            logging.warning(f"cloud: Groq {r.status_code} - {detail}")
        raise RuntimeError(f"Groq rejected the request ({r.status_code}). {detail}".strip())
    if last == "rate limited":
        # Everyone on this server shares one free account, so this is a fleet
        # problem, not the user's fault. Say so in words they can act on.
        raise RuntimeError(
            "MinitAI's free transcription allowance is used up for now - too "
            "many meetings in the last hour. It frees up again shortly, so "
            "please try this recording later, or use the desktop version, "
            "which has no limit.")
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


# --- optional: speaker labels via AssemblyAI ------------------------------
# Groq has no speaker support at all. AssemblyAI does, it handles Malay, and
# diarisation costs about two cents an hour. Entirely optional: with no key
# set, nothing below ever runs and Groq stays the only service touched.
AAI_KEY_ENV = "ASSEMBLYAI_API_KEY"
AAI_ROOT = "https://api.assemblyai.com/v2"


def diarisation_available():
    return bool((os.environ.get(AAI_KEY_ENV) or "").strip())


def transcribe_with_speakers(audio_path, language=None, speakers=None):
    """Transcript as "Speaker A: ..." lines. Raises if anything goes wrong, so
    the caller can fall back to Groq and the meeting is never lost."""
    key = (os.environ.get(AAI_KEY_ENV) or "").strip()
    if not key:
        raise RuntimeError("No AssemblyAI key configured.")
    head = {"authorization": key}
    with open(audio_path, "rb") as fh:
        up = requests.post(AAI_ROOT + "/upload", headers=head, data=fh, timeout=600)
    if up.status_code != 200:
        raise RuntimeError(f"AssemblyAI rejected the upload ({up.status_code}).")
    body = {"audio_url": up.json()["upload_url"], "speaker_labels": True}
    if language:
        body["language_code"] = language
    if speakers:
        body["speakers_expected"] = int(speakers)
    job = requests.post(AAI_ROOT + "/transcript", headers=head, json=body, timeout=60)
    if job.status_code not in (200, 201):
        raise RuntimeError(f"AssemblyAI refused the job ({job.status_code}).")
    tid = job.json()["id"]
    deadline = time.time() + 3600
    while time.time() < deadline:
        time.sleep(5)
        r = requests.get(f"{AAI_ROOT}/transcript/{tid}", headers=head, timeout=60)
        j = r.json()
        if j.get("status") == "completed":
            lines = []
            for u in (j.get("utterances") or []):
                who = u.get("speaker") or "?"
                said = (u.get("text") or "").strip()
                if said:
                    lines.append(f"Speaker {who}: {said}")
            return "\n".join(lines) or (j.get("text") or "")
        if j.get("status") == "error":
            raise RuntimeError(j.get("error") or "AssemblyAI failed.")
    raise RuntimeError("AssemblyAI took too long.")


def transcribe(audio_path, data_dir, ffmpeg_exe, language=None,
               prompt=None, duration=None, progress=None, segments_out=None):
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
        parts, failed, stamps = [], [], []
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
            # verbose_json costs nothing extra and returns segment timings, so
            # a reader can find the moment a line came from instead of taking
            # the transcript on trust.
            fields = {"model": (None, STT_MODEL),
                      "response_format": (None, "verbose_json")}
            if language:
                fields["language"] = (None, language)
            if prompt:
                fields["prompt"] = (None, prompt[:800])
            with open(piece, "rb") as fh:
                fields["file"] = (os.path.basename(piece), fh, "audio/flac")
                r = _post_with_retry(API_ROOT + "/audio/transcriptions", key,
                                     files=fields, timeout=600)
            body = r.json()
            offset = float(start or 0)
            for seg in (body.get("segments") or []):
                txt = (seg.get("text") or "").strip()
                if txt:
                    stamps.append((offset + float(seg.get("start") or 0), txt))
            parts.append((body.get("text") or "").strip())
            try:
                os.remove(piece)
            except OSError:
                pass

        if failed and len(failed) * 2 >= len(spans):
            raise RuntimeError("Most of the recording could not be uploaded.")
        text = " ".join(p for p in parts if p)
        if segments_out is not None:
            segments_out.extend(stamps)
        if not text.strip():
            raise RuntimeError("No speech detected in audio.")
        return text
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)


def _one_pass(transcript_text, data_dir, system_prompt, schema, max_retries=4):
    """Summarise via Groq, with the same JSON schema the local engine uses,
    so the document generators see an identical shape either way."""
    key = get_key(data_dir)
    if not key:
        raise RuntimeError("No Groq key configured.")
    keys = ", ".join(schema.get("required", []))
    json_rule = ("\n\nReturn a single valid JSON object and nothing else - no "
                 "markdown, no code fences, no commentary. The JSON object must "
                 f"contain exactly these keys: {keys}.")
    model = pick_chat_model(data_dir)

    def _body(fmt):
        b = {
            "model": model,
            # The word "json" MUST appear in the messages: OpenAI-compatible
            # JSON modes reject the request with 400 otherwise. This is what
            # broke the first live deploy.
            "messages": [{"role": "system", "content": system_prompt + json_rule},
                         {"role": "user", "content": transcript_text}],
            "temperature": 0.2,
        }
        if fmt:
            b["response_format"] = fmt
        return b

    # Three attempts, most-constrained first. Models vary in what they accept,
    # and a hosted model can be retired without notice, so never depend on one.
    formats = [
        {"type": "json_schema",
         "json_schema": {"name": "minutes", "schema": schema, "strict": False}},
        {"type": "json_object"},
        None,                      # no format at all; parsed loosely below
    ]
    r = None
    last = None
    for fmt in formats:
        try:
            r = _post_with_retry(API_ROOT + "/chat/completions", key,
                                 json_body=_body(fmt), timeout=300,
                                 attempts=max_retries)
            break
        except RuntimeError as e:
            last = e
            logging.info(f"cloud: response_format "
                         f"{(fmt or {}).get('type', 'none')} not accepted")
    if r is None:
        raise last or RuntimeError("Groq would not accept the request.")
    raw = (r.json().get("choices") or [{}])[0].get("message", {}).get("content", "")
    if not raw.strip():
        raise RuntimeError("The AI returned an empty response.")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Strip code fences / surrounding prose and take the outermost object.
        t = raw.strip()
        if t.startswith("```"):
            t = t.split("```")[1] if "```" in t[3:] else t[3:]
            if t.lstrip().lower().startswith("json"):
                t = t.lstrip()[4:]
        i, j = t.find("{"), t.rfind("}")
        if i != -1 and j > i:
            return json.loads(t[i:j + 1])
        raise RuntimeError("The AI returned data that could not be read.")


def _merge(parts):
    """Combine section summaries. Reuses the desktop engine's merge so both
    versions produce identically-shaped minutes."""
    import watch_and_run as _engine
    return _engine._merge_analyses([p for p in parts if p])


def _find_missing(transcript_text, draft, data_dir, schema):
    """Second opinion: show the model the transcript AND the draft minutes, and
    ask only what important item was left out. This is the pass that answers
    'are all the points there' - a single summarisation pass cannot check
    itself."""
    import json as _j
    brief = {
        "agenda_items": [i.get("topic", "") for i in (draft.get("agenda_items") or [])],
        "decisions": [i.get("decision", "") for i in (draft.get("agenda_items") or [])],
        "action_items": [i.get("task", "") for i in (draft.get("action_items") or [])],
        "key_points": draft.get("key_points") or [],
    }
    sys_p = (
        "You are checking a set of draft meeting minutes for omissions. You are "
        "given the transcript and a summary of what the draft already covers. "
        "Return JSON listing ONLY items that were genuinely discussed in the "
        "transcript but are MISSING from the draft. If the draft is complete, "
        "return empty arrays. Never repeat something the draft already has. "
        "Never invent anything. Be strict: only real omissions.")
    miss_schema = {
        "type": "object",
        "properties": {
            "agenda_items": {"type": "array", "items": {
                "type": "object",
                "properties": {"topic": {"type": "string"},
                               "discussion": {"type": "string"},
                               "decision": {"type": "string"}},
                "required": ["topic", "discussion", "decision"]}},
            "action_items": {"type": "array", "items": {
                "type": "object",
                "properties": {"task": {"type": "string"},
                               "owner": {"type": "string"},
                               "deadline": {"type": "string"}},
                "required": ["task", "owner", "deadline"]}},
            "key_points": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["agenda_items", "action_items", "key_points"],
    }
    # Truncating to the head meant omissions in the LAST hour of a long meeting
    # could never be found - the exact case this pass exists for. Sample evenly
    # across the whole transcript instead.
    budget = 60000
    t = transcript_text or ""
    if len(t) <= budget:
        sample = t
    else:
        n = 6
        piece = budget // n
        step = len(t) // n
        sample = "\n[...]\n".join(t[i * step:i * step + piece] for i in range(n))
    user = ("ALREADY COVERED BY THE DRAFT:\n" + _j.dumps(brief, ensure_ascii=False)
            + "\n\nTRANSCRIPT (sampled evenly across the whole meeting):\n" + sample)
    # attempts=1: this pass is optional, so it must not hold up the meeting.
    return _one_pass(user, data_dir, sys_p, miss_schema, max_retries=1)


def analyze(transcript_text, data_dir, system_prompt, schema,
            style=DEFAULT_STYLE, completeness_check=True, focus="", roster="",
            previous="", lang=""):
    """Summarise a transcript.

    Long transcripts are summarised in sections and merged, then checked once
    for omissions. A single pass over a two-hour meeting silently drops the
    middle, which is how agenda items go missing.
    """
    style_rule = SUMMARY_STYLES.get(style, SUMMARY_STYLES[DEFAULT_STYLE])
    sys_p = system_prompt + "\n\nSTYLE FOR THIS DOCUMENT:\n" + style_rule
    # The dropdown used to steer only the transcriber. The summariser never
    # learned what language to write in, so an English meeting could come back
    # as Malay minutes because the installed default said so.
    import watch_and_run as _eng
    _rule = _eng._LANG_RULES.get((lang or "").lower())
    if _rule:
        sys_p = _rule + "\n\n" + sys_p
    focus = (focus or "").strip()
    if focus:
        # The user's own words. Placed last so it outranks the style, but framed
        # so it can never override the no-inventing rule: asking for something
        # the meeting never covered must yield an empty field, not fiction.
        sys_p += ("\n\nWHAT THIS PARTICULAR READER ASKED FOR:\n" + focus[:600]
                  + "\n\nGive that request priority when deciding what to "
                    "include and what to leave out. If the meeting simply did "
                    "not cover it, say nothing about it rather than inventing "
                    "content - the no-invention rule still outranks this.")

    names = [n.strip() for n in (roster or "").splitlines() if n.strip()]
    if names:
        # A roster the user typed is ground truth. It beats whatever the
        # transcript garbled, and it is the difference between an attendance
        # list and a list of everyone whose name was said out loud.
        sys_p += ("\n\nWHO WAS PRESENT (given by the user, authoritative):\n"
                  + "; ".join(names[:60])
                  + "\n\nUse exactly these spellings for these people wherever "
                    "they appear. Put exactly these names in attendees - do not "
                    "add anyone who was merely mentioned, and do not drop anyone "
                    "on this list.")

    prev = (previous or "").strip()
    if prev:
        # Malaysian minutes open with what was carried over. Nobody wants to
        # retype it every month when last month's file already says it.
        sys_p += ("\n\nLAST MEETING'S MINUTES (for matters arising only):\n"
                  + prev[:12000]
                  + "\n\nBEFORE the new agenda items, add agenda_items whose topic "
                    "begins \"Perkara Berbangkit: \" for each matter from those "
                    "minutes that THIS meeting actually returned to - what has "
                    "happened since, and where it now stands. Only matters this "
                    "recording genuinely discussed. Never carry an item over just "
                    "because it appears in the old minutes."
                    "\n\nThose old minutes are BACKGROUND ONLY. Everything else you "
                    "produce must come from THIS recording:"
                    "\n- action_items: only tasks assigned in THIS meeting. Never "
                    "copy an action out of the old minutes. If an old action is "
                    "still outstanding, say so inside its Perkara Berbangkit item "
                    "instead."
                    "\n- meeting_title: the title of THIS meeting. Never title a "
                    "meeting after a matter arising, and never begin the title "
                    "with \"Perkara Berbangkit\"."
                    "\n- attendees: only people present at THIS meeting.")

    text = transcript_text or ""
    if len(text) <= MAP_REDUCE_OVER_CHARS:
        data = _one_pass(text, data_dir, sys_p, schema)
    else:
        sections = _split_sections(text)
        logging.info(f"cloud: long transcript, {len(text)} chars -> "
                     f"{len(sections)} sections")
        parts = []
        for i, sec in enumerate(sections, 1):
            try:
                parts.append(_one_pass(sec, data_dir, sys_p, schema))
                logging.info(f"cloud: section {i}/{len(sections)} summarised")
            except Exception as e:
                # One weak section must not lose the whole meeting.
                logging.warning(f"cloud: section {i} failed ({type(e).__name__})")
        if not parts:
            raise RuntimeError("None of the meeting could be summarised.")
        data = _merge(parts)

    if completeness_check and len(text) > 1500:
        try:
            missing = _find_missing(text, data, data_dir, schema)
            added = 0
            for f in ("agenda_items", "action_items", "key_points"):
                extra = missing.get(f) or []
                if isinstance(extra, list) and extra:
                    data[f] = (data.get(f) or []) + extra
                    added += len(extra)
            if added:
                logging.info(f"cloud: completeness pass added {added} missed item(s)")
                # The completeness pass appends without looking at what is
                # already there, so it can put back a topic the merge just
                # folded. Fold again. This is why one real meeting still showed
                # "Kolokium Pascasiswazah" and "Pembentangan Kolokium".
                import watch_and_run as _engine
                before = len(data.get("agenda_items") or [])
                data["agenda_items"] = _engine._merge_agenda(data.get("agenda_items") or [])
                data["action_items"] = _engine._merge_actions(data.get("action_items") or [])
                if len(data["agenda_items"]) < before:
                    logging.info(f"cloud: re-folded {before - len(data['agenda_items'])} "
                                 f"duplicate topic(s) after the completeness pass")
        except Exception as e:
            # A failed check must never cost the user their minutes.
            logging.info(f"cloud: completeness check skipped ({type(e).__name__})")

    # Word-matching cannot tell that "Kelas RMC" and "Pembentangan RMC" are one
    # subject or two. When a meeting still looks over-fragmented, ask the model
    # once - text only, so it barely touches the free tier - and accept the
    # answer only if it is strictly a folding of what we already had.
    if names:
        data["attendees"] = names
    if (lang or "").lower() in ("en", "ms", "zh"):
        data["output_language"] = lang.lower()   # the document furniture too
    if len(data.get("agenda_items") or []) > CONSOLIDATE_OVER_ITEMS:
        try:
            data = _consolidate(data, data_dir)
        except Exception as e:
            logging.info(f"cloud: consolidation skipped ({type(e).__name__})")
    return data


CONSOLIDATE_OVER_ITEMS = int(os.environ.get("MINITAI_CONSOLIDATE_OVER", "10"))


def ask_text(system_prompt, question, data_dir):
    """One plain-text answer. Used by the help assistant and by questions about
    a past meeting - both want prose, not the minutes JSON."""
    key = get_key(data_dir)
    if not key:
        raise RuntimeError("No Groq key configured.")
    body = {"model": pick_chat_model(data_dir), "temperature": 0.2,
            "messages": [{"role": "system", "content": system_prompt},
                         {"role": "user", "content": question}]}
    r = _post_with_retry(API_ROOT + "/chat/completions", key,
                         json_body=body, timeout=120)
    return (r.json()["choices"][0]["message"]["content"] or "").strip()


def _consolidate(data, data_dir):
    """Fold agenda items that are the same subject worded differently.

    Deliberately conservative: the model may only merge, never rewrite. Any
    reply that invents a topic, or that collapses the meeting to almost
    nothing, is thrown away and the original kept.
    """
    import json as _j
    items = data.get("agenda_items") or []
    listing = [{"i": n, "topic": it.get("topic", "")} for n, it in enumerate(items)]
    sys_p = (
        "You are tidying the agenda of a Malaysian meeting's minutes. You get a "
        "numbered list of agenda topics, some of which describe the SAME subject "
        "in different words because the meeting was summarised in sections.\n"
        "Return JSON: {\"groups\": [[0,3],[1],[2,4,5]]} - each group holds the "
        "indexes of entries that are the same subject. Every index must appear "
        "exactly once. Do NOT merge topics that are merely related; only merge "
        "ones a reader would call duplicates. If nothing is duplicated, return "
        "each index in its own group.")
    schema = {"type": "object",
              "properties": {"groups": {"type": "array", "items": {
                  "type": "array", "items": {"type": "integer"}}}},
              "required": ["groups"]}
    reply = _one_pass(_j.dumps(listing, ensure_ascii=False), data_dir, sys_p, schema)
    groups = reply.get("groups")
    if not isinstance(groups, list) or not groups:
        return data
    seen, merged = set(), []
    for g in groups:
        idx = [i for i in g if isinstance(i, int) and 0 <= i < len(items) and i not in seen]
        if not idx:
            continue
        seen.update(idx)
        merged.append(_fold([items[i] for i in idx]))
    # Anything the model forgot to mention keeps its place rather than vanishing.
    for i, it in enumerate(items):
        if i not in seen:
            merged.append(it)
    if len(merged) < max(1, len(items) // 3):
        logging.warning("cloud: consolidation collapsed too much, keeping original")
        return data
    if len(merged) < len(items):
        logging.info(f"cloud: consolidation folded {len(items) - len(merged)} topic(s)")
    data["agenda_items"] = merged
    return data


def _fold(group):
    """One agenda entry from several describing the same subject."""
    import watch_and_run as _engine
    keep = dict(group[0])
    for other in group[1:]:
        if len(other.get("discussion", "")) > len(keep.get("discussion", "")):
            keep["discussion"] = other["discussion"]
        dec = other.get("decision", "")
        if _engine._real_decision(dec):
            if not _engine._real_decision(keep.get("decision", "")):
                keep["decision"] = dec
            elif dec.lower() not in keep["decision"].lower():
                keep["decision"] = keep["decision"].rstrip(".") + "; " + dec
    return keep
