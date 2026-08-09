# MinitAI Web

The hosted version. Upload a meeting recording, get Word minutes, slides and a
transcript back. Runs on a free tier.

## Why this is separate from the desktop app

The desktop app is built for one person on their own machine: no login, one
global job lock, and any file in the output folder is downloadable by anyone who
knows its name. Those are all correct choices there and all confidentiality
holes the moment the app is public. This version replaces storage,
authentication, concurrency and download authorisation. Everything else — the
Word/PowerPoint generation, the analysis schema, the anti-hallucination pass —
is shared with the desktop app in `engine/`.

## Deploy in about 10 minutes

1. Put this folder in a GitHub repo.
2. On [render.com](https://render.com), **New → Web Service**, point it at the repo.
   Render reads `render.yaml` and builds the Dockerfile.
3. In **Environment**, set three variables:

| Variable | Value |
|---|---|
| `GROQ_API_KEY` | Your key from console.groq.com |
| `INVITE_CODES` | One code per person, comma separated |
| `MINITAI_SECRET` | Any long random string |

4. Deploy. Check `/health` returns `{"ok": true, "engine": true}`.

### Invite codes

Give each person their own code — `siti-2026`, `ahmad-2026`. That way you can
revoke one person without disturbing anyone else, and each code gets its own
isolated storage. The codes are never stored, only a hash of them.

**If `INVITE_CODES` is empty the site is closed to everyone.** Failing shut is
deliberate.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `MINITAI_RETENTION_HOURS` | 24 | Documents are deleted after this long |
| `MINITAI_DAILY_MINUTES` | 240 | Per person, per day |
| `MINITAI_MAX_UPLOAD_MB` | 300 | Largest single upload |

## Before every deploy

```
python3 test_cloudapp.py
```

39 checks, mostly about whether one user can reach another user's meeting.
Do not deploy on a failure.

## Known limits

- **Free hosting sleeps.** First request after idle takes ~30s to wake.
- **Disk is ephemeral.** Documents can vanish on restart — retention is a
  backstop, not a promise. Tell people to download.
- **One job at a time.** Correct for the Groq free tier; a second upload queues.
- **Audio leaves the machine.** Unavoidable in a hosted product. Say so plainly,
  and keep the desktop version for anything confidential.

## Updating the engine

`watch_and_run.py` and `cloud.py` are copies from the desktop app. When those
change, copy them across and re-run the tests.
