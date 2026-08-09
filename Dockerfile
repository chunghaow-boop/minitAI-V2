FROM python:3.12-slim

# ffmpeg converts and chunks uploads before they are sent on for transcription.
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Everything lives at the repo root: app.py plus the two shared engine modules.
# The local AI stack (faster-whisper, torch) is deliberately NOT installed -
# this server never transcribes locally.
COPY . /app/

# APPDATA is what the shared engine uses to find its data folder. Without it the
# engine would create a MinitAI/ folder inside the app directory.
ENV MINITAI_DATA=/tmp/minitai-web \
    APPDATA=/tmp/minitai-engine \
    PYTHONUNBUFFERED=1

EXPOSE 8080
# One worker: the job queue is in-process and the free Groq tier cannot feed
# more than one at a time. Threads keep the page responsive while a meeting runs.
CMD gunicorn -w 1 -k gthread --threads 8 -b 0.0.0.0:${PORT:-8080} \
    --timeout 1800 --access-logfile - app:app
