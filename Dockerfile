# Westbridge Bank - simulated insider-threat platform: ONE container running the FastAPI backend and the three Streamlit
# apps on loopback behind a small gateway that is the only public port ($PORT). See docs/deployment.md.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements-deploy.txt ./
RUN pip install -r requirements-deploy.txt

COPY app.py ./
COPY backend ./backend
COPY data/__init__.py data/demo_accounts.py data/seed_data.py ./data/
COPY ml ./ml
COPY frontend ./frontend
COPY deploy ./deploy
COPY .streamlit ./.streamlit

# The anomaly model is built here, from the repository's synthetic generator with its fixed seed, so no model file has to
# be stored or downloaded. Building needs no secret; the throw-away key file the settings loader creates when none is
# configured is kept out of the image (written to /tmp and deleted in the same layer).
RUN LOCAL_SECRET_FILE=/tmp/build-only-key python -m ml.train_model && rm -f /tmp/build-only-key

RUN useradd --create-home --uid 10001 app && chown -R app:app /app
USER app

ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
    CMD python -c "import os,urllib.request as u; u.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8080'), timeout=4)"

CMD ["python", "-m", "deploy.start"]
