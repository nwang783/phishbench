# Headless browser sandbox. It opens live phishing pages, so it runs as a
# non-root user and gets only one folder from the host (see render.py).
FROM python:3.13-slim

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

RUN apt-get update \
    && apt-get install -y --no-install-recommends libatomic1 \
    && pip install --no-cache-dir playwright \
    && playwright install --with-deps chromium \
    && chmod -R a+rX /ms-playwright \
    && useradd --create-home render \
    && rm -rf /var/lib/apt/lists/*

COPY render_worker.py /app/render_worker.py
USER render
ENTRYPOINT ["python", "/app/render_worker.py"]
