FROM python:3.12-slim

LABEL org.opencontainers.image.title="Cerberus" \
      org.opencontainers.image.description="Syslog anomaly and security watchdog for firewalls and switches" \
      org.opencontainers.image.source="https://github.com/CerberusNetSec/Cerberus" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CERBERUS_DATA_DIR=/data

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cerberus ./cerberus
COPY tools/migrate.py ./tools/migrate.py

# Runs unprivileged, so it listens on 5514 and compose maps host port 514 to it.
RUN useradd --system --uid 10001 --no-create-home cerberus \
    && mkdir /data && chown cerberus:cerberus /data
USER cerberus
VOLUME /data

EXPOSE 5514/udp 5514/tcp 8080/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD \
    python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"

CMD ["python", "-m", "cerberus"]
