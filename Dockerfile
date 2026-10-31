FROM python:3.12-slim

# ping and ip for status and discovery, nmap for the port scan
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping iproute2 nmap tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app.py fingerprints.json index.html logo.svg ./

ENV LANTERN_DB=/data/lantern.db \
    PYTHONUNBUFFERED=1
VOLUME /data

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import os,urllib.request as u; h=os.environ.get('LANTERN_HOST','127.0.0.1'); u.urlopen('http://%s:%s/api/session' % ('127.0.0.1' if h in ('0.0.0.0','') else h, os.environ.get('LANTERN_PORT','8099')), timeout=4)"

CMD ["python", "app.py"]
