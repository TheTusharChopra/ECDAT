FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl=3.0.11-1 libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ /srv/app/
COPY certs/citizen-portal.crt /etc/ssl/certs/
CMD ["gunicorn", "--bind", "0.0.0.0:8443", "app.main:app"]
