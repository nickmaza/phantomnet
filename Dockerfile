# PhantomNet application image: web decoy, rotation controller, core (collector,
# correlation, alerts, dashboard). One image, different commands.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && groupadd -g 10001 phantom && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin phantom

COPY controller/ controller/
COPY detection/ detection/
COPY dashboard/ dashboard/
COPY services/__init__.py services/__init__.py
COPY services/decoys/__init__.py services/decoys/__init__.py
COPY services/decoys/web/ services/decoys/web/

USER 10001:10001
