# PhantomNet protocol decoys (OpenCanary SSH + MySQL simulations).
# Pin the OpenCanary release; verify the version on PyPI before each release.
FROM python:3.12-slim-bookworm

ARG OPENCANARY_VERSION=0.9.5

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libssl-dev libffi-dev \
 && pip install --no-cache-dir "opencanary==${OPENCANARY_VERSION}" \
 && apt-get purge -y build-essential \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 phantom && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin phantom

# Writable paths are tmpfs/volumes; the rest of the filesystem is read-only.
WORKDIR /tmp
USER 10001:10001

# Equivalent of `opencanaryd --dev` (foreground twistd, supervised by Docker).
# The opencanaryd wrapper is bypassed because it shells out to `sudo` whenever
# it isn't root, and this image deliberately has neither root nor sudo.
CMD ["twistd", "--nodaemon", "--pidfile=", "--python=/usr/local/bin/opencanary.tac"]
