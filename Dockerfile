FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md alembic.ini ./
COPY pleskmcp ./pleskmcp
RUN pip install --no-cache-dir . && mkdir -p /data && chown 1000:1000 /data

# Build metadata set by GitHub Actions; shown in /healthz and `pleskmcp check`.
ARG GIT_SHA=unknown
ARG APP_VERSION=
# uid 1000 has no passwd entry in this image: asyncssh needs USER/LOGNAME and a HOME for its config lookup.
ENV GIT_SHA=$GIT_SHA \
    APP_VERSION=$APP_VERSION \
    DATA_DIR=/data \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    HOME=/tmp \
    USER=pleskmcp \
    LOGNAME=pleskmcp \
    PYTHONUNBUFFERED=1

USER 1000:1000
VOLUME ["/data"]
EXPOSE 8000

# The api healthcheck; worker and scheduler override it in docker-compose.yml (heartbeat file).
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s CMD python -c "import os,urllib.request,urllib.parse;u=urllib.parse.urlparse(os.environ['PUBLIC_BASE_URL']);urllib.request.urlopen('http://127.0.0.1:8000'+u.path.rstrip('/')+'/healthz',timeout=4)" || exit 1

# Start commands: pleskmcp api | worker | scheduler | migrate | ...
CMD ["pleskmcp", "api"]
