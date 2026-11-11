FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.8.11 /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
# The `acme` extra brings certbot, which obtains and renews the certificate for OUTPOST_TLS=acme.
RUN uv sync --frozen --no-dev --extra acme --no-install-project
COPY outpost ./outpost
RUN uv sync --frozen --no-dev --extra acme

RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin outpost \
    && mkdir -p /data && chown outpost /data
USER outpost

ENV OUTPOST_DATA_DIR=/data \
    PATH=/app/.venv/bin:$PATH
VOLUME ["/data"]
EXPOSE 53/udp 53/tcp 80/tcp 443/tcp 25/tcp 9443/tcp

CMD ["/app/.venv/bin/python", "-m", "outpost.server"]
