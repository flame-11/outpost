FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.8.11 /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY outpost ./outpost
RUN uv sync --frozen --no-dev

RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin outpost \
    && mkdir -p /data && chown outpost /data
USER outpost

ENV OUTPOST_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 53/udp 53/tcp 80/tcp 9443/tcp

CMD ["/app/.venv/bin/python", "-m", "outpost.server"]
