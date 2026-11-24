# syntax=docker/dockerfile:1

# ---- build stage: produce a wheel and install into an isolated venv ----
FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
RUN python -m venv /opt/venv
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN /opt/venv/bin/pip install .

# ---- runtime stage: minimal, non-root ----
FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Git is required: GitVigil reads repository history via git plumbing.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 gitvigil \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin gitvigil

COPY --from=builder /opt/venv /opt/venv

USER 10001:10001
WORKDIR /repo
ENTRYPOINT ["gitvigil"]
CMD ["--help"]
