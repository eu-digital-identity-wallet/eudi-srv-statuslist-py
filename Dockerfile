# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.13-slim AS builder

WORKDIR /build

# Only needed when a dependency has no wheel for the target platform.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt .

RUN pip install --upgrade pip \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.13-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Only the application code: no tests, docs, keys or local state.
COPY app/ ./app/

# Unprivileged user (fixed UID so host-mounted directories can be granted to
# it: chown -R 10001 <dir>). It owns the default list, backup and log
# directories (status_list_dir, backup_dir, logging.path).
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin statuslist \
 && mkdir -p /etc/statuslist_config /var/opt/status_lists /var/opt/status_list_backup /var/log/status_lists \
 && chown -R statuslist:statuslist /var/opt/status_lists /var/opt/status_list_backup /var/log/status_lists

USER statuslist

ENV FLASK_APP="app:create_app"

EXPOSE 5000

# The lists are kept on disk under a lock: several containers or processes
# may serve the same status_list_dir (only one of them renews at a time).
CMD ["flask", "run", "--host=0.0.0.0"]
