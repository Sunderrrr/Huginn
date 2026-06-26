# Huginn hub image.
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install .

# Application code and migrations.
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# Normalize permissions so the unprivileged user can read the app code and exec
# the entrypoint regardless of the build host's umask (COPY preserves source
# file modes, which on a umask-077 checkout would be unreadable to non-root).
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh && chmod -R a+rX /app

# Run as an unprivileged user.
RUN useradd --system --uid 10001 huginn
USER huginn

EXPOSE 8000
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
