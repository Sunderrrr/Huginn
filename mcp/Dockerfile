# Huginn MCP server image.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HUGINN_MCP_TRANSPORT=streamable-http

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install .
COPY app ./app

RUN useradd --system --uid 10002 huginn
USER huginn

EXPOSE 9000
CMD ["python", "-m", "app.server"]
