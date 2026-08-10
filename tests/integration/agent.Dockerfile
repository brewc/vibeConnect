FROM python:3.12-slim

RUN useradd --system --create-home --home-dir /var/lib/vibeconnect vibe
WORKDIR /app
COPY pyproject.toml SPEC.md ./
COPY src ./src
RUN pip install --no-cache-dir .

ENV PYTHONPATH=/app/src
