FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml SPEC.md ./
COPY src ./src
RUN pip install --no-cache-dir .

ENV PYTHONPATH=/app/src
