FROM python:3.12-slim AS base

WORKDIR /app

COPY pyproject.toml README.md ./
COPY ceyo/ ceyo/

RUN pip install --no-cache-dir .

ENTRYPOINT ["ceyo"]
CMD ["--help"]
