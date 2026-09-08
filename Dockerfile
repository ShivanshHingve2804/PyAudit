FROM python:3.11-slim AS builder

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

FROM python:3.11-slim

WORKDIR /app
COPY --from=builder /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/
COPY --from=builder /usr/local/bin/pyaudit /usr/local/bin/pyaudit

RUN useradd --create-home appuser
USER appuser

ENTRYPOINT ["pyaudit"]
CMD ["--help"]
