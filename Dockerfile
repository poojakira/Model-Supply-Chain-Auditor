FROM python:3.12-slim AS base

WORKDIR /app
COPY pyproject.toml requirements.txt rules.yaml ./
COPY src/ src/

RUN pip install --no-cache-dir -e .

ENTRYPOINT ["msca"]
CMD ["--help"]
