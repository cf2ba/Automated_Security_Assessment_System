FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl git ca-certificates iputils-ping procps \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir flask requests

WORKDIR /workspace

CMD ["sleep", "infinity"]
