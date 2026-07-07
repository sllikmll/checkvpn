FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CHECKVPN_DB_URL=sqlite:////app/data/checkvpn.db

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash \
       curl \
       iproute2 \
       iputils-ping \
       dnsutils \
       musl \
       wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /app/
COPY app /app/app
COPY third_party/amneziawg/linux-amd64/awg /usr/local/bin/awg
COPY third_party/amneziawg/linux-amd64/awg-quick /usr/local/bin/awg-quick
COPY third_party/amneziawg/linux-amd64/amneziawg-go /usr/local/bin/amneziawg-go

RUN chmod +x /usr/local/bin/awg /usr/local/bin/awg-quick /usr/local/bin/amneziawg-go

RUN pip install --upgrade pip \
    && pip install .

RUN mkdir -p /app/data

EXPOSE 8098

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://127.0.0.1:8098/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8098"]
