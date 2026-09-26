# --- build the TLSNotary prover -------------------------------------------
FROM rust:1-bookworm AS prover
WORKDIR /src
COPY prover/Cargo.toml prover/Cargo.lock* ./
COPY prover/src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release && cp target/release/witness-prover /witness-prover

# --- runtime: Chromium (Playwright), wget, prover -------------------------
FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN apt-get update \
 && apt-get install -y --no-install-recommends wget ca-certificates poppler-utils fonts-dejavu fonts-noto-core \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir playwright==1.55.0 warcio==1.7.5 opentimestamps-client==0.7.2 ecdsa==0.19.1 requests==2.32.5 pyHanko==0.29.0 \
 && playwright install --with-deps chromium \
 && rm -rf /var/lib/apt/lists/*
COPY --from=prover /witness-prover /usr/local/bin/witness-prover
COPY capture.py /app/capture.py
WORKDIR /app
VOLUME /out
EXPOSE 8080
ENTRYPOINT ["python3", "/app/capture.py"]
