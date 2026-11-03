FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping iperf3 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY nettool_agent/ /app/nettool_agent/

# No credentials or certificates are copied. Runtime adds only NET_RAW and
# NET_BIND_SERVICE with --cap-drop=ALL, and mounts secrets read-only.
# Root plus this narrow capability set lets Linux bind the selected device/68.
ENTRYPOINT ["python3", "-m", "nettool_agent"]
