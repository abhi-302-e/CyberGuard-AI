FROM python:3.11-slim

LABEL maintainer="CyberGuard AI Engineering Team"
LABEL description="Autonomous Multi-Agent Cybersecurity Decision Intelligence System"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CYBERGUARD_ENV=production \
    CYBERGUARD_UI_PORT=5000 \
    CYBERGUARD_API_PORT=8080

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run validation test suite during build
RUN python -m unittest discover tests

EXPOSE 5000 8080

CMD ["python", "-m", "cyberguard.ui.dashboard"]
