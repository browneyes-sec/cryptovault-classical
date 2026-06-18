# Deliverable Technical Package — Deployment Guide

**Version:** 0.2.0  
**Date:** June 2026  

---

## 1. Installation

### 1.1 From Source (Development)

```bash
git clone https://github.com/browneyes-sec/cryptovault-classical.git
cd cryptovault-classical
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 1.2 From PyPI (When Published)

```bash
pip install cryptovault-classical
```

### 1.3 With Web Portal Dependencies

```bash
pip install -e ".[web]"
```

## 2. Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CRYPTOVAULT_KEYSTORE_PATH` | `~/.cryptovault/keystore.json` | Encrypted keystore location |
| `CRYPTOVAULT_KEYSTORE_PASSWORD` | (prompt) | Master password for keystore |
| `CRYPTOVAULT_LOG_LEVEL` | `INFO` | Logging verbosity |
| `CRYPTOVAULT_WEB_HOST` | `0.0.0.0` | Web portal bind address |
| `CRYPTOVAULT_WEB_PORT` | `8000` | Web portal port |
| `CRYPTOVAULT_WEB_WORKERS` | `1` | Uvicorn worker count |
| `CRYPTOVAULT_SECRET_KEY` | (random) | Session secret for web portal |

## 3. CLI Usage

```bash
# List all ciphers
cryptovault list-ciphers

# Encrypt/Decrypt
cryptovault encrypt --cipher caesar --key 3 --input "HELLO WORLD"
cryptovault decrypt --cipher caesar --key 3 --input "KHOOR ZRUOG"

# Cryptanalysis
cryptovault crack --cipher caesar --input "KHOOR ZRUOG"
cryptovault analyze --input "KHOOR ZRUOG"

# Key Management
cryptovault keygen --cipher vigenere --length 10
cryptovault dh-demo
```

## 4. Web Portal

### 4.1 Development Server

```bash
cd /tmp/opencode/cryptovault-classical
uvicorn cryptovault.web.api.main:app --reload --port 8000
```

### 4.2 Production Server

```bash
uvicorn cryptovault.web.api.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 4 \
  --log-level info \
  --access-log
```

### 4.3 Reverse Proxy (Nginx)

```nginx
server {
    listen 80;
    server_name crypto.local;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias /opt/cryptovault/static/;
        expires 1d;
        add_header Cache-Control "public, immutable";
    }
}
```

## 5. Docker

### 5.1 Dockerfile

```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

EXPOSE 8000

CMD ["uvicorn", "cryptovault.web.api.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "4"]
```

### 5.2 Docker Compose

```yaml
version: "3.8"
services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      - CRYPTOVAULT_LOG_LEVEL=info
      - CRYPTOVAULT_SECRET_KEY=${SECRET_KEY}
    volumes:
      - keystore:/app/.cryptovault
    restart: unless-stopped

volumes:
  keystore:
```

## 6. Production Hardening

### 6.1 Security Checklist

- [ ] Set strong `CRYPTOVAULT_SECRET_KEY` (256-bit random)
- [ ] Enable HTTPS via reverse proxy (Let's Encrypt)
- [ ] Restrict CORS origins in FastAPI config
- [ ] Set `CRYPTOVAULT_KEYSTORE_PASSWORD` from secrets manager
- [ ] Enable rate limiting on API endpoints
- [ ] Configure logging to file/syslog
- [ ] Set `--limit-concurrency` on Uvicorn

### 6.2 Performance Tuning

| Parameter | Development | Production |
|---|---|---|
| Workers | 1 | 2 × CPU cores |
| Log level | DEBUG | WARNING |
| Access log | Yes | Structured JSON |
| Reload | Yes | No |
| Timeout | 30s | 60s |

## 7. Scaling Considerations

- **Horizontal:** Add Uvicorn workers behind load balancer
- **Vertical:** Increase worker count for CPU-bound crypto operations
- **Caching:** Redis for session state and frequently accessed analyses
- **Database:** PostgreSQL for multi-user key storage (future)

## 8. Monitoring

```python
# Health check endpoint (planned)
@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "version": "0.2.0",
        "ciphers_loaded": len(CIPHER_REGISTRY),
        "uptime_seconds": time.time() - START_TIME
    }
```

## 9. Backup & Recovery

| Component | Backup Method | Frequency |
|---|---|---|
| KeyStore | File copy + encryption | Daily |
| Configuration | Version control | On change |
| Logs | Log rotation | Weekly |
| Database (future) | pg_dump | Daily |
