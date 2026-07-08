# PentraAI

> **AI-Driven Autonomous Web Penetration Testing Agent**

PentraAI is an AI-powered autonomous web application security testing framework designed to perform intelligent reconnaissance, generate attack hypotheses, execute security tests, and report verified vulnerabilities against **authorized targets only**.

The project combines modern Large Language Models (LLMs) with automated reconnaissance and security testing to reduce manual effort during web application penetration testing.

---

# Features

- AI-driven attack planning
- Intelligent endpoint discovery
- Automated reconnaissance
- Multi-provider LLM support
  - DeepSeek (OpenCode Zen)
  - Google Gemini
  - DeepSeek Direct (optional)
- Automatic provider fallback
- API key rotation
- Vulnerability verification
- Benchmark framework
- Modern web dashboard
- Docker-based vulnerable lab support
- Asynchronous FastAPI backend

---

# Supported Security Tests

Current modules include:

- IDOR (Broken Object Level Authorization)
- Broken Authentication
- Broken Function Level Authorization (BFLA)
- SSRF
- Race Condition testing

---

# Project Structure

pentraai/
│
├── backend/
│   ├── main.py
│   ├── llm.py
│   ├── knowledge.py
│   ├── config.py
│   └── requirements.txt
│
├── frontend/
│   └── index.html
│
├── benchmark/
│   ├── benchmark.py
│   ├── ground_truth.json
│   ├── targets.example.json
│   ├── targets.json
│   └── results/
│
├── docker-compose.yml
├── Authorization.md
├── .env.example
└── README.md


# Architecture

                +----------------------+
                |      Frontend        |
                |    HTML Dashboard    |
                +----------+-----------+
                           |
                           v
                  FastAPI REST API
                           |
        +------------------+------------------+
        |                                     |
        v                                     v
Recon Engine                        AI Decision Engine
        |                                     |
        +------------------+------------------+
                           |
                           v
                 Vulnerability Modules
        (IDOR, Auth, BFLA, SSRF, Race, ...)
                           |
                           v
                  Verified Security Findings
```

# Requirements

- Python 3.11+
- pip
- Docker Desktop (recommended)
- Git

# Installation

## Clone

# bash
git clone https://github.com/<your-username>/pentraai.git
cd pentraai

## Create Virtual Environment

**Windows**

# bash
python -m venv .venv
.venv\Scripts\activate

**Linux/macOS**

# bash
python3 -m venv .venv
source .venv/bin/activate

## Install Dependencies

# bash
pip install -r backend/requirements.txt

## Install Playwright
# bash
playwright install

## Configure Environment
# bash
cp .env.example .env

Fill in your API keys:
env
LLM_PROVIDER_ORDER=deepseek_zen,gemini
OPENCODE_ZEN_API_KEYS=YOUR_KEY
GEMINI_API_KEYS=YOUR_KEY
DEEPSEEK_API_KEYS=

> Never commit your `.env` file.

# Running the Backend
# bash
cd backend
uvicorn main:app --reload


API:

http://localhost:8000


# Frontend

#bash
python -m http.server

or open `frontend/index.html`.

# Docker Test Labs

#bash
docker compose up -d

Available labs:

| Application | URL |
|-------------|-----|
| OWASP Juice Shop | http://localhost:3001 |
| crAPI | http://localhost:8888 |

# Benchmarking

```bash
python benchmark/benchmark.py
```

Results are stored under `benchmark/results/`.

# Technologies

- FastAPI
- Playwright
- HTTPX
- SQLAlchemy
- BeautifulSoup
- Docker
- Redis
- Celery
- Google Gemini
- DeepSeek

# Responsible Usage

PentraAI is intended **only** for:

- Authorized penetration testing
- Security research
- Educational use
- Local lab environments

Never test systems without explicit authorization.

# Contributing

```bash
git checkout -b feature/my-feature
git commit -m "Add new feature"
git push origin feature/my-feature
```

Then open a Pull Request.


# Authors

- Muhammad Saad Abdullah
- Pooja Sri Kuppuswamy Niranjana
- Prabanjan Velayutham

EPITA – Computer Security

# Disclaimer

The authors assume no responsibility for misuse of this software. Users are solely responsible for ensuring they have authorization before testing any system.
