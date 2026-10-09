# CyberShield — Defensive Cybersecurity Monitoring & Assessment Platform

CyberShield is an enterprise-grade, web-based defensive cybersecurity monitoring and security assessment platform. It is engineered to perform non-destructive diagnostics, integrity verification, log analysis, network scanning, and posture management exclusively for systems, networks, files, and domains that the operator owns or has explicit, documented authorization to assess.

---

> [!CAUTION]
> **DEFENSIVE SECURITY DISCLAIMER & CODE OF CONDUCT**  
> CyberShield is strictly a **defensive security platform**. It does **NOT** contain, support, or permit:
> - Malware, ransomware, or exploit delivery
> - Credential theft, harvesting, or stuffing
> - Brute-force password cracking or keylogging
> - Unauthorized network access, port flooding, or stealth evasion
> - Data exfiltration or destructive operations  
>
> All diagnostic scans, integrity checks, and analyses must only operate on explicitly authorized targets.

---

## Current Development Status

- **Phase 1 — Project Foundation & Tooling Setup** ✅
- **Phase 2 — Database Layer, ORM Models & Migrations** ✅
- **Phase 3 — Authentication, RBAC & Audit Logging** ✅
- **Phase 4 — Unified Security Findings Engine & Posture Dashboard** ✅
- **Phase 5 — Web Security Header Analyzer & SSRF Protection** ✅
- **Phase 6 — File Integrity Monitor (FIM) & SHA-256 Tamper Detection** ✅
- **Phase 7 — Defensive Log Analyzer & Threat Signature Engine** ✅
- **Phase 8 — Authorized Network Scanner & Perimeter Diagnostics** ✅
- **Phase 9 — Platform Security Hardening & Production Readiness** ✅
  - **Fail-safe Production Configuration**: Strict startup validation blocking `DEBUG=True`, weak/default `JWT_SECRET_KEY` (<32 chars or placeholder values), and wildcard CORS in production environments.
  - **Hardened Authentication & Session Lifecycle**: Bounded JWT lifetimes, strict signature verification, explicit handling of expired and forged tokens with `WWW-Authenticate: Bearer` headers, and automatic frontend session clearing on 401 responses.
  - **Comprehensive RBAC Enforcement**: Server-side and client-side authorization boundaries across all modules ensuring `viewer` accounts cannot initiate scans, baselines, analyses, or mutations; `analyst` accounts cannot delete findings (`admin` only).
  - **Data Minimization & Credential Protection**: Passwords and hashes are never exposed in API responses or audit logs; recursive sanitization redacts sensitive keys from audit log metadata.
  - **Database Transaction Safety**: Explicit transaction rollbacks on exceptions in database session generators preventing connection leaks or dirty states.
  - **Zero-Disclosure Exception Handling**: Production error handler sanitizes internal exception messages and stack traces to prevent server reconnaissance.

---

## Technology Stack

- **Backend**: Python 3.12+, FastAPI, Uvicorn (ASGI), SQLAlchemy 2.0, Alembic, Pydantic v2 & Pydantic Settings
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons
- **Security & Cryptography**: Argon2id password hashing, PyJWT, custom SSRF/DNS rebinding validation transport, SHA-256 cryptographic hashing
- **Testing & Quality**: Pytest (104+ unit tests), HTTPX, Black, Flake8, ESLint, TypeScript Strict Mode

---

## Project Structure

```
CyberShield/
├── backend/
│   ├── alembic/                 # Database migration versions & env
│   ├── app/
│   │   ├── models/              # SQLAlchemy ORM models (User, Finding, FIM, LogEvent, Scan, Audit)
│   │   ├── routes/              # FastAPI REST routers (auth, findings, dashboard, headers, fim, logs, scans)
│   │   ├── schemas/             # Pydantic v2 request/response validation schemas
│   │   ├── security/            # Security controls (hashing, JWT, SSRF guard, path guards, target guards)
│   │   ├── services/            # Defensive business logic & assessment engines
│   │   ├── utils/               # Audit helpers, sanitization, system helpers
│   │   ├── config.py            # Hardened Pydantic settings & production validator
│   │   ├── database.py          # SQLAlchemy engine, session maker, transaction rollback
│   │   └── main.py              # Application entrypoint, CORS, global error handling
│   ├── tests/
│   │   └── unit/                # Unit test suites (auth, findings, fim, logs, scans, ssrf, hardening)
│   ├── pyproject.toml           # Tooling configurations (Black, Pytest)
│   ├── .flake8                  # PEP 8 linting rules
│   ├── requirements.txt         # Production backend dependencies
│   └── requirements-dev.txt     # Development and test dependencies
│
├── frontend/
│   ├── src/
│   │   ├── app/                 # Root application shell
│   │   ├── components/          # Shared components (Navbar, StatusCard, etc.)
│   │   ├── features/            # Feature modules (auth, dashboard, findings, headers, fim, logs, scans)
│   │   ├── services/            # API client with token lifecycle and 401 interceptor
│   │   ├── types/               # TypeScript data models and interfaces
│   │   └── index.css            # Tailwind directives and cyber styling
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   └── tailwind.config.js
│
├── data/                        # Persistent database and baseline storage (.gitignore protected)
├── reports/                     # Generated security reports
├── logs/                        # Application runtime and audit logs (.gitignore protected)
├── .env.example                 # Comprehensive environment configuration template
├── .gitignore                   # Multi-layer protection against secret and database leaks
└── README.md
```

---

## Setup & Execution Guide

### Prerequisites
- Python 3.11+ or 3.12+
- Node.js 18+ and npm

### 1. Environment Configuration
Copy `.env.example` to create `.env`:
```powershell
# PowerShell
Copy-Item .env.example .env
```
For production, update the `.env` settings:
```ini
APP_ENV=production
DEBUG=False
CORS_ORIGINS=https://cybershield.yourdomain.com
JWT_SECRET_KEY=<generate-strong-random-64-character-hex-key>
```
To generate a secure production secret key:
```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

### 2. Backend Setup
From the repository root:
```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
API endpoints will be available at:
- Health check: `http://127.0.0.1:8000/api/v1/health`
- API documentation: `http://127.0.0.1:8000/api/v1/docs` (disabled when `DEBUG=False`)

### 3. Frontend Setup
In a separate terminal:
```powershell
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## Testing & Verification

### Backend Automated Test Suite
From the `backend/` directory with virtual environment active:
```powershell
pytest -q
```
*Current test suite: **104 passed, 1 skipped** (Windows non-admin symlink test), 0 failures.*

### Code Quality & Static Analysis
```powershell
# Backend
flake8 app tests
black --check app tests

# Frontend
cd ../frontend
npm run lint
npm run build
```

---

## Security Architecture & Defensive Boundaries

| Layer / Feature | Defensive Control | Enforcement Mechanism |
| :--- | :--- | :--- |
| **Configuration** | Production Validation | `Settings.validate_production_security` rejects `DEBUG=True`, weak keys, wildcard CORS |
| **Authentication** | Password Security | Argon2id hashing with salt; password never logged or returned in responses |
| **Token Handling** | JWT Lifetime & Claims | Requires `sub`, `exp`, `iat`; expired or forged tokens return 401 with `WWW-Authenticate` |
| **Frontend Lifecycle** | Session Eviction | Event-driven logout on 401 responses from authenticated API calls |
| **Authorization** | Role-Based Access Control | Strict hierarchy: Admin > Analyst > Viewer. Viewers restricted to read-only across all modules |
| **Audit Logging** | Tamper Evident & Redacted | Every security event logged; recursive sanitization redacts keys matching sensitive patterns |
| **Web Analyzer** | Anti-SSRF & Rebinding | Pre-connection DNS validation, custom transport socket binding, blocks internal & cloud metadata |
| **File Integrity** | Path & Symlink Defense | Monitored paths restricted to `FIM_ALLOWED_ROOTS`; blocks symlink escapes and path traversal |
| **Log Analyzer** | Traversal & DoS Defense | Files restricted to `LOG_ALLOWED_ROOTS`; line length and line count bounds prevent ReDoS/OOM |
| **Network Scanner** | Scope & Port Restriction | Connect-only TCP checks restricted to `SCAN_ALLOWED_TARGETS`; bounded port count, rate limits |
| **Database** | Transaction Safety | Database session generator executes `db.rollback()` on exceptions prior to closing |
| **Error Handling** | Information Disclosure | Global 500 handler sanitizes stack traces when `DEBUG=False` |
