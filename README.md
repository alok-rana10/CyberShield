# CyberShield â€” Defensive Cybersecurity Monitoring & Assessment Platform

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.3-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-5.4-646CFF.svg?logo=vite&logoColor=white)](https://vitejs.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.4-38B2AC.svg?logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-119%20Passed%20%7C%201%20Skipped-success.svg)](#testing--quality-assurance)

CyberShield is a defensive cybersecurity monitoring and posture assessment platform engineered for authorized security environments. Built with a **FastAPI** asynchronous backend and a **React 18 + TypeScript** single-page frontend, CyberShield delivers automated security diagnostics, cryptographic file integrity baselining, multi-format log parsing with brute-force correlation, HTTP header hardening analysis with anti-SSRF transport enforcement, and policy-restricted TCP port discovery.

---

> [!CAUTION]
> ### Responsible-Use Disclaimer & Code of Conduct
> **CyberShield is engineered strictly for authorized, defensive cybersecurity operations.**
>
> Scanning, monitoring, and diagnostic assessments must **only** be performed on systems, networks, files, and domains that the operator owns or has explicit, documented authorization to assess.
>
> This platform does **NOT** contain, support, or permit:
> - Exploitation payloads, arbitrary code execution, or malware delivery
> - Credential theft, harvesting, brute-forcing, or dictionary attacks
> - Stealth scanning, SYN flood techniques, or IDS/IPS evasion mechanisms
> - Destructive file alterations or unauthorized privilege escalation
>
> All diagnostic modules enforce strict boundary guards (pre-request DNS validation, RFC 1918 / loopback blocking, canonical path isolation, and target whitelisting) to ensure assessments remain non-destructive and contained.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Key Defensive Features](#key-defensive-features)
  - [1. Web Security Header Analyzer & SSRF Guard](#1-web-security-header-analyzer--ssrf-guard)
  - [2. Cryptographic File Integrity Monitor (FIM)](#2-cryptographic-file-integrity-monitor-fim)
  - [3. Defensive Log Analyzer & Threat Correlator](#3-defensive-log-analyzer--threat-correlator)
  - [4. Policy-Governed Network Scanner](#4-policy-governed-network-scanner)
  - [5. Central Security Findings Engine & Dashboard](#5-central-security-findings-engine--dashboard)
  - [6. Authentication, RBAC & Tamper-Evident Audit Logging](#6-authentication-rbac--tamper-evident-audit-logging)
- [System Architecture](#system-architecture)
- [Technology Stack](#technology-stack)
- [Project Directory Structure](#project-directory-structure)
- [Prerequisites & System Requirements](#prerequisites--system-requirements)
- [Local Setup & Installation (Windows PowerShell)](#local-setup--installation-windows-powershell)
  - [Step 1: Environment Configuration](#step-1-environment-configuration)
  - [Step 2: Backend Setup & Database Migration](#step-2-backend-setup--database-migration)
  - [Step 3: Frontend Setup & Development Server](#step-3-frontend-setup--development-server)
- [Environment Configuration Reference](#environment-configuration-reference)
- [Testing & Quality Assurance](#testing--quality-assurance)
- [REST API Specification](#rest-api-specification)
- [Production Deployment on Render](#production-deployment-on-render)
- [Security Architecture & Boundary Controls](#security-architecture--boundary-controls)
- [Factual Security Posture & Known Limitations](#factual-security-posture--known-limitations)
- [License](#license)

---

## Project Overview

Modern defense-in-depth requires continuous verification across multiple system layers: web application perimeter posture, host-level filesystem integrity, system authentication telemetry, and network port exposure.

CyberShield aggregates these critical defensive disciplines into a unified operational dashboard:
* **Perimeter Defense**: Evaluates public HTTP response headers against OWASP secure header recommendations with built-in anti-SSRF socket transport controls.
* **Host Integrity**: Creates cryptographically verifiable baselines using SHA-256 to instantly detect file alterations, additions, or deletions in sensitive directories.
* **Audit & Log Telemetry**: Ingests authentication and access logs to correlate threat signals, such as brute-force authentication bursts and web path traversals.
* **Network Visibility**: Conducts non-destructive TCP connect checks restricted strictly to operator-authorized loopback or internal infrastructure.
* **Security Triage**: Feeds diagnostic results into a central findings registry equipped with severity classifications, CWE tags, and remediation advisories.

---

## Key Defensive Features

### 1. Web Security Header Analyzer & SSRF Guard
* **Comprehensive Header Auditing**: Inspects target endpoints for six critical security headers:
  * `Content-Security-Policy` (CSP)
  * `Strict-Transport-Security` (HSTS)
  * `X-Frame-Options` (Clickjacking prevention)
  * `X-Content-Type-Options` (MIME-sniffing protection)
  * `Referrer-Policy` (Referrer leakage defense)
  * `Permissions-Policy` (Browser API access control)
* **Hardening Scorecard**: Computes a weighted numerical score (0â€“100) and letter grade (`A+` through `F`) with actionable remediation guidance.
* **Multi-Stage SSRF Defense**:
  * **Pre-connection DNS Resolution**: Resolves target hostnames prior to socket creation.
  * **Prohibited IP Validation**: Blocks loopback (`127.0.0.0/8`, `::1`), private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local, multicast, and cloud metadata services (`169.254.169.254`, `metadata.google.internal`).
  * **DNS Rebinding Prevention**: Uses a custom synchronous HTTP transport pinning validated IP addresses directly to the connection socket.
  * **NAT64 / IPv4-Mapped Handling**: Inspects embedded IPv4 addresses in `64:ff9b::/96` ranges to allow legitimate translated destinations while blocking prohibited internal destinations.
  * **Strict Port Bounding**: Allows connections exclusively to standard web ports (`80` and `443`).

### 2. Cryptographic File Integrity Monitor (FIM)
* **Cryptographic Baselining**: Computes SHA-256 hashes and filesystem metadata (size, modification time) across authorized directories.
* **Tamper Detection**: Identifies modified files (hash mismatches), newly created unauthorized files, and removed critical files.
* **Automated Finding Pipeline**: Automatically generates High/Medium security findings containing exact cryptographic hash evidence upon detecting unauthorized modifications.
* **Filesystem Containment**: Constrains scans strictly within configured `FIM_ALLOWED_ROOTS`, rejecting directory traversal (`../`) and symbolic link escapes. File size caps prevent memory exhaustion denial-of-service.

### 3. Defensive Log Analyzer & Threat Correlator
* **Multi-Format Parsing**: Ingests authentication logs, Nginx/Apache access logs, and generic syslog formats.
* **Threat Correlation Rules**:
  * **Brute-Force Detection**: Correlates authentication failures within a sliding time window (triggers High finding when failures exceed threshold).
  * **Web Application Probing**: Identifies directory traversal sequences, SQL injection artifacts, and automated scanner signatures.
  * **Access Denied Spikes**: Flags repeated authorization failures and privilege escalation attempts.
* **Safe Evidence Extraction**: Attaches redacted raw log line excerpts and source IP telemetry to generated findings for verifiable post-incident review.
* **Resource Safeguards**: Limits processed file sizes (`LOG_MAX_FILE_SIZE_BYTES`), enforces maximum line lengths (`LOG_MAX_LINE_LENGTH`), and caps processed lines per run to prevent ReDoS or memory exhaustion.

### 4. Policy-Governed Network Scanner
* **Defensive TCP Handshake Probing**: Uses standard OS-level three-way TCP connect calls (`socket.connect_ex`) without raw socket manipulation, SYN flooding, or packet crafting.
* **Strict Target Policy**: Restricts scan targets strictly to whitelist-configured assets (`SCAN_ALLOWED_TARGETS`, defaulting to `127.0.0.1`, `localhost`, `::1`). External or unapproved targets are rejected with HTTP 403 Forbidden.
* **Attestation Requirement**: Enforces mandatory operator authorization confirmation for every scan request.
* **Operational Limits**: Caps maximum ports per scan (100 ports), enforces per-port socket connect timeouts (1.5s), and applies sliding-window user rate limiting.
* **High-Risk Port Findings**: Generates findings for confirmed cleartext protocols (Telnet port 23, cleartext FTP port 21) and exposed database interfaces.

### 5. Central Security Findings Engine & Dashboard
* **Unified Finding Schema**: Standardizes findings across all assessment engines (`web_security`, `integrity`, `authentication`, `network`, `general`).
* **Severity Triage**: Classifies findings into `critical`, `high`, `medium`, `low`, and `informational`.
* **Lifecycle Management**: Tracks finding statuses across `open`, `investigating`, `resolved`, and `false_positive` states with operator attribution.
* **Executive Posture Dashboard**: Aggregates real-time security metrics, severity breakdown charts, engine operational statuses, and recent audit activity.

### 6. Authentication, RBAC & Tamper-Evident Audit Logging
* **Argon2id Hashing**: Uses state-of-the-art Argon2id password hashing with unique salt and strict password complexity rules (uppercase, lowercase, digit, special character).
* **JWT Lifecycle**: Issues signed JSON Web Tokens requiring `sub`, `exp`, and `iat` claims. Expired or forged tokens return `401 Unauthorized` with `WWW-Authenticate: Bearer` headers.
* **Role-Based Access Control (RBAC)**:
  * **Admin**: Complete platform control, user management, and authorization to permanently delete findings.
  * **Analyst**: Can initiate analyses, create baselines, run scans, and update finding statuses. Cannot delete findings.
  * **Viewer**: Read-only visibility across dashboards, findings, and logs. Cannot trigger scans or mutate state.
* **Audit Trail**: Immutable database audit table recording action names, actor IDs, client IP addresses, user agents, and timestamps. Sensitive keys (passwords, tokens, API keys) are recursively redacted before storage.

---

## System Architecture

CyberShield implements a clean, layered architecture separating user interface presentation, security perimeter gateways, assessment engines, and transactional persistence.

```mermaid
flowchart TD
    subgraph Client["Presentation Layer (React 18 + TypeScript + Vite + Tailwind CSS)"]
        UI["CyberShield Single Page Application"]
        AuthUI["Auth Context & Session Eviction (sessionStorage)"]
        DashUI["Posture Dashboard"]
        FindUI["Findings Registry"]
        HeadUI["Web Header Analyzer UI"]
        FimUI["File Integrity Monitor UI"]
        LogUI["Defensive Log Analyzer UI"]
        ScanUI["Authorized Network Scanner UI"]
    end

    subgraph Gateway["API Gateway & Security Middleware (FastAPI)"]
        CORS["CORS Middleware"]
        AuthGuard["JWT Bearer Guard (sub, exp, iat claims)"]
        RBACGuard["Role-Based Access Control Factory (Admin / Analyst / Viewer)"]
        RateLimiter["Sliding Window Rate Limiters"]
        ErrorHandler["Sanitizing Exception Handler (No Leakage)"]
    end

    subgraph Engines["Defensive Security Assessment Engines"]
        AuthSvc["Authentication Service (Argon2id + PyJWT)"]
        FindSvc["Findings Engine & Triage Service"]
        HeadSvc["Header Analyzer & SSRF Transport Guard"]
        FimSvc["File Integrity Monitor (SHA-256 Hashes)"]
        LogSvc["Defensive Log Analyzer & Threat Correlator"]
        ScanSvc["Authorized Network Scanner (TCP Connect)"]
    end

    subgraph SecurityGuards["Strict Policy & Containment Guards"]
        SSRFGuard["SSRF & DNS Rebinding Guard (Custom Transport)"]
        FIMPathGuard["FIM Allowed Roots & Symlink Guard"]
        LogPathGuard["Log Allowed Roots & Traversal Guard"]
        ScanTargetGuard["Scan Target Policy & Port Bounding Guard"]
        AuditRedactor["Audit Sanitizer (Credential Redaction)"]
    end

    subgraph Persistence["Storage & Persistence Layer"]
        DB[(Database: SQLite / PostgreSQL via SQLAlchemy 2.0 ORM)]
        Alembic["Alembic Migration Engine"]
        AuditTable["Immutable Audit Logs Table"]
        FindingsTable["Unified Security Findings Table"]
    end

    UI --> Gateway
    Gateway --> Engines
    Engines --> SecurityGuards
    Engines --> Persistence
    SecurityGuards -.-> AuditRedactor -.-> AuditTable
    Engines --> FindSvc --> FindingsTable
```

---

## Technology Stack

| Layer | Component | Technologies | Implementation Details |
| :--- | :--- | :--- | :--- |
| **Backend API** | Core Framework | Python 3.12+, FastAPI, Uvicorn | Async ASGI server, modular routers, OpenAPI 3.1 specification |
| **Data Validation** | Request/Response Typing | Pydantic v2, Pydantic Settings | Strict schema enforcement, runtime environment validation |
| **Persistence** | ORM & Migrations | SQLAlchemy 2.0, Alembic, SQLite | Modern 2.0 declarative models, batch schema migrations, PostgreSQL path |
| **Authentication** | Cryptography & Tokens | Argon2id (`argon2-cffi`), PyJWT | Memory-hard password hashing, signed HMAC-SHA256 JWT sessions |
| **Network & SSRF** | HTTP & Sockets | HTTPX, HTTPCore, Python Sockets | Synchronous socket transport, pre-request DNS validation, timeout bounding |
| **Frontend UI** | Client Application | React 18, TypeScript, Vite | Component-driven architecture, custom hooks, strict TypeScript types |
| **Styling & Design** | User Experience | Tailwind CSS, Lucide React Icons | Modern cybersecurity dark-theme palette, accessible responsive layout |
| **Quality & Tests** | Testing & Linting | Pytest, Flake8, Black, ESLint | 116 automated unit/integration tests, PEP 8 enforcement, TypeScript build checks |

---

## Project Directory Structure

```text
CyberShield/
â”œâ”€â”€ backend/
â”‚   â”œâ”€â”€ alembic/                 # Database migrations (versions & env.py)
â”‚   â”œâ”€â”€ app/
â”‚   â”‚   â”œâ”€â”€ models/              # SQLAlchemy models (User, Finding, FIM, LogEvent, Scan, Audit)
â”‚   â”‚   â”œâ”€â”€ routes/              # FastAPI routers (auth, findings, dashboard, headers, fim, logs, scans)
â”‚   â”‚   â”œâ”€â”€ schemas/             # Pydantic v2 schemas for request/response validation
â”‚   â”‚   â”œâ”€â”€ security/            # Security guards (hashing, JWT, SSRF, FIM paths, log paths, scan targets)
â”‚   â”‚   â”œâ”€â”€ services/            # Core assessment engines (FIM, logs, headers, scanner, findings)
â”‚   â”‚   â”œâ”€â”€ utils/               # Audit helpers, IP extraction, recursive sanitization
â”‚   â”‚   â”œâ”€â”€ config.py            # Pydantic Settings with production readiness validation
â”‚   â”‚   â”œâ”€â”€ database.py          # SQLAlchemy engine, session maker, path normalizer
â”‚   â”‚   â””â”€â”€ main.py              # FastAPI app entrypoint, CORS, exception handlers
â”‚   â”œâ”€â”€ tests/
â”‚   â”‚   â””â”€â”€ unit/                # 116 automated unit and end-to-end integration tests
â”‚   â”œâ”€â”€ pyproject.toml           # Black and Pytest configuration
â”‚   â”œâ”€â”€ .flake8                  # PEP 8 linting configuration
â”‚   â”œâ”€â”€ requirements.txt         # Production dependencies
â”‚   â””â”€â”€ requirements-dev.txt     # Development, testing, and linting dependencies
â”‚
â”œâ”€â”€ frontend/
â”‚   â”œâ”€â”€ src/
â”‚   â”‚   â”œâ”€â”€ app/                 # Root application shell and navigation layout
â”‚   â”‚   â”œâ”€â”€ components/          # Shared components (Navbar, StatusCard)
â”‚   â”‚   â”œâ”€â”€ features/            # Feature modules:
â”‚   â”‚   â”‚   â”œâ”€â”€ auth/            # LoginPage, RegisterPage, ProtectedRoute, AuthContext
â”‚   â”‚   â”‚   â”œâ”€â”€ dashboard/       # DashboardOverview posture summary
â”‚   â”‚   â”‚   â”œâ”€â”€ findings/        # FindingsPage registry with search, filter, and triage
â”‚   â”‚   â”‚   â”œâ”€â”€ headers/         # WebSecurityHeadersPage analyzer UI
â”‚   â”‚   â”‚   â”œâ”€â”€ fim/             # FileIntegrityMonitorPage baseline & verification UI
â”‚   â”‚   â”‚   â”œâ”€â”€ logs/            # LogAnalyzerPage event viewer & analysis UI
â”‚   â”‚   â”‚   â””â”€â”€ scans/           # NetworkScannerPage authorized TCP scanner UI
â”‚   â”‚   â”œâ”€â”€ services/            # API client with token lifecycle and 401 interceptor
â”‚   â”‚   â”œâ”€â”€ types/               # TypeScript interfaces and data models
â”‚   â”‚   â””â”€â”€ index.css            # Tailwind directives and cyber theme styling
â”‚   â”œâ”€â”€ package.json             # Frontend dependencies and build scripts
â”‚   â”œâ”€â”€ package-lock.json        # Locked dependency tree for deterministic builds
â”‚   â”œâ”€â”€ tsconfig.json            # TypeScript compiler configuration
â”‚   â”œâ”€â”€ vite.config.ts           # Vite bundler configuration
â”‚   â””â”€â”€ tailwind.config.js       # Tailwind CSS theme configuration
â”‚
â”œâ”€â”€ data/                        # Persistent database and baseline storage (.gitignore protected)
â”œâ”€â”€ docs/                        # Architectural documentation:
â”‚   â””â”€â”€ API_SPEC.md              # Complete REST API specification (28 endpoints)
â”œâ”€â”€ logs/                        # Application runtime and audit logs (.gitignore protected)
â”œâ”€â”€ reports/                     # Generated assessment reports (.gitignore protected)
â”œâ”€â”€ .env.example                 # Comprehensive environment configuration template
â”œâ”€â”€ .gitignore                   # Multi-layer protection against secret and database leaks
â”œâ”€â”€ LICENSE                      # MIT Open Source License
â”œâ”€â”€ docker-compose.yml           # Containerized multi-service definition
â”œâ”€â”€ render.yaml                  # Render.com Blueprint deployment specification
â””â”€â”€ README.md                    # Project documentation
```

---

## Prerequisites & System Requirements

Before running CyberShield locally, verify that your environment meets the following requirements:

* **Operating System**: Windows 10/11 (PowerShell), macOS, or Linux
* **Python**: `3.11` or `3.12` installed (verify with `python --version`)
* **Node.js**: `18.x` or `20.x` LTS and `npm` installed (verify with `node -v` and `npm -v`)
* **Git**: `2.30+` installed (verify with `git --version`)

---

## Local Setup & Installation (Windows PowerShell)

Follow these steps to run CyberShield locally on Windows using PowerShell:

### Step 1: Environment Configuration

```powershell
# Clone the repository
git clone https://github.com/yourusername/CyberShield.git
cd CyberShield

# Create your local environment file from the template
Copy-Item .env.example .env
```

Open `.env` to review the default local configuration:
* `APP_ENV=development` and `DEBUG=True` allow local testing and enable the interactive Swagger UI.
* `DATABASE_URL` defaults to SQLite at `./data/cybershield.db`.
* `FIM_ALLOWED_ROOTS` defaults to `./monitored,./data`.
* `LOG_ALLOWED_ROOTS` defaults to `./logs,./data/logs`.
* `SCAN_ALLOWED_TARGETS` defaults to `127.0.0.1,localhost,::1`.

---

### Step 2: Backend Setup & Database Migration

Open a PowerShell terminal:

```powershell
# Navigate to the backend directory
cd backend

# Create a Python virtual environment
python -m venv .venv

# Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# Upgrade pip and install development dependencies
pip install --upgrade pip
pip install -r requirements-dev.txt

# Execute database migrations using Alembic
alembic upgrade head

# Start the FastAPI ASGI server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The backend server will start at:
* **API Base URL**: `http://127.0.0.1:8000/api/v1`
* **Interactive Swagger UI**: `http://127.0.0.1:8000/api/v1/docs`
* **Health Check**: `http://127.0.0.1:8000/api/v1/health`

---

### Step 3: Frontend Setup & Development Server

Open a second PowerShell terminal:

```powershell
# Navigate to the frontend directory
cd frontend

# Install Node dependencies
npm install

# Start the Vite development server
npm run dev
```

The frontend web interface will be available at:
* **Web UI**: `http://localhost:5173`

---

## Environment Configuration Reference

The platform uses Pydantic Settings to load and validate variables from `.env` or system environment variables:

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `APP_NAME` | `CyberShield` | Application branding and system identifier |
| `APP_ENV` | `development` | Environment mode (`development` or `production`). Production enforces strict secret rules |
| `DEBUG` | `True` | Debug flag. **Must be `False` in production** (enforced by startup validator) |
| `API_V1_PREFIX` | `/api/v1` | URL prefix for all REST API endpoints |
| `HOST` | `0.0.0.0` | Bind host interface for the ASGI server |
| `PORT` | `8000` | Bind port for the ASGI server |
| `CORS_ORIGINS` | `http://localhost:5173,...` | Comma-separated allowed CORS origins. Wildcard `*` is rejected in production |
| `DATABASE_URL` | `sqlite:///./data/cybershield.db` | SQLAlchemy connection string (SQLite for dev, PostgreSQL for production) |
| `JWT_SECRET_KEY` | `cybershield-dev-secret-...` | Secret key for signing access tokens. Must be >= 32 chars and non-default in production |
| `JWT_ALGORITHM` | `HS256` | JWT HMAC signing algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Lifespan in minutes for issued JWT tokens |
| `FIM_ALLOWED_ROOTS` | `./monitored,./data` | Comma-separated directory paths authorized for file integrity monitoring |
| `FIM_MAX_FILE_SIZE_BYTES` | `104857600` | Maximum file size (100 MB) processed by the FIM engine |
| `FIM_MAX_FILES_PER_BASELINE` | `1000` | Maximum file count allowed in a single directory baseline |
| `LOG_ALLOWED_ROOTS` | `./logs,./data/logs` | Comma-separated directory paths authorized for defensive log analysis |
| `LOG_MAX_FILE_SIZE_BYTES` | `52428800` | Maximum log file size (50 MB) processed per analysis run |
| `LOG_MAX_LINE_LENGTH` | `4096` | Maximum characters per log line to prevent ReDoS / memory exhaustion |
| `LOG_MAX_LINES_PER_RUN` | `50000` | Maximum lines read in a single log analysis run |
| `LOG_BRUTE_FORCE_THRESHOLD` | `5` | Number of failed authentications within window to trigger a High finding |
| `LOG_BRUTE_FORCE_WINDOW_SECONDS`| `300` | Sliding window duration (5 minutes) for log correlation |
| `SCAN_ALLOWED_TARGETS` | `127.0.0.1,localhost,::1` | Comma-separated IP addresses or hostnames authorized for TCP scanning |
| `SCAN_MAX_PORTS_PER_SCAN` | `100` | Maximum port count permitted per scan execution |
| `SCAN_CONNECT_TIMEOUT_SECONDS` | `1.5` | Individual TCP connect timeout per port probe |
| `SCAN_MAX_CONCURRENCY` | `20` | Maximum concurrent worker sockets in scanner thread pool |
| `SCAN_RATE_LIMIT_PER_MINUTE` | `10` | Maximum scans permitted per minute per operator |
| `SCAN_TOTAL_TIMEOUT_SECONDS` | `30` | Maximum overall wall-clock execution time for a scan job |

---

## Testing & Quality Assurance

CyberShield maintains an automated testing suite ensuring zero regressions across all security controls.

### 1. Run Automated Backend Tests (Pytest)
From the `backend/` directory:
```powershell
.\.venv\Scripts\pytest -v
```
* **Status**: **119 passed, 1 skipped** in ~24s.
* *Note on Skipped Test*: `test_logs_symlink_escape_rejected` skips gracefully on non-elevated Windows environments because Windows requires Administrator privileges or Developer Mode to create filesystem symlinks (`os.symlink`). All canonical path isolation tests pass unconditionally.

### 2. Run Backend Code Linters & Formatters
From the `backend/` directory:
```powershell
# Verify code formatting with Black (PEP 8 line-length 100)
.\.venv\Scripts\black --check app tests scripts

# Run static linting with Flake8
.\.venv\Scripts\flake8 app tests scripts
```

### 3. Run Frontend Linting & Build Checks
From the `frontend/` directory:
```powershell
# Execute ESLint checks
npm run lint

# Execute TypeScript typechecking and production bundle compilation
npm run build
```

---

## REST API Specification

CyberShield provides a clean, fully documented REST API exposing **28 endpoints** across 8 core modules.

* Detailed API documentation: [**`docs/API_SPEC.md`**](docs/API_SPEC.md)
* Interactive Swagger UI: `http://127.0.0.1:8000/api/v1/docs` (available when `DEBUG=True`)

### Endpoint Overview

| Module | Method & Route | Auth / RBAC | Description |
| :--- | :--- | :--- | :--- |
| **System** | `GET /api/v1/health` | Public | System health check and operational status |
| **Auth** | `POST /api/v1/auth/register` | Public | Register a new platform user (`analyst` or `viewer`) |
| **Auth** | `POST /api/v1/auth/login` | Public | Authenticate credentials and receive JWT access token |
| **Auth** | `POST /api/v1/auth/refresh` | Public | Refresh an active JWT access token |
| **Auth** | `GET /api/v1/auth/me` | Authenticated | Retrieve current authenticated operator profile and role |
| **Dashboard** | `GET /api/v1/dashboard/summary` | Authenticated | Aggregated posture statistics, severity counts, and engine states |
| **Findings** | `GET /api/v1/findings` | Authenticated | List and filter security findings by severity, category, or status |
| **Findings** | `POST /api/v1/findings` | Analyst / Admin | Create an authorized security finding |
| **Findings** | `GET /api/v1/findings/{id}` | Authenticated | Retrieve finding details with remediation guidance and evidence |
| **Findings** | `PATCH /api/v1/findings/{id}` | Analyst / Admin | Update finding details, severity, or remediation guidance |
| **Findings** | `PATCH /api/v1/findings/{id}/status` | Analyst / Admin | Transition finding lifecycle status (`open`, `investigating`, `resolved`) |
| **Findings** | `DELETE /api/v1/findings/{id}` | **Admin Only** | Permanently delete a security finding |
| **Headers** | `POST /api/v1/headers/analyze` | Analyst / Admin | Analyze security headers with mandatory SSRF protection |
| **Headers** | `GET /api/v1/headers/history` | Authenticated | Retrieve historical header analysis assessments |
| **FIM** | `POST /api/v1/fim/baselines` | Analyst / Admin | Generate cryptographic SHA-256 baseline for authorized directory |
| **FIM** | `POST /api/v1/fim/check` | Analyst / Admin | Compare directory against baseline to detect file alterations |
| **FIM** | `GET /api/v1/fim/records` | Authenticated | View file baseline records and cryptographic metadata |
| **FIM** | `GET /api/v1/fim/status` | Authenticated | Summary of monitored files and baseline integrity status |
| **FIM** | `GET /api/v1/fim/roots` | Authenticated | List configured authorized monitoring roots |
| **Logs** | `POST /api/v1/logs/analyze` | Analyst / Admin | Parse authorized log file and correlate threat patterns |
| **Logs** | `GET /api/v1/logs/events` | Authenticated | Query normalized security events with pagination and filters |
| **Logs** | `GET /api/v1/logs/events/{id}` | Authenticated | Retrieve individual normalized log event details |
| **Logs** | `GET /api/v1/logs/summary` | Authenticated | Aggregated event statistics and threat category breakdown |
| **Logs** | `GET /api/v1/logs/roots` | Authenticated | List configured authorized log file directories |
| **Scanner** | `POST /api/v1/scans` | Analyst / Admin | Execute non-destructive TCP connect scan against authorized target |
| **Scanner** | `GET /api/v1/scans` | Authenticated | List historical network scan records |
| **Scanner** | `GET /api/v1/scans/{id}` | Authenticated | Retrieve port scan results, open services, and duration |
| **Scanner** | `GET /api/v1/scans/summary` | Authenticated | Summary metrics of scanned ports and identified exposures |
| **Scanner** | `GET /api/v1/scans/scope` | Authenticated | View configured authorized scan target whitelist |

---

## Production Deployment on Render

CyberShield is ready for turnkey production deployment on [Render](https://render.com) using the included [`render.yaml`](render.yaml) Blueprint or manual service configuration.

### Architecture on Render
* **Database (`cybershield-db`)**: Render Managed PostgreSQL replacing local SQLite for production concurrency and data persistence.
* **Backend Web Service (`cybershield-backend`)**: Python 3.12+ ASGI service running FastAPI on Uvicorn behind Render's automated TLS reverse proxy.
* **Frontend Static Site (`cybershield-frontend`)**: Global CDN hosting the compiled React 18 single-page application.

---

### Method 1: Automated Blueprint Deployment (Recommended)
1. Fork or push this repository to your GitHub account (`https://github.com/alok-rana10/CyberShield`).
2. Log in to the [Render Dashboard](https://dashboard.render.com).
3. Click **Blueprints** â†’ **New Blueprint Instance**.
4. Connect your GitHub repository. Render reads [`render.yaml`](render.yaml) and provisions:
   - PostgreSQL Database (`cybershield-db`)
   - Backend Web Service (`cybershield-backend`)
   - Frontend Static Site (`cybershield-frontend`)
5. During creation, Render will prompt for un-synced environment variables:
   - `CORS_ORIGINS`: Set to your frontend static site URL (e.g., `https://cybershield-frontend.onrender.com`).
   - `VITE_API_BASE_URL`: Set to your backend web service URL (e.g., `https://cybershield-backend.onrender.com`).
6. Click **Apply**. Render will automatically run Alembic migrations on startup and launch both services.

---

### Method 2: Manual Dashboard Configuration

#### Step 1: Provision Managed PostgreSQL
* **Name**: `cybershield-db`
* **Database**: `cybershield`
* **User**: `cybershield`
* **Region**: `Oregon` (or match your service region)
* **Plan**: `Free` or `Starter`
* Copy the generated **Internal Database URL** (e.g., `postgres://cybershield:password@dpg-xxx:5432/cybershield`).

#### Step 2: Deploy Backend Web Service
* **Type**: Web Service
* **Name**: `cybershield-backend`
* **Runtime**: `Python`
* **Root Directory**: `backend`
* **Build Command**: `pip install --upgrade pip && pip install -r requirements.txt`
* **Start Command**: `alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port $PORT`
* **Health Check Path**: `/api/v1/health`
* **Environment Variables**:
  | Variable | Production Value | Purpose |
  | :--- | :--- | :--- |
  | `APP_ENV` | `production` | Enforces production security checks |
  | `DEBUG` | `False` | Disables debug mode and suppresses internal error traces |
  | `DATABASE_URL` | `<Your-Internal-Database-URL>` | Automatic normalization to `postgresql+psycopg2://` |
  | `JWT_SECRET_KEY` | `<Random-32-Char-Secret>` | Generate via `python -c "import secrets; print(secrets.token_hex(32))"` |
  | `CORS_ORIGINS` | `https://cybershield-frontend.onrender.com` | Restricts CORS to the frontend domain (no wildcard `*`) |
  | `SCAN_ALLOWED_TARGETS` | `127.0.0.1,localhost,::1` | Allowed targets for TCP scanning |
  | `FIM_ALLOWED_ROOTS` | `./monitored,./data` | Authorized roots for file integrity baselines |
  | `LOG_ALLOWED_ROOTS` | `./logs,./data/logs` | Authorized roots for log analysis |

#### Step 3: Deploy Frontend Static Site
* **Type**: Static Site
* **Name**: `cybershield-frontend`
* **Root Directory**: `frontend`
* **Build Command**: `npm install && npm run build`
* **Publish Directory**: `dist`
* **Redirects / Rewrites** *(Mandatory for React SPA routing)*:
  * **Type**: `Rewrite`
  * **Source**: `/*`
  * **Destination**: `/index.html`
* **Environment Variables**:
  | Variable | Production Value | Purpose |
  | :--- | :--- | :--- |
  | `VITE_API_BASE_URL` | `https://cybershield-backend.onrender.com` | Embedded into the client bundle at build time |

---

## Security Architecture & Boundary Controls

| Defensive Boundary | Threat Mitigated | Technical Implementation |
| :--- | :--- | :--- |
| **SSRF / DNS Rebinding** | Open proxy abuse, internal reconnaissance, cloud metadata exfiltration | Pre-request DNS resolution; custom synchronous HTTP transport binding validated socket IP; unconditional blocking of loopback, RFC 1918, link-local, multicast, and metadata addresses |
| **Filesystem Traversal** | Unauthorized file disclosure, arbitrary file overwrite | Strict canonical path resolution against `FIM_ALLOWED_ROOTS` and `LOG_ALLOWED_ROOTS`; rejection of symlink escapes and parent traversals (`../`) |
| **Network Probing Scope** | Unauthorized port scanning, network abuse | Whitelisted target matching (`SCAN_ALLOWED_TARGETS`); strict port caps (max 100); sliding window user rate limiting; standard TCP connect-only |
| **Credential Protection** | Password disclosure, hash leakage | Argon2id hashing; exclusion of sensitive fields from API schemas; recursive audit detail sanitization redacting secret keys |
| **Session Integrity** | Stale session access, token forgery | Mandatory JWT claim validation (`sub`, `exp`, `iat`); event-driven frontend logout on 401; sessionStorage lifecycle management |
| **Information Disclosure** | Stack trace & SQL schema reconnaissance | Global exception handler sanitizing unhandled errors in non-debug mode; server-side error logging with client-safe generic responses |

---

## Factual Security Posture & Known Limitations

To maintain engineering transparency, the following technical boundaries apply to the current architecture:

1. **Local Concurrency & SQLite**:
   * For local development and demonstration, CyberShield defaults to SQLite. Under high concurrent write loads (e.g., dozens of simultaneous scan runs or baselines), SQLite database file locks may occur.
   * *Production Path*: The codebase uses SQLAlchemy 2.0 with Alembic migrations and is designed for zero-code configuration to PostgreSQL by updating `DATABASE_URL`.
2. **Reverse Proxy & TLS Termination**:
   * The application does not natively implement HTTPS/TLS certificates inside Uvicorn. For production deployments, CyberShield must be placed behind a reverse proxy (Nginx, Traefik, or Caddy) handling TLS termination and HSTS enforcement.
   * *Production Path*: Configure HTTPS reverse proxy termination and update `CORS_ORIGINS` to trusted HTTPS origins.
3. **Connect-Only Network Diagnostics**:
   * The Network Scanner intentionally uses standard OS-level TCP connect calls (`socket.connect_ex`). It does not perform SYN stealth scans, OS fingerprinting, banner grabbing, or vulnerability fuzzing by defensive design.
4. **Local Filesystem FIM Scope**:
   * The FIM engine operates on local directory paths accessible by the application process. It does not monitor remote agent endpoints or kernel-level filesystem events (`inotify`/`ReadDirectoryChangesW`) in real time; checks are executed on demand.
5. **Windows Symlink Test Privilege**:
   * Creating symbolic links on Windows requires Developer Mode or elevated Administrator privileges. In non-elevated developer shells, the symlink escape test (`test_logs_symlink_escape_rejected`) is gracefully skipped while all path canonicalization checks pass.

---

## License

This project is licensed under the **MIT License**. See the [**`LICENSE`**](LICENSE) file for complete terms and copyright notices.
