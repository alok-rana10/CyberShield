# CyberShield — Defensive Cybersecurity Monitoring & Assessment Platform

CyberShield is an enterprise-grade, web-based defensive cybersecurity monitoring and security assessment platform. Engineered strictly for defensive operations, CyberShield provides non-destructive security posture diagnostics, cryptographic file integrity monitoring, log correlation and threat detection, web security header evaluation with mandatory anti-SSRF protections, and policy-governed network port discovery for authorized assets.

---

> [!CAUTION]
> **DEFENSIVE SECURITY DISCLAIMER & CODE OF CONDUCT**  
> CyberShield is engineered exclusively as a **defensive security monitoring platform**. It does **NOT** contain, support, or permit:
> - Malware, ransomware, or exploit delivery payloads
> - Credential harvesting, credential theft, or credential stuffing
> - Brute-force password cracking, dictionary attacks, or keylogging
> - Stealth port scanning, packet flooding, or IDS/IPS evasion
> - Data exfiltration or destructive system alterations  
>
> All diagnostic scans, integrity baselines, log evaluations, and header assessments must only operate on systems, networks, files, and domains that the operator owns or has explicit, documented authorization to assess.

---

## Architecture Overview

CyberShield implements a clean, layered architecture separating presentation, security boundary enforcement, assessment engines, and transactional persistence.

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
        LogSvc["Defensive Log Analyzer & Pattern Engine"]
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

## Core Defensive Modules

### 1. Authentication, RBAC & Audit Logging
- **Password Security**: Argon2id password hashing with unique salt; strict password complexity validation (minimum 8 characters, uppercase, lowercase, digit, and special character). Passwords and password hashes are never returned in API responses or written to logs.
- **Token Lifecycle**: Signed JSON Web Tokens (PyJWT) requiring `sub`, `exp`, and `iat` claims. Expired or forged tokens return `401 Unauthorized` with `WWW-Authenticate: Bearer` headers.
- **Frontend Session Lifecycle**: Event-driven token interceptor that detects `401 Unauthorized` responses and automatically evicts session tokens from `sessionStorage`, redirecting the operator cleanly to the login interface.
- **Role-Based Access Control (RBAC)**:
  - `Admin`: Full platform control, user management, and permanent deletion of findings.
  - `Analyst`: Operational triage, header analysis, FIM baseline management, log analysis, and network scanning. Forbidden from deleting findings.
  - `Viewer`: Read-only access to all dashboards, finding details, assessment histories, and scopes. Strictly forbidden from creating findings, running scans, or mutating state (HTTP 403).
- **Tamper-Evident Audit Logging**: Immutable database audit trail capturing action, actor ID, client IP address, user agent, and timestamp. Recursive sanitization redacts sensitive fields matching passwords, tokens, API keys, and hashes.

### 2. Central Security Findings Registry & Posture Dashboard
- **Standardized Finding Schema**: Unified categorization across all defensive engines (`web_security`, `integrity`, `authentication`, `network`, `general`).
- **Severity Classification**: `critical`, `high`, `medium`, `low`, and `informational`.
- **Lifecycle Tracking**: State transitions between `open`, `resolved`, and `accepted` with resolution timestamps and operator attribution.
- **Defensive Triage**: Rich search and filtering by severity, lifecycle status, category, originating module, and affected resource. Actionable remediation advice and diagnostic evidence are stored with each finding.
- **Posture Dashboard**: Real-time aggregated metrics displaying total findings, open vs. resolved ratios, severity distributions, and recent assessment highlights.

### 3. Web Security Header Analyzer & SSRF Protection
- **Evaluated Headers**: Evaluates presence and configuration of 6 critical web security headers:
  - `Content-Security-Policy` (CSP)
  - `Strict-Transport-Security` (HSTS)
  - `X-Frame-Options` (Clickjacking defense)
  - `X-Content-Type-Options` (MIME-sniffing prevention)
  - `Referrer-Policy` (Referrer leakage control)
  - `Permissions-Policy` (Browser feature restriction)
- **Hardening Scoring**: Weighted letter grading (`A+` through `F`) and numerical score (0–100) with automatic generation of remediable findings for missing or weak headers.
- **Mandatory SSRF Protection**:
  - Pre-connection DNS validation resolving hostnames to IP addresses before making socket requests.
  - Unconditional blocking of loopback addresses (`127.0.0.1`, `::1`), private RFC1918 networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local addresses, multicast, and cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
  - Standard web port restriction (strictly ports 80 and 443).
  - DNS rebinding prevention via custom synchronous transport pinning the validated IP address to the outbound connection socket.
  - Safe translation and inspection of IPv4-mapped / NAT64 IPv6 addresses (`64:ff9b::/96`).

### 4. File Integrity Monitor (FIM)
- **Cryptographic Baseline**: Computes SHA-256 cryptographic hashes and metadata for files within authorized directories.
- **Tamper Detection**: Detects file alterations (hash mismatch), newly created unauthorized files, and deleted critical files.
- **Automated Correlation**: Generates high-severity security findings with cryptographic hash evidence upon detecting unexpected file tampering.
- **Filesystem Boundaries**: Path containment strictly enforced within configured `FIM_ALLOWED_ROOTS`. Blocks path traversal sequences (`../`), directory escapes, and symbolic link redirection. File size limits prevent denial-of-service via memory exhaustion.

### 5. Defensive Log Analyzer
- **Multi-Format Ingestion**: Ingests and normalizes authentication logs, web server access logs (Nginx/Apache), and system authorization events.
- **Threat Detection Engine**:
  - Brute-force authentication detection using sliding-window correlation (triggers High finding when failures exceed configurable threshold within time window).
  - Web application probing detection (SQL injection strings, directory traversal patterns, script scanning).
  - Access denial and authorization failure correlation.
- **Correlated Findings**: Generates findings attributed to specific source IP addresses with raw log line excerpts attached as verifiable evidence.
- **Containment & Resource Limits**: Enforces path containment within `LOG_ALLOWED_ROOTS`, maximum file size caps (`LOG_MAX_FILE_SIZE_BYTES`), line length caps (`LOG_MAX_LINE_LENGTH`), and maximum processed lines per run (`LOG_MAX_LINES_PER_RUN`).

### 6. Authorized Network Scanner
- **Defensive TCP Connect Checks**: Performs standard, non-destructive three-way TCP handshake probes without raw sockets, SYN floods, or evasion techniques.
- **Target Policy Enforcement**: Probes are restricted strictly to explicitly authorized targets configured in `SCAN_ALLOWED_TARGETS`. Unauthorized targets and public IP scans without prior whitelisting return HTTP 403 Forbidden.
- **Operational Safety Controls**:
  - Mandatory operator confirmation checkbox required for each scan request.
  - Unconditional blocking of cloud metadata (`169.254.169.254`), multicast, and broadcast addresses.
  - Port count bounding (maximum 100 ports per scan) and individual socket connect timeouts.
  - Sliding-window rate limiting per operator.
- **Selective Findings Generation**: Automatically creates security findings for confirmed insecure cleartext protocols (Telnet on port 23, cleartext FTP on port 21) or exposed database interfaces, while avoiding false alarms on standard web services.

---

## Technology Stack

| Layer | Technologies & Libraries | Purpose |
| :--- | :--- | :--- |
| **Backend Framework** | Python 3.12+, FastAPI, Uvicorn | High-performance asynchronous REST API, OpenAPI schema generation |
| **Data Validation** | Pydantic v2, Pydantic Settings | Strict request/response typing, environment validation, security boundaries |
| **Database & ORM** | SQLAlchemy 2.0, Alembic, SQLite | Modern declarative ORM, migration tracking, PostgreSQL production path |
| **Authentication** | Argon2id (`argon2-cffi`), PyJWT | Cryptographic password hashing, signed JWT session management |
| **Network & HTTP** | HTTPX, HTTPCore | Asynchronous HTTP client, custom SSRF-safe synchronous socket transport |
| **Frontend Framework** | React 18, TypeScript, Vite | Single-page application, strict static typing, fast HMR build tooling |
| **Styling & UI** | Tailwind CSS, Lucide React Icons | Responsive cybersecurity dark-theme styling, accessible component icons |
| **Testing & Quality** | Pytest, Flake8, Black, ESLint | Comprehensive unit/integration testing, strict PEP 8 and TypeScript linting |

---

## Project Structure

```
CyberShield/
├── backend/
│   ├── alembic/                 # Database migrations (versions & env.py)
│   ├── app/
│   │   ├── models/              # SQLAlchemy models (User, Finding, FIM, LogEvent, Scan, Audit)
│   │   ├── routes/              # FastAPI routers (auth, findings, dashboard, headers, fim, logs, scans)
│   │   ├── schemas/             # Pydantic v2 schemas for request/response validation
│   │   ├── security/            # Security guards (hashing, JWT, SSRF, FIM paths, log paths, scan targets)
│   │   ├── services/            # Core business logic & assessment engines
│   │   ├── utils/               # Audit helpers, IP extraction, sanitization
│   │   ├── config.py            # Pydantic settings with production readiness validation
│   │   ├── database.py          # SQLAlchemy engine, session maker, transaction rollback
│   │   └── main.py              # Application entrypoint, CORS, exception handling
│   ├── tests/
│   │   └── unit/                # 116 automated unit and end-to-end integration tests
│   ├── pyproject.toml           # Tooling configurations (Black, Pytest)
│   ├── .flake8                  # PEP 8 linting rules
│   ├── requirements.txt         # Production backend dependencies
│   └── requirements-dev.txt     # Development, testing, and linting dependencies
│
├── frontend/
│   ├── src/
│   │   ├── app/                 # Root application shell and router layout
│   │   ├── components/          # Shared components (Navbar, StatusCard, DashboardPlaceholder)
│   │   ├── features/            # Feature modules:
│   │   │   ├── auth/            # LoginPage, RegisterPage, ProtectedRoute, AuthContext
│   │   │   ├── dashboard/       # DashboardOverview posture summary
│   │   │   ├── findings/        # FindingsPage registry with search, filter, and triage
│   │   │   ├── headers/         # WebSecurityHeadersPage analyzer UI
│   │   │   ├── fim/             # FileIntegrityMonitorPage baseline & verification UI
│   │   │   ├── logs/            # LogAnalyzerPage event viewer & analysis UI
│   │   │   └── scans/           # NetworkScannerPage authorized TCP scanner UI
│   │   ├── services/            # API client with token lifecycle and 401 interceptor
│   │   ├── types/               # TypeScript interfaces and data models
│   │   └── index.css            # Tailwind directives and cyber theme styling
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   └── tailwind.config.js
│
├── data/                        # Persistent database and baseline storage (.gitignore protected)
├── docs/                        # Architectural documentation:
│   └── API_SPEC.md              # Complete REST API specification (28 endpoints)
├── logs/                        # Application runtime and audit logs (.gitignore protected)
├── reports/                     # Generated assessment reports (.gitignore protected)
├── .env.example                 # Comprehensive environment configuration template
├── .gitignore                   # Multi-layer protection against secret and database leaks
├── docker-compose.yml           # Containerized multi-service definition
└── README.md
```

---

## Local Setup & Installation (Windows PowerShell)

Follow these steps to run CyberShield locally on Windows using PowerShell.

### Prerequisites
- **Python 3.11+ or 3.12+** (Verify with `python --version`)
- **Node.js 18+ and npm** (Verify with `node -v` and `npm -v`)
- **Git** (Verify with `git --version`)

---

### Step 1: Clone Repository & Configure Environment

```powershell
# Clone the repository
git clone https://github.com/yourusername/CyberShield.git
cd CyberShield

# Copy the environment configuration template
Copy-Item .env.example .env
```

Open `.env` to review the default local configuration:
- By default, `APP_ENV=development` and `DEBUG=True` allow local testing.
- For local testing, `DATABASE_URL` defaults to SQLite at `./data/cybershield.db`.
- Default authorized roots are configured for `./monitored` and `./logs`.

---

### Step 2: Backend Setup & Database Migration

Open a PowerShell terminal:

```powershell
# Navigate to backend directory
cd backend

# Create Python virtual environment
python -m venv .venv

# Activate virtual environment
.venv\Scripts\Activate.ps1

# Upgrade pip and install development dependencies
pip install --upgrade pip
pip install -r requirements-dev.txt

# Execute database migrations using Alembic
alembic upgrade head

# Start the FastAPI backend server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The backend server will start at:
- **API Base URL**: `http://127.0.0.1:8000/api/v1`
- **Interactive Swagger Docs**: `http://127.0.0.1:8000/api/v1/docs`
- **Health Check**: `http://127.0.0.1:8000/api/v1/health`

---

### Step 3: Frontend Setup & Development Server

Open a second PowerShell terminal:

```powershell
# Navigate to frontend directory
cd frontend

# Install Node dependencies
npm install

# Start Vite development server
npm run dev
```

The frontend application will be available at:
- **Web UI**: `http://localhost:5173`

---

## Environment Configuration Dictionary

The platform uses Pydantic Settings to load and strictly validate settings from `.env` or system environment variables:

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
.venv\Scripts\pytest -v
```
*Current test suite: **115 passed, 1 skipped** (Windows non-admin symlink test), 0 failures.*

### 2. Run Backend Code Linters & Formatters
```powershell
# Check code style with Black
.venv\Scripts\black --check app tests

# Run PEP 8 linter with Flake8
.venv\Scripts\flake8 app tests
```

### 3. Run Frontend Linting & Build Checks
From the `frontend/` directory:
```powershell
# ESLint validation
npm run lint

# TypeScript compilation and production bundle build
npm run build
```

---

## Screenshot Walkthrough & Portfolio Reproduction Guide

To capture authentic UI screenshots for demonstrations or GitHub portfolio documentation, perform the following walkthrough against a running local instance (`http://localhost:5173`):

### 1. Authentication & Role Showcase
1. Navigate to `http://localhost:5173`.
2. Register an Analyst account (e.g., `analyst@cybershield.local` with password `CyberShield#2026!Secure`).
3. Notice that the role selector allows `Analyst` or `Viewer`. Attempting to register as `Admin` returns a defensive error.
4. Log in to establish an authenticated session.
5. **Screenshot 1**: *Login & Registration Screen showing defensive password complexity enforcement.*

### 2. Security Posture Dashboard
1. Upon login, the application loads the **Security Dashboard**.
2. Review the aggregated posture indicators: Active Findings, Severity Breakdown, Lifecycle Metrics, and Module Quick-Launch Cards.
3. **Screenshot 2**: *Security Posture Dashboard displaying real-time metrics and severity distribution.*

### 3. Findings Registry & Triage
1. Navigate to the **Findings** tab in the navigation bar.
2. View existing findings generated across defensive engines.
3. Filter by Severity (`High`, `Medium`), Category, or lifecycle Status (`Open`, `Resolved`).
4. Click on a finding to view remediation guidance, diagnostic evidence, and CWE references.
5. As an Analyst, transition a finding's status to `Resolved`.
6. **Screenshot 3**: *Central Security Findings Registry showing multi-facet filtering and finding triage details.*

### 4. Web Security Header Analyzer
1. Navigate to the **Header Analyzer** tab.
2. Enter an authorized target URL (e.g., `https://example.com` or your authorized portfolio domain).
3. Check the mandatory operator authorization confirmation checkbox.
4. Click **Run Analysis** to view the letter grade, hardening score, and detailed evaluation for all 6 security headers.
5. Try testing an internal or loopback address (`http://127.0.0.1:8000`) to observe the active SSRF defense in action.
6. **Screenshot 4**: *Web Security Header Analyzer displaying grading scorecard and SSRF protection intercept.*

### 6. File Integrity Monitor (FIM)
1. Navigate to the **File Integrity** tab.
2. Select an authorized directory within the configured monitoring roots (`./monitored`).
3. Click **Create Baseline** to compute SHA-256 cryptographic hashes for the directory files.
4. Edit a monitored file in the directory and click **Check Integrity**.
5. Observe the detection of the modified file and the automatic generation of a correlated Security Finding.
6. **Screenshot 5**: *File Integrity Monitor showing cryptographic baseline status and tamper detection alert.*

### 7. Defensive Log Analyzer
1. Navigate to the **Log Analyzer** tab.
2. Select or provide an authorized log file path (`./logs/test.log`).
3. Click **Analyze Log** to parse events and run threat correlation.
4. Review the normalized security event table, identified event categories (Authentication, Web Probing, Access Denied), and correlated findings.
5. **Screenshot 6**: *Defensive Log Analyzer showcasing normalized security event logs and brute-force correlation.*

### 8. Authorized Network Scanner
1. Navigate to the **Network Scanner** tab.
2. The scanner automatically displays the approved target scope (`SCAN_ALLOWED_TARGETS`).
3. Enter `127.0.0.1`, select the `Common Ports` or `Custom` preset (e.g., ports `80, 443, 8000`), and check the mandatory authorization confirmation.
4. Click **Start Scan** to execute the non-destructive connect check.
5. Review the port status table showing identified open/closed ports and service mapping.
6. Try scanning an unauthorized external IP (e.g., `8.8.8.8`) to observe the policy guard blocking the probe.
7. **Screenshot 7**: *Authorized Network Scanner showing localized TCP connect diagnostics and scope containment.*

---

## Security Architecture & Defensive Boundaries

| Defensive Boundary | Threat Mitigated | Technical Implementation |
| :--- | :--- | :--- |
| **SSRF / DNS Rebinding** | Open proxy abuse, internal reconnaissance, cloud metadata exfiltration | Pre-request DNS resolution; custom synchronous HTTP transport binding validated socket IP; blocking loopback, RFC1918, link-local, multicast, and metadata addresses |
| **Filesystem Traversal** | Unauthorized file disclosure, arbitrary file overwrite | Strict canonical path resolution against `FIM_ALLOWED_ROOTS` and `LOG_ALLOWED_ROOTS`; rejection of symlink escapes and parent traversals (`../`) |
| **Network Probing Scope** | Unauthorized port scanning, network abuse | Whitelisted target matching (`SCAN_ALLOWED_TARGETS`); strict port caps (max 100); sliding window user rate limiting; standard TCP connect-only |
| **Credential Protection** | Password disclosure, hash leakage | Argon2id hashing; exclusion of sensitive fields from API schemas; recursive audit detail sanitization redacting secret keys |
| **Session Integrity** | Stale session access, token forgery | Mandatory JWT claim validation (`sub`, `exp`, `iat`); event-driven frontend logout on 401; sessionStorage lifecycle management |
| **Information Disclosure** | Stack trace & SQL schema reconnaissance | Global exception handler sanitizing unhandled errors in non-debug mode; server-side error logging with client-safe generic responses |

---

## Factual Security Posture & Known Limitations

CyberShield is engineered for defensive monitoring, assessment, and compliance workflows. To maintain transparency, the following technical limitations apply to the current architecture:

1. **Local Concurrency & SQLite**:
   - For local development and demonstration, CyberShield defaults to SQLite. Under high concurrent write loads (e.g., dozens of simultaneous scan runs or baselines), SQLite database file locks may occur.
   - *Production Path*: The codebase uses SQLAlchemy 2.0 with Alembic migrations and is designed for zero-code configuration to PostgreSQL by updating `DATABASE_URL`.
2. **Reverse Proxy & TLS Termination**:
   - The application does not natively implement HTTPS/TLS certificates inside Uvicorn. For production deployments, CyberShield must be placed behind a reverse proxy (Nginx, Traefik, or Caddy) handling TLS termination and HSTS enforcement.
3. **Connect-Only Network Diagnostics**:
   - The Network Scanner intentionally uses standard OS-level TCP connect calls (`socket.connect_ex`). It does not perform SYN stealth scans, OS fingerprinting, banner grabbing, or vulnerability fuzzing by defensive design.
4. **Local Filesystem FIM Scope**:
   - The FIM engine operates on local directory paths accessible by the application process. It does not monitor remote agent endpoints or kernel-level filesystem events (`inotify`/`ReadDirectoryChangesW`) in real time; checks are executed on demand or via scheduled triggers.
5. **Windows Symlink Test Privilege**:
   - Creating symbolic links on Windows requires Developer Mode or elevated Administrator privileges. In non-elevated developer shells, the symlink escape test (`test_logs_symlink_escape_rejected`) is gracefully skipped while all path canonicalization checks pass.
