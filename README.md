# CyberShield — Defensive Cybersecurity Monitoring & Assessment Platform

CyberShield is an enterprise-grade, web-based defensive cybersecurity monitoring and security assessment platform. It is engineered to perform non-destructive diagnostics, integrity verification, log analysis, and posture management exclusively for systems, networks, files, and domains that the operator owns or has explicit, documented authorization to assess.

---

> [!CAUTION]
> **DEFENSIVE SECURITY DISCLAIMER & CODE OF CONDUCT**  
> CyberShield is strictly a **defensive security tool**. It does **NOT** contain, support, or permit:
> - Malware, ransomware, or exploit delivery
> - Credential theft, harvesting, or stuffing
> - Brute-force password cracking or keylogging
> - Unauthorized network access, port flooding, or stealth evasion
> - Data exfiltration or destructive operations  
>
> All diagnostic scans, integrity checks, and analyses must only operate on explicitly authorized targets.

---

## Current Development Status

- **Current Phase**: **Phase 1 — Project Foundation & Tooling Setup** ✅
- **Phase Goal**: Establish a robust, modular full-stack development foundation with FastAPI, React, TypeScript, Tailwind CSS, testing suites, and dev tooling before domain engines are constructed.

---

## Technology Stack

- **Backend**: Python 3.12+, FastAPI, Uvicorn (ASGI), Pydantic v2 & Pydantic Settings
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons
- **Database (Target Architecture)**: SQLAlchemy 2.0 ORM with SQLite for frictionless local development and zero-code migration path to PostgreSQL for production
- **Code Quality & Testing**: Pytest, HTTPX, Black, Flake8, ESLint, Prettier

---

## Project Structure

```
CyberShield/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI entrypoint, health endpoint, CORS
│   │   └── config.py            # Pydantic Settings & environment parsing
│   ├── tests/
│   │   └── unit/
│   │       └── test_health.py   # Health endpoint unit tests
│   ├── pyproject.toml           # Black and Pytest configuration
│   ├── .flake8                  # Flake8 linting rules
│   ├── requirements.txt         # Production backend dependencies
│   └── requirements-dev.txt     # Test & linting dependencies
│
├── frontend/
│   ├── src/
│   │   ├── app/                 # Application shell & root layout
│   │   ├── components/          # Reusable UI components (Navbar, StatusCard, etc.)
│   │   ├── services/            # API client calling /api/v1/health
│   │   ├── types/               # TypeScript interfaces
│   │   └── index.css            # Tailwind directives & cyber styling
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   └── tailwind.config.js
│
├── data/                        # Persistent database and baseline storage
├── reports/                     # Generated PDF and JSON reports
├── logs/                        # Application runtime and audit logs
├── docs/                        # Architectural specifications
├── .env.example                 # Environment configuration template
├── .gitignore
├── docker-compose.yml           # Local multi-container definition
└── README.md
```

---

## Local Setup & Quickstart

### Prerequisites
- Python 3.11+ or 3.12+
- Node.js 18+ and npm

### 1. Environment Configuration
Copy `.env.example` to create your local `.env`:
```bash
cp .env.example .env
```

### 2. Backend Setup
Navigate to the `backend/` directory:
```bash
cd backend
python -m venv .venv

# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
# source .venv/bin/activate

pip install -r requirements-dev.txt
```

Run the backend server:
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
The backend API and documentation will be accessible at:
- Health Endpoint: `http://127.0.0.1:8000/api/v1/health`
- Interactive API Docs (Swagger): `http://127.0.0.1:8000/api/v1/docs`

### 3. Frontend Setup
In a separate terminal, navigate to the `frontend/` directory:
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser. The frontend will immediately probe `GET /api/v1/health` and display **Backend Online** with measured round-trip latency.

---

## Testing & Quality Assurance

### Run Backend Tests
From the `backend/` directory with the virtual environment activated:
```bash
pytest
```

### Code Formatting & Linting
**Backend:**
```bash
# Check code style with Black
black --check app tests

# Run linter with Flake8
flake8 app tests
```

**Frontend:**
```bash
cd frontend
npm run lint
npm run build
```

---

## Docker Quickstart (Optional)

To start both services using Docker Compose:
```bash
docker compose up --build
```
- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:8000`

---

## Next Steps

Following approval of Phase 1, the project will transition into **Phase 2 — Database Layer, ORM Models & Migrations** to implement the SQLAlchemy 2.0 schema and Alembic migrations.
