# CyberShield REST API Specification (v1)

Base URL: `/api/v1`  
All operational and analytical endpoints require an `Authorization: Bearer <token>` header unless explicitly marked public.

---

## 1. System & Health

### 1.1 Health Check
- **Method**: `GET`
- **Path**: `/api/v1/health`
- **Authentication**: None (Public)
- **Summary**: Health Check
- **Response (`200 OK`)**:
  ```json
  {
    "status": "ok",
    "app": "CyberShield"
  }
  ```

---

## 2. Authentication & User Management

### 2.1 Register User
- **Method**: `POST`
- **Path**: `/api/v1/auth/register`
- **Authentication**: None (Public)
- **Summary**: Register a new platform user
- **Request Body (`UserRegisterRequest`)**:
  ```json
  {
    "email": "analyst@example.com",
    "password": "CyberShield#2026!Secure",
    "full_name": "Security Analyst",
    "role": "analyst"
  }
  ```
- **Rules**:
  - `role` can be `"analyst"` or `"viewer"`. Self-registration as `"admin"` is rejected with `403 Forbidden`.
  - Passwords must be 8–128 characters and contain uppercase, lowercase, digit, and special character.
- **Response (`201 Created`)**: `UserResponse`
  ```json
  {
    "id": "c8a41249-1663-490f-9031-294b2a8d11c4",
    "email": "analyst@example.com",
    "full_name": "Security Analyst",
    "role": "analyst",
    "is_active": true,
    "created_at": "2026-10-06T20:44:11.285568Z",
    "last_login_at": null
  }
  ```
- **Errors**: `403 Forbidden` (admin requested), `409 Conflict` (duplicate email), `422 Unprocessable Entity` (weak password).

### 2.2 User Login
- **Method**: `POST`
- **Path**: `/api/v1/auth/login`
- **Authentication**: None (Public)
- **Summary**: Authenticate user and obtain JWT access token
- **Request Body (`UserLoginRequest`)**:
  ```json
  {
    "email": "analyst@example.com",
    "password": "CyberShield#2026!Secure"
  }
  ```
- **Response (`200 OK`)**: `TokenResponse`
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "expires_in": 1800,
    "user": {
      "id": "c8a41249-1663-490f-9031-294b2a8d11c4",
      "email": "analyst@example.com",
      "full_name": "Security Analyst",
      "role": "analyst",
      "is_active": true,
      "created_at": "2026-10-06T20:44:11.285568Z",
      "last_login_at": "2026-10-06T20:45:00.123456Z"
    }
  }
  ```
- **Errors**: `401 Unauthorized` (generic "Invalid email or password."), `403 Forbidden` (account inactive).

### 2.3 Current User Profile
- **Method**: `GET`
- **Path**: `/api/v1/auth/me`
- **Authentication**: `Bearer <token>` (Viewer, Analyst, Admin)
- **Summary**: Get current authenticated user profile
- **Response (`200 OK`)**: `UserResponse`
- **Errors**: `401 Unauthorized` (expired, missing, or invalid token).

---

## 3. Security Dashboard

### 3.1 Aggregated Dashboard Summary
- **Method**: `GET`
- **Path**: `/api/v1/dashboard/summary`
- **Authentication**: `Bearer <token>` (Viewer, Analyst, Admin)
- **Summary**: Get aggregated security dashboard metrics and recent findings
- **Response (`200 OK`)**: `DashboardSummaryResponse`
  ```json
  {
    "total_findings": 42,
    "open_findings": 35,
    "resolved_findings": 7,
    "severity_counts": {
      "critical": 2,
      "high": 10,
      "medium": 18,
      "low": 8,
      "informational": 4
    },
    "status_counts": {
      "open": 35,
      "resolved": 7,
      "accepted": 0
    },
    "recent_findings": [ ... ]
  }
  ```

---

## 4. Security Findings Registry

### 4.1 List Security Findings
- **Method**: `GET`
- **Path**: `/api/v1/findings`
- **Authentication**: `Bearer <token>` (Viewer, Analyst, Admin)
- **Summary**: List security findings with filtering and pagination
- **Query Parameters**:
  - `page`: int (default: 1, ge: 1)
  - `size`: int (default: 20, ge: 1, le: 100)
  - `severity`: string (`critical`, `high`, `medium`, `low`, `informational`)
  - `status`: string (`open`, `resolved`, `accepted`)
  - `category`: string
  - `source_module`: string (`manual`, `header_analyzer`, `fim`, `log_analyzer`, `network_scanner`)
  - `search`: string (keyword across title, asset, description)
- **Response (`200 OK`)**: `FindingListResponse`

### 4.2 Create Security Finding
- **Method**: `POST`
- **Path**: `/api/v1/findings`
- **Authentication**: `Bearer <token>` (Analyst, Admin)
- **Summary**: Create a new security finding
- **Request Body (`FindingCreate`)**:
  ```json
  {
    "title": "Missing Strict-Transport-Security Header",
    "description": "The server does not enforce HSTS on HTTPS connections.",
    "severity": "high",
    "category": "web_security",
    "source_module": "manual",
    "affected_resource": "https://api.internal",
    "remediation": "Add Strict-Transport-Security header with max-age=31536000.",
    "evidence": "Strict-Transport-Security: missing",
    "cwe_id": "CWE-319",
    "status": "open"
  }
  ```
- **Response (`201 Created`)**: `FindingResponse`
- **Errors**: `403 Forbidden` (Viewer role).

### 4.3 Get Single Finding
- **Method**: `GET`
- **Path**: `/api/v1/findings/{finding_id}`
- **Authentication**: `Bearer <token>` (Viewer, Analyst, Admin)
- **Summary**: Retrieve single security finding details
- **Response (`200 OK`)**: `FindingResponse`
- **Errors**: `404 Not Found`.

### 4.4 Update Finding Details
- **Method**: `PATCH`
- **Path**: `/api/v1/findings/{finding_id}`
- **Authentication**: `Bearer <token>` (Analyst, Admin)
- **Summary**: Update finding details
- **Request Body (`FindingUpdate`)**: Optional fields (`title`, `description`, `severity`, `category`, `affected_resource`, `remediation`, `evidence`).
- **Response (`200 OK`)**: `FindingResponse`

### 4.5 Transition Finding Status
- **Method**: `PATCH`
- **Path**: `/api/v1/findings/{finding_id}/status`
- **Authentication**: `Bearer <token>` (Analyst, Admin)
- **Summary**: Transition finding lifecycle status
- **Request Body (`FindingStatusUpdate`)**:
  ```json
  {
    "status": "resolved"
  }
  ```
- **Response (`200 OK`)**: `FindingResponse`

### 4.6 Delete Finding
- **Method**: `DELETE`
- **Path**: `/api/v1/findings/{finding_id}`
- **Authentication**: `Bearer <token>` (Admin Only)
- **Summary**: Permanently delete a security finding
- **Response (`204 No Content`)**
- **Errors**: `403 Forbidden` (Analyst or Viewer).

---

## 5. Web Security Header Analyzer

### 5.1 Perform Header Assessment
- **Method**: `POST`
- **Path**: `/api/v1/headers/analyze`
- **Authentication**: `Bearer <token>` (Analyst, Admin)
- **Summary**: Perform authorized web security header assessment
- **Request Body (`HeaderAnalysisRequest`)**:
  ```json
  {
    "url": "https://example.com",
    "authorization_confirmed": true
  }
  ```
- **Defensive SSRF Controls**:
  - Rejects missing authorization confirmation (`400`).
  - Pre-connection DNS validation blocking loopback, private ranges, cloud metadata, multicast, and unspecified addresses (`400`).
  - Strict port limitation to standard web ports (80, 443) (`400`).
  - Sync socket binding preventing DNS rebinding TOCTOU attacks.
- **Response (`200 OK`)**: `HeaderAnalysisResponse`
  ```json
  {
    "id": "e44d32a1-...",
    "target_url": "https://example.com",
    "final_url": "https://example.com",
    "status_code": 200,
    "is_https": true,
    "redirect_count": 0,
    "grade": "B",
    "score": 75,
    "headers": [
      {
        "name": "Strict-Transport-Security",
        "status": "present",
        "value": "max-age=31536000",
        "severity": "low",
        "description": "Enforces secure HTTPS connections.",
        "recommendation": "Maintain header."
      }
    ],
    "created_findings_count": 1,
    "created_finding_ids": [ "..." ],
    "analyzed_at": "2026-10-09T10:00:00Z"
  }
  ```

### 5.2 Header Assessment History
- **Method**: `GET`
- **Path**: `/api/v1/headers/history`
- **Authentication**: `Bearer <token>` (Viewer, Analyst, Admin)
- **Summary**: Get recent web security header assessment history
- **Response (`200 OK`)**: List of historical assessments.

---

## 6. File Integrity Monitor (FIM)

### 6.1 Create Baseline
- **Method**: `POST`
- **Path**: `/api/v1/fim/baselines`
- **Authentication**: `Bearer <token>` (Analyst, Admin)
- **Summary**: Create cryptographic baseline for an authorized path
- **Request Body (`FIMBaselineRequest`)**:
  ```json
  {
    "path": "./monitored"
  }
  ```
- **Rules**: Path must reside strictly within `FIM_ALLOWED_ROOTS`. Symlink escapes and path traversals are blocked.
- **Response (`201 Created`)**: `FIMBaselineResponse`

### 6.2 Execute Integrity Check
- **Method**: `POST`
- **Path**: `/api/v1/fim/check`
- **Authentication**: `Bearer <token>` (Analyst, Admin)
- **Summary**: Execute integrity check against existing baseline
- **Request Body (`FIMCheckRequest`)**:
  ```json
  {
    "path": "./monitored"
  }
  ```
- **Response (`200 OK`)**: `FIMCheckResponse` (reports `modified_count`, `added_count`, `deleted_count`, and created finding IDs).

### 6.3 List Monitored Records
- **Method**: `GET`
- **Path**: `/api/v1/fim/records`
- **Authentication**: `Bearer <token>` (Viewer, Analyst, Admin)
- **Summary**: List paginated FIM records
- **Query Parameters**: `status`, `path`, `page`, `size`.
- **Response (`200 OK`)**: `FIMRecordListResponse`

### 6.4 FIM Posture Status
- **Method**: `GET`
- **Path**: `/api/v1/fim/status`
- **Authentication**: `Bearer <token>` (Viewer, Analyst, Admin)
- **Summary**: Get FIM status summary and monitored counts
- **Response (`200 OK`)**: `FIMStatusSummaryResponse`

### 6.5 Authorized Roots
- **Method**: `GET`
- **Path**: `/api/v1/fim/roots`
- **Authentication**: `Bearer <token>` (Viewer, Analyst, Admin)
- **Summary**: Get configured authorized monitoring roots
- **Response (`200 OK`)**: `{"allowed_roots": [ "..." ]}`

---

## 7. Defensive Log Analyzer

### 7.1 Analyze Log File
- **Method**: `POST`
- **Path**: `/api/v1/logs/analyze`
- **Authentication**: `Bearer <token>` (Analyst, Admin)
- **Summary**: Analyze an authorized log file
- **Request Body (`LogAnalysisRequest`)**:
  ```json
  {
    "path": "./logs/auth.log"
  }
  ```
- **Rules**: File must be a regular file inside `LOG_ALLOWED_ROOTS`. Maximum file size bounded by `LOG_MAX_FILE_SIZE_BYTES`. Max lines bounded by `LOG_MAX_LINES_PER_RUN`.
- **Response (`200 OK`)**: `LogAnalysisResponse`

### 7.2 List Ingested Events
- **Method**: `GET`
- **Path**: `/api/v1/logs/events`
- **Authentication**: `Bearer <token>` (Viewer, Analyst, Admin)
- **Summary**: List paginated ingested log events
- **Query Parameters**: `severity`, `category`, `source_type`, `source_file`, `search`, `page`, `size`.
- **Response (`200 OK`)**: `LogEventListResponse`

### 7.3 Get Event by ID
- **Method**: `GET`
- **Path**: `/api/v1/logs/events/{event_id}`
- **Authentication**: `Bearer <token>` (Viewer, Analyst, Admin)
- **Summary**: Get single log event by ID
- **Response (`200 OK`)**: `LogEventResponse`

### 7.4 Log Analyzer Status
- **Method**: `GET`
- **Path**: `/api/v1/logs/summary`
- **Authentication**: `Bearer <token>` (Viewer, Analyst, Admin)
- **Summary**: Get log analyzer status and event metrics
- **Response (`200 OK`)**: `LogStatusSummaryResponse`

### 7.5 Authorized Log Roots
- **Method**: `GET`
- **Path**: `/api/v1/logs/roots`
- **Authentication**: `Bearer <token>` (Viewer, Analyst, Admin)
- **Summary**: Get configured authorized log roots
- **Response (`200 OK`)**: `{"allowed_roots": [ "..." ]}`

---

## 8. Authorized Network Scanner

### 8.1 Execute Network Scan
- **Method**: `POST`
- **Path**: `/api/v1/scans`
- **Authentication**: `Bearer <token>` (Analyst, Admin)
- **Summary**: Execute an authorized TCP network scan
- **Request Body (`ScanCreateRequest`)**:
  ```json
  {
    "target": "127.0.0.1",
    "ports": [80, 443, 8000],
    "port_preset": "custom",
    "authorization_confirmed": true
  }
  ```
- **Rules**:
  - Target must reside strictly within `SCAN_ALLOWED_TARGETS`. Unauthorized targets return `403 Forbidden`.
  - Cloud metadata (`169.254.169.254`), multicast, and broadcast are unconditionally blocked (`400/403`).
  - Total ports per scan bounded by `SCAN_MAX_PORTS_PER_SCAN` (max 100) (`400`).
  - Sliding-window rate limit enforced per user (`429 Too Many Requests`).
- **Response (`201 Created`)**: `ScanResponse`

### 8.2 List Historical Scans
- **Method**: `GET`
- **Path**: `/api/v1/scans`
- **Authentication**: `Bearer <token>` (Viewer, Analyst, Admin)
- **Summary**: List paginated historical network scans
- **Query Parameters**: `page`, `size`.
- **Response (`200 OK`)**: `ScanListResponse`

### 8.3 Get Scan Details
- **Method**: `GET`
- **Path**: `/api/v1/scans/{scan_id}`
- **Authentication**: `Bearer <token>` (Viewer, Analyst, Admin)
- **Summary**: Get details of a specific scan by ID
- **Response (`200 OK`)**: `ScanResponse`

### 8.4 Network Scanner Scope & Bounds
- **Method**: `GET`
- **Path**: `/api/v1/scans/scope`
- **Authentication**: `Bearer <token>` (Viewer, Analyst, Admin)
- **Summary**: Get enforced authorized targets and operational bounds
- **Response (`200 OK`)**: `ScanScopeResponse`

### 8.5 Scanner KPI Summary
- **Method**: `GET`
- **Path**: `/api/v1/scans/summary`
- **Authentication**: `Bearer <token>` (Viewer, Analyst, Admin)
- **Summary**: Get aggregated network scanner summary KPIs
- **Response (`200 OK`)**: `ScanSummaryResponse`
