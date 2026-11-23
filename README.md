# CipherGuard: Intelligent Hybrid Encryption & Data Leak Prevention Platform

CipherGuard is a cutting-edge, professional full-stack cybersecurity web application designed to secure sensitive data using a hybrid cryptosystem and identify potential data breaches through an intelligent Data Leak Prevention (DLP) engine.

---

## 🛡️ Platform Features

1. **Intelligent Hybrid Cryptosystem**:
   - High-speed symmetric encryption (AES-GCM / ChaCha20-Poly1305) for large files and data fields.
   - Secure asymmetric key exchange (RSA-OAEP / ECC) for key distribution.
   - Robust key derivation functions (PBKDF2, Argon2) and hashing (bcrypt, SHA-256).

2. **AI-Powered Data Leak Prevention (DLP)**:
   - Real-time text scanning and document classifying using scikit-learn models.
   - PII (Personally Identifiable Information), credentials, and intellectual property detection.
   - Automated risk scoring and audit logs of suspected data transfer attempts.

3. **Secure Document & Vault Management**:
   - Secure upload, encryption, storage, and decryption workflows.
   - Encrypted QR code generation for secure mobile file access sharing.
   - Fine-grained access control with MySQL back-end validation.

4. **Interactive Security Analytics**:
   - Visual dashboard illustrating encryption usage stats, DLP violations, threat metrics, and audit timelines.

---

## 🏗️ System Architecture

CipherGuard follows a clean **MVC (Model-View-Controller)** pattern:

```mermaid
graph TD
    subgraph Frontend [React.js SPA with Vite]
        View[UI Views / Pages] --> |Actions / Service Calls| Controller_FE[React Services / Axios]
    end
    
    subgraph Backend [Flask REST API]
        Controller_FE --> |HTTP Requests| Routes[Flask Blueprints]
        Routes --> Controllers[Flask Controllers]
        Controllers --> Models[SQLAlchemy Models]
        Models --> DB[(MySQL Database)]
        
        Controllers --> |Process Crypto| CryptoEngine[Hybrid Encryption Service]
        Controllers --> |Classify Data| AIEngine[AI DLP Service]
    end
```

---

## 📂 Directory Layout

```
Cipher Guard/
├── backend/                             # Python Flask REST API
│   ├── app/
│   │   ├── AI/                          # ML models and DLP pipelines
│   │   ├── config/                      # Flask configuration & environment loader
│   │   ├── controllers/                 # MVC Controllers handling business logic
│   │   ├── database/                    # Connection setup and SQLAlchemy engines
│   │   ├── encryption/                  # Hybrid cryptographic core
│   │   ├── models/                      # SQLAlchemy database schemas
│   │   ├── routes/                      # API endpoint routing declarations
│   │   ├── services/                    # Background processes and third-party wrappers
│   │   ├── utils/                       # Response helpers, input validators, decorators
│   │   └── __init__.py                  # Application Factory init
│   ├── requirements.txt                 # Backend dependency list
│   └── run.py                           # Application entry-point script
│
├── frontend/                            # React.js SPA (Vite + Tailwind CSS)
│   ├── public/                          # Static assets and public documents
│   ├── src/
│   │   ├── assets/                      # Stylesheets, global images, fonts
│   │   ├── components/                  # Reusable UI widgets and layout blocks
│   │   ├── layout/                      # Template wrappers (Sidebar, Dashboard view)
│   │   ├── pages/                       # Target views mapping router paths
│   │   ├── services/                    # API client logic (Axios calls)
│   │   ├── App.jsx                      # App router mapping and theme wrappers
│   │   ├── main.jsx                     # DOM mount point
│   │   └── index.css                    # Tailwind imports & baseline variables
│   ├── package.json                     # Frontend npm manifest
│   ├── tailwind.config.js               # Tailwind styling definitions
│   ├── postcss.config.js                # Stylesheet compilation config
│   └── vite.config.js                   # Vite tooling configuration
│
└── README.md                            # Documentation landing page
```

---

## 🚀 Running CipherGuard Locally

### 1. Database Setup
CipherGuard supports both MySQL 8.x (production recommendation) and local SQLite (instant zero-configuration development).

#### Option A: MySQL 8.x Setup (Recommended)
1. Ensure MySQL Server is running on your machine (default port `3306`).
2. Execute the schema script using your mysql client to initialize the tables:
   ```bash
   mysql -u root -p < backend/app/database/schema.sql
   ```
3. Update `.env` inside the `backend` or root folder with your database connection URI:
   ```env
   DATABASE_URL=mysql+pymysql://<user>:<password>@localhost:3306/cipherguard
   ```

#### Option B: SQLite Quickstart (Zero Configuration)
If no MySQL instance is configured, CipherGuard automatically defaults to a local SQLite database:
```env
DATABASE_URL=sqlite:///cipherguard.db
```
Tables will automatically be created in `backend/instance/cipherguard.db` upon initial application launch.

---

### 2. Backend Local Startup (Python + Flask)
1. Open a terminal and navigate to the `backend/` directory:
   ```bash
   cd backend
   ```
2. Create and activate a Python virtual environment:
   ```bash
   # On Windows (PowerShell / CMD)
   python -m venv venv
   .\venv\Scripts\activate

   # On macOS / Linux
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Set up the local environment configuration:
   ```bash
   cp .env.example .env     # On Windows CMD/PowerShell: copy .env.example .env
   ```
5. Launch the Flask API server:
   ```bash
   python run.py
   ```
   *The backend REST API will start listening at `http://localhost:5000` (API endpoint prefix: `/api`).*

---

### 3. Frontend Local Startup (React + Vite)
1. Open a second terminal and navigate to the `frontend/` directory:
   ```bash
   cd frontend
   ```
2. Install npm dependencies:
   ```bash
   npm install
   ```
3. Start the Vite development server:
   ```bash
   npm run dev
   ```
4. Open your browser and navigate to:
   ```
   http://localhost:3000
   ```
   *Vite dev server is pre-configured to proxy all `/api/*` calls directly to `http://localhost:5000`.*

---

## 🌐 Production Deployment Configuration

### 1. Build Commands
#### Frontend SPA Build
Vite compiles the frontend into static HTML, JS, and CSS chunks inside the `dist/` directory. Run the build command inside the `frontend/` directory:
```bash
cd frontend
npm run build
```
The output files in `frontend/dist/` should be hosted using a high-performance web server like Nginx, serving `index.html` for all client-side router fallbacks.

#### Backend WSGI Production Startup
Do **not** use the built-in Flask development server in production. Run the backend using a WSGI container like `gunicorn`:
```bash
cd backend
gunicorn -w 4 -b 127.0.0.1:5000 "run:app"
```

---

### 2. Environment Variables Specification
Configure these variables inside your production environment or server `.env` file (refer to [`.env.example`](file:///c:/Projects/Cipher%20Guard/.env.example)):

| Variable | Description | Production Requirement |
| :--- | :--- | :--- |
| `SECRET_KEY` | Flask session cookie signature key | Must be a cryptographically secure random string. **Do not use default.** |
| `JWT_SECRET` | Token signature key for authentications | Must be a secure key. Startup check halts boot if default is detected. |
| `DATABASE_URL` | Production database connection URI | MySQL connection string (e.g. `mysql+pymysql://user:pass@host:3306/db`). |
| `SHARE_BASE_URL` | Baseline URL for secure sharing links | Production domain url (e.g. `https://cipherguard.company.com`). |
| `FLASK_ENV` | Application environment state | Set to `production`. |
| `FLASK_DEBUG` | Flask stack trace debug mode | Must be set to `False`. |

---

### 3. Production Database Hardening
- **Schema Initialization**: Execute [`schema.sql`](file:///c:/Projects/Cipher%20Guard/backend/app/database/schema.sql) in your production database instance.
- **Indices**: The schema defines key performance indexes:
  - `idx_email` on `Users(email)`
  - `idx_owner` on `Files(owner_id)`
  - `idx_file_user` on `EncryptionKeys(file_id, user_id)`
  - `idx_sharing` on `FileSharing(owner_id)`
  - `idx_user_activity` on `ActivityLogs(user_id)`
- **Connection Pools**: Configure connection pools on the database server to handle expected concurrent loads, enforcing a maximum idle timeout (e.g., 300 seconds) to reclaim inactive sockets.

---

### 4. Production Security Hardening Checklist
- [ ] **No Secrets in Source Control**: Ensure `.env` is listed in `.gitignore` and never committed.
- [ ] **Disable Debug Modes**: Confirm `FLASK_DEBUG=False` in environment settings to prevent stack trace leaks.
- [ ] **Restricted CORS**: Enforce CORS rules in Flask so that only authorized origins (your frontend deployment domain) can communicate with the backend.
- [ ] **Secure Cookies**: If session cookies are used, configure `SESSION_COOKIE_SECURE=True` and `SESSION_COOKIE_HTTPONLY=True`.
- [ ] **Enforced HTTPS**: Terminate SSL at Nginx or your load balancer and redirect all traffic from HTTP port 80 to HTTPS port 443.

---

## 🔒 Cryptographic Specifications

CipherGuard implements a zero-trust, mathematically rigorous hybrid cryptosystem that couples the execution performance of symmetric ciphers with the secure key-distribution of asymmetric envelopes.

---

### 1. Architectural Cryptographic Workflow

```mermaid
graph TD
    subgraph Encryption Stage [Encryption Phase]
        File[Original File Payload] -->|AES-256-GCM| EncData[Encrypted Ciphertext Data]
        DEK[Random 256-bit AES DEK] -->|Symmetric Cipher Key| File
        DEK -->|RSA-2048-OAEP Wrap| EncDEK[Wrapped Encrypted DEK]
        PubKey[User RSA Public Key] -->|Key Encryption Key KEK| DEK
    end
    
    subgraph Encrypted Envelope [Storage Envelope]
        EncDEK --> Metadata[(Database Records)]
        EncData --> DiskStorage[(Disk Vault Storage)]
    end
    
    subgraph Decryption Stage [Decryption Phase]
        DiskStorage --> DecData[Unpacked Ciphertext]
        Metadata --> DecDEK[Wrapped DEK]
        DecDEK -->|RSA-2048-OAEP Unwrap| RawDEK[Decrypted DEK]
        PrivKey[User RSA Private Key] -->|Decryption KEK| DecDEK
        DecData -->|AES-256-GCM Decrypt + GCM Tag Verify| DecryptedFile[Original File Recovered]
        RawDEK -->|Decryption Key| DecData
    end
```

---

### 2. Standard Algorithms & Constants Enforced
The platform utilizes the following centralised parameters (defined in [`constants.py`](file:///c:/Projects/Cipher%20Guard/backend/app/encryption/constants.py)):
- **Symmetric Encryption**: 256-bit AES-GCM (`AES_KEY_SIZE_BITS = 256`).
- **Nonces/IV**: Unique, cryptographically secure 12-byte initialization vectors (`GCM_NONCE_SIZE_BYTES = 12`) generated via `os.urandom()` on every operation. **No nonce reuse is permitted.**
- **Galois Integrity Tag**: 16-byte authentication tags (`GCM_TAG_SIZE_BYTES = 16`) validated strictly during decryption to prevent bit-flipping and tampering attacks.
- **Asymmetric Envelope**: 2048-bit RSA keys (`RSA_KEY_SIZE_BITS = 2048`) with Optimal Asymmetric Encryption Padding (`OAEP`).
- **Cryptographic Hash**: SHA-256 hashing for both the main OAEP padding and the MGF1 Mask Generation Function (`hashes.SHA256()`).

---

### 3. Key Design Decisions

#### Why Hybrid Encryption is Used Instead of Direct RSA
1. **Payload Size Constraints**: Direct asymmetric RSA encryption cannot encrypt payloads larger than the key modulus minus padding overhead. For a 2048-bit RSA key using OAEP padding with SHA-256, the maximum encryptable payload size is only **190 bytes** (`256 bytes modulus - 2 * 32 bytes SHA-256 - 2 bytes padding overhead = 190 bytes`). Any file larger than this limit cannot be directly encrypted by RSA.
2. **Computational Performance**: Asymmetric operations are mathematically intensive (modular exponentiations), running orders of magnitude slower than symmetric block ciphers. Hybrid encryption wraps only a short, fixed-length 32-byte Data Encryption Key (DEK) with RSA, leaving the large file payload to be encrypted by high-speed hardware-accelerated AES-GCM.

#### Why RSA-OAEP is Enforced over PKCS#1 v1.5
- **Bleichenbacher Attacks**: PKCS#1 v1.5 padding is vulnerable to adaptive chosen-ciphertext attacks (Bleichenbacher oracle attacks). By monitoring variations in server decryption error responses, an adversary can incrementally reconstruct the wrapped plaintext payload.
- **IND-CCA2 Security**: RSA-OAEP is mathematically proven to be secure against adaptive chosen-ciphertext attacks (IND-CCA2). It utilizes a Feistel network to randomize the plaintext envelope prior to modular exponentiation, ensuring decryption checks fail uniformly and securely without leaking side-channel data.
- **Zero-Knowledge Isolation**: RSA private keys are encrypted on the database at rest under the server's master key via AES-256-GCM. Decrypted downloads of Secret files strictly require the user's private key PEM, ensuring zero-knowledge key isolation. Master keys and configuration secrets are configured solely through environment configurations and never exposed to the client.

---

## 🔑 Administrative Authentication & RBAC

CipherGuard enforces a secure Role-Based Access Control (RBAC) boundary between normal operators and system administrators.

### Access Levels Comparison

| Feature / Resource | Normal User (`role = 'user'`) | Admin User (`role = 'admin'`) |
| :--- | :---: | :---: |
| Normal User Login | ✅ | ✅ |
| Admin Command Login | ❌ | ✅ |
| Personal File Vault & Encryption | ✅ | ✅ |
| Personal Activity Logs & Profile | ✅ | ✅ |
| System-Wide Analytics Dashboard | ❌ | ✅ |
| Compliance Security Reports | ❌ | ✅ |
| Global System Activity Logs | ❌ | ✅ |
| Security Incident Resolution | ❌ | ✅ |

### Admin Seeding / Bootstrap Procedure
The primary system administrator is provisioned idempotently during the application's initialization context.

1. Configure variables in your `.env` configuration file:
   ```env
   ADMIN_EMAIL=admin@cipherguard.io
   ADMIN_PASSWORD=Configure_Secure_Passphrase_123!
   ```
2. Start the Flask backend. The startup script checks if any account with `role = 'admin'` exists. If not, it creates a new administrator with a bcrypt-hashed password hash and a cryptographically generated 2048-bit RSA keypair.
3. If an administrator is already seeded, the bootstrap procedure terminates gracefully without modifying passwords or configuration settings.

### Security Configurations & Guardrails
- **Double-Layer Authorization**: Admin routes (e.g. `/api/admin/...`) require authentication through the `@token_required` decorator followed by validation through the `@admin_required` decorator.
- **Client-Side Menu Obfuscation**: Sidebar links for system-wide auditing and reporting are hidden for non-admin accounts.
- **Verification Boundaries**: Role checks occur entirely on the server-side, querying user properties straight from the database context instead of trusting JWT claims or client local storage objects.

---

## 🔔 Security Alert & Notification Center

CipherGuard incorporates a role-aware real-time Security Alert and Notification Center for users and administrative operators.

### Security Severity & Event Levels Enforced

| Severity | Category | Target Audience | Trigger Events |
| :---: | :--- | :---: | :--- |
| **INFO** | `SHARING` | User | Successful creation of a share link, shared file download |
| **LOW** | `SHARING` / `INTEGRITY` | User | Shared links expiring or manually revoked, file verification checks |
| **MEDIUM** | `AUTHENTICATION` / `AI_CLASSIFICATION` | User & Admin | Multiple failed login attempts, Confidential/Secret file detection |
| **HIGH** | `AUTHENTICATION` / `ENCRYPTION` | User & Admin | Account lockouts, repeated decryption failures |
| **CRITICAL** | `INTEGRITY` / `ACCOUNT_SECURITY` | User & Admin | File tampering detection, unauthorized admin API accesses |

### Notification Lifecycle & State Controls
- **Personal Center**: Users query their own unread alerts badge (`GET /api/notifications`) and dismiss them via patch queries (`PATCH /api/notifications/<id>/read`), secured against IDOR.
- **Admin Center**: Administrative accounts review global alerts (`GET /api/admin/alerts`), filters by severity/categories, and change alert status to `resolved` (`PATCH /api/admin/alerts/<id>/resolve`), which automatically records administrative audit events.
- **Deduplication Engine**: Unresolved alerts of the same type and context within a 5-minute time window are merged by the backend to prevent notification spam.



