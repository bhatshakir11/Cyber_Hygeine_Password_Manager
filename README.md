# 🔐 Cyber Hygiene Password Manager

A full-stack password management and cyber hygiene platform designed to help users securely manage credentials, monitor password strength, detect password reuse, and safely autofill credentials through a Chrome extension.

The project combines a **React web application**, **FastAPI backend**, and **Chrome Extension** with password-strength analysis, passkey authentication, phishing-risk detection, dashboards, notes, and security reports.

---

## 🚀 Key Features

### 🔑 Password Vault

* Store and manage website credentials.
* Add, edit, and delete saved credentials.
* Search credentials by website/domain.
* Password strength analysis using `zxcvbn`.
* Detect reused passwords.
* Generate strong password suggestions.
* View password strength directly from the dashboard.

### 📊 Cyber Hygiene Dashboard

The dashboard provides an overview of the user's password security.

It includes:

* Overall Cyber Hygiene Score
* Strong, medium, and weak password statistics
* Reused vs. unique password analysis
* Security tips and reminders
* Passkey/fingerprint management

The Cyber Hygiene Score is calculated from the strength of the stored passwords.

### 🛡️ Phishing Detection

The Chrome extension performs a local risk assessment before autofilling credentials.

It checks signals such as:

* Suspicious domains
* HTTP login pages
* Punycode domains
* Suspicious keywords
* Urgent language
* External form actions
* Suspicious iframes
* Brand/domain mismatch
* Login-page characteristics

The extension categorizes websites as:

* **Safe**
* **Suspicious**
* **Likely phishing**

High-risk websites can be prevented from receiving automatic credential autofill.

### 🔐 Passkey / Biometric Authentication

The application supports WebAuthn-based authentication using platform authenticators such as:

* Windows Hello
* Fingerprint authentication
* Device passkeys
* Other supported biometric authenticators

This provides an additional authentication layer before sensitive operations such as credential autofill.

### 🌐 Chrome Autofill Extension

The Chrome extension provides convenient credential autofill.

It can:

* Detect login forms
* Match saved credentials with domains
* Autofill usernames and passwords
* Perform phishing-risk checks
* Require biometric/passkey authentication
* Remember domains where autofill is disabled
* Synchronize authentication with the main application

The extension uses **Manifest V3**.

### 📝 Notes

Authenticated users can create and manage personal notes from the application.

> Note: In the current implementation, notes are stored in the application's database. They should not be described as end-to-end encrypted.

### 📄 Security Reports

Users can generate a PDF security report containing information such as:

* Cyber Hygiene Score
* Password strength statistics
* Reused password statistics
* Security findings
* Recommended actions
* Credential information

**Important:** The current PDF report contains stored credential values, so generated reports should be treated as sensitive files and should not be shared publicly.

---

# 🏗️ System Architecture

```text
                     ┌──────────────────────┐
                     │      User            │
                     └──────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │   React Web App       │
                    │                       │
                    │ Login / Register      │
                    │ Dashboard             │
                    │ Password Vault        │
                    │ Notes                 │
                    │ Reports               │
                    └───────────┬───────────┘
                                │
                              Axios
                                │
                    ┌───────────▼───────────┐
                    │    FastAPI Backend    │
                    │                       │
                    │ JWT Authentication    │
                    │ Password Management   │
                    │ WebAuthn              │
                    │ Dashboard APIs        │
                    │ Report Generation     │
                    └───────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │       SQLite          │
                    │       Database        │
                    └───────────────────────┘


             Chrome Extension
                    │
                    ▼
          ┌─────────────────────┐
          │ Login Page Detection│
          │ Domain Matching     │
          │ Phishing Detection  │
          │ Passkey Verification│
          │ Secure Autofill     │
          └──────────┬──────────┘
                     │
                     ▼
              FastAPI Backend
```

---

# 🛠️ Tech Stack

## Frontend

* React
* React Router
* Axios
* Tailwind CSS
* Recharts
* WebAuthn APIs
* Browser Crypto APIs

## Backend

* Python
* FastAPI
* SQLite
* bcrypt
* JWT
* WebAuthn
* Cryptography
* ReportLab
* zxcvbn

## Browser Extension

* JavaScript
* HTML
* CSS
* Chrome Extension Manifest V3
* Chrome Storage API
* Chrome Tabs API
* Chrome Scripting API
* Chrome Side Panel API

---

# 📁 Project Structure

```text
Cyber_Hygeine_Password_Manager/
│
├── cyberhygine/
│   │
│   ├── public/
│   │
│   ├── src/
│   │   ├── apiClient.js
│   │   ├── config.js
│   │   │
│   │   ├── pages/
│   │   │   ├── LoginPage.jsx
│   │   │   ├── RegisterPage.jsx
│   │   │   ├── DashboardPage.jsx
│   │   │   ├── VaultPage.jsx
│   │   │   ├── NotesPage.jsx
│   │   │   └── ReportsPage.jsx
│   │   │
│   │   └── utils/
│   │       └── webauthn.js
│   │
│   └── package.json
│
├── cyberhygine-backend/
│   │
│   ├── main.py
│   ├── requirements.txt
│   └── users.db
│
├── cyberhygine-extension/
│   │
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── popup.html
│   ├── popup.js
│   ├── sidepanel.html
│   ├── sidepanel.js
│   ├── autofill-auth.html
│   ├── autofill-auth.js
│   ├── passkey-setup.html
│   ├── passkey-setup.js
│   └── icons/
│
└── README.md
```

---

# ⚙️ Getting Started

## 1. Clone the Repository

```bash
git clone <repository-url>
cd Cyber_Hygeine_Password_Manager
```

---

# 🖥️ Frontend Setup

Navigate to the frontend directory:

```bash
cd cyberhygine
```

Install dependencies:

```bash
npm install
```

Start the React development server:

```bash
npm start
```

The frontend is configured to communicate with the backend through the API configuration in:

```text
src/config.js
```

The default development backend URL is:

```text
http://localhost:9000/api
```

---

# 🐍 Backend Setup

Open another terminal and navigate to:

```bash
cd cyberhygine-backend
```

Create a virtual environment:

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the FastAPI server:

```bash
uvicorn main:app --reload --port 9000
```

The backend will run at:

```text
http://localhost:9000
```

---

# 🌐 Chrome Extension Setup

The project includes a Chrome extension located inside:

```text
cyberhygine-extension/
```

### Installation

1. Open Google Chrome.
2. Navigate to:

```text
chrome://extensions
```

3. Enable **Developer mode**.
4. Click **Load unpacked**.
5. Select:

```text
cyberhygine-extension
```

6. The extension will appear in your Chrome extensions list.
7. Pin the extension for easier access.

---

# 🔄 How Autofill Works

The autofill process follows several security checks.

```text
User visits website
        │
        ▼
Extension detects login form
        │
        ▼
Identify current domain
        │
        ▼
Find matching credentials
        │
        ▼
Check website risk
        │
        ├──── High Risk ────► Block Autofill
        │
        ├──── Medium Risk ──► Warn User
        │
        └──── Low Risk ─────► Continue
                              │
                              ▼
                     Passkey / Biometric
                              │
                              ▼
                         Autofill
```

The extension uses domain matching to ensure credentials are associated with the correct website.

It also supports domains where the user has explicitly disabled autofill.

---

# 🧠 Password Strength Analysis

The project uses `zxcvbn` to estimate password strength.

Passwords are categorized approximately as:

```text
Score 0-1  → Weak
Score 2    → Medium
Score 3-4  → Strong
```

The system also checks for:

* Password reuse
* Password length
* Character variety
* Easily guessable patterns
* Website/username-related patterns

---

# 📊 Cyber Hygiene Score

The dashboard calculates a Cyber Hygiene Score based on password strength.

Conceptually:

```text
Cyber Hygiene Score =
Strong Passwords / Total Passwords × 100
```

For example:

```text
Total Passwords = 10
Strong Passwords = 8

Score = 8 / 10 × 100
      = 80
```

This gives users a simple way to understand the overall state of their stored passwords.

---

# 🔐 Authentication

The application supports two primary authentication mechanisms.

## 1. Password Authentication

Passwords for user accounts are hashed using:

```text
bcrypt
```

Authentication uses JWT tokens for maintaining logged-in sessions.

The frontend stores the authentication token and sends it with API requests.

---

## 2. WebAuthn / Passkeys

The application also supports WebAuthn-based authentication.

The flow is:

```text
User
 │
 ▼
Web Application
 │
 ▼
WebAuthn API
 │
 ▼
Device Authenticator
 │
 ├── Fingerprint
 ├── Windows Hello
 └── Passkey
 │
 ▼
Authentication Result
 │
 ▼
Application
```

---

# 🔌 API Endpoints

## Authentication

```text
POST /api/register
POST /api/login
```

## Credentials

```text
GET    /api/credentials
POST   /api/credentials
PUT    /api/credentials/{cred_id}
DELETE /api/credentials/{cred_id}
```

## Vault

```text
GET /api/vault
```

Optional domain filtering is supported.

## Dashboard

```text
GET /api/dashboard
```

## Notes

```text
GET  /api/notes
POST /api/notes
```

## Reports

```text
GET /api/report
```

## Passkeys

```text
/api/passkeys/*
```

The project also contains compatibility routes for fingerprint and extension-based passkey flows.

---

# 🔒 Security Features

The project implements several security-focused mechanisms:

### Account Password Hashing

User account passwords are protected using bcrypt hashing.

### JWT Authentication

Authenticated API requests use JWT-based authorization.

### WebAuthn

Passkey/biometric authentication provides an additional authentication mechanism.

### Password Strength Analysis

Passwords are evaluated using `zxcvbn`.

### Password Reuse Detection

The system identifies passwords reused across multiple stored credentials.

### Phishing Risk Detection

The browser extension evaluates multiple characteristics of a website before autofilling credentials.

### Domain-Based Credential Matching

Stored credentials are matched against the website domain to reduce accidental autofilling on unrelated websites.

### Autofill Protection

High-risk websites can be blocked from automatic credential filling.

---

# ⚙️ Environment Variables

The backend supports configuration through environment variables.

### JWT Secret

```text
JWT_SECRET
```

Used to sign JWT authentication tokens.

### WebAuthn Configuration

```text
WEBAUTHN_RP_ID
WEBAUTHN_RP_NAME
WEBAUTHN_ORIGIN
```

Example development configuration:

```text
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_NAME=Cyber Hygiene Vault
WEBAUTHN_ORIGIN=http://localhost:3000
```

For production deployment, these values should be configured for the actual domain.

---

# 🗄️ Database

The current backend implementation uses:

```text
SQLite
```

The database file is:

```text
users.db
```

The database stores application information including:

* User accounts
* Credentials
* Notes
* WebAuthn/passkey information

For production deployment, database configuration and credential protection should be reviewed and hardened before handling real user data.

---

# 📄 Report Generation

The backend generates security reports using:

```text
ReportLab
```

Reports can include:

* User security summary
* Cyber Hygiene Score
* Password strength distribution
* Reused password statistics
* Security findings
* Recommended actions
* Stored credential information

Because credential values are currently included in the generated report, reports should be treated as sensitive data.

---

# 🧪 Development

Recommended development setup:

```text
Frontend
React development server
        │
        ▼
Backend
FastAPI + Uvicorn
        │
        ▼
Database
SQLite
        │
        ▲
        │
Chrome Extension
```

Run the frontend and backend simultaneously during development.

---

# 🎯 Project Goals

The project was built to address common password-security problems faced by everyday users.

Instead of only storing passwords, the system focuses on **overall cyber hygiene** by helping users understand:

* Whether their passwords are weak
* Whether passwords are being reused
* Which credentials need attention
* Whether a website may be suspicious
* When biometric authentication should be required
* How their overall password security is changing

The Chrome extension extends these security features directly into the browser.

---

# 🚧 Future Improvements

Possible improvements for future versions include:

* End-to-end encryption for stored vault credentials
* Encrypted notes
* PostgreSQL or another production-grade database
* Stronger production CORS configuration
* Secure secret management
* Automatic security alerts
* Breached-password detection using privacy-preserving APIs
* Improved phishing detection using trained ML models
* Password expiry/reminder system
* Secure cloud synchronization
* Multi-device synchronization
* Better audit logging
* More advanced WebAuthn credential management
* Secure password sharing
* Improved report privacy controls

---

# ⚠️ Security Considerations

This project is primarily a learning and development project.

Before using it for real sensitive credentials in production, the following areas should be hardened:

* Encrypt stored vault passwords at rest.
* Use a persistent and securely managed JWT secret.
* Restrict CORS to trusted frontend origins.
* Secure database access.
* Protect generated reports.
* Add stronger session management.
* Perform a professional security audit.
* Avoid storing sensitive credentials in logs or exposed files.
* Use HTTPS in production.
* Apply secure cookie/token storage practices.
* Implement proper key management.

**Do not use the development configuration for production password storage without additional security hardening.**

---

# 📚 Technologies Learned

This project provided practical experience with:

* Full-stack web development
* React
* FastAPI
* REST APIs
* JWT authentication
* Password hashing
* WebAuthn
* Passkeys
* Browser extension development
* Chrome Manifest V3
* Phishing detection
* Password security
* SQLite
* PDF generation
* Data visualization
* Client-server architecture
* API integration
* Security-focused application design

---

# 👨‍💻 Author

**Bhat Shakir**

Computer Science Engineering Student

Interested in:

* Full-Stack Development
* Artificial Intelligence
* Cybersecurity
* Web Development
* Software Engineering

---

# ⭐ Project Purpose

The main objective of **Cyber Hygiene Password Manager** is to move beyond traditional password storage and provide users with a practical way to **understand, monitor, and improve their everyday password security**.

The combination of a password vault, cyber hygiene dashboard, phishing detection, biometric authentication, and browser autofill creates a security-focused workflow directly around the user's daily web activity.
