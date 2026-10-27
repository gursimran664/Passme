# 🛡️ Passme — Access Control & Security Monitoring

**Right access. Right people. Every time.**

Passme is a Flask-based web application developed as an educational cybersecurity project. It demonstrates secure authentication, Flat Role-Based Access Control (RBAC), local database storage, audit logging, and application-level security monitoring through a central dashboard.

## ✨ Features

- 🔐 **Secure Authentication** — bcrypt password hashing with unique salts.
- 👥 **User Management** — Manage user accounts and assigned roles.
- 🛡️ **Flat RBAC** — Four roles with server-side permission checks.
- 📋 **Audit Logs** — Review recorded security events and export eligible records as CSV.
- 🚨 **Security Centre** — Monitor selected suspicious requests and security findings.
- 🔒 **Session Security** — Configurable session expiry and failed-login protection.
- 🛡️ **CSRF Protection** — Validate state-changing requests using CSRF tokens.
- 📊 **Security Dashboard** — View application activity and security information.
- 🗄️ **SQLite Database** — Store application data locally.

## 🛠️ Technology Stack

Python · Flask · SQLite · bcrypt · HTML · CSS · JavaScript · Jinja

## 📂 Project Structure

```text
passme/
├── app.py
├── requirements.txt
├── passme.db
├── static/
│   └── css/
│       └── style.css
└── templates/
    ├── base.html
    ├── login.html
    ├── overview.html
    ├── users.html
    ├── roles.html
    ├── audit_logs.html
    ├── security_centre.html
    ├── settings.html
    └── error.html
```

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
cd YOUR-REPOSITORY
```

Replace the placeholders with your actual GitHub username and repository name.

### 2. Create a virtual environment

**Windows PowerShell**

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
```

**Linux or macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Run Passme

```bash
python app.py
```
The application initialises its SQLite database and required tables when started.

## Passwords to login our application
passme@gursimran
123456789passme
or passme@parth
123456789passme

## 🔐 Security

Passme demonstrates password hashing, server-side access-control checks, CSRF protection, session security, failed-login lockout, and security-event logging.

The Security Centre uses configured detection rules to identify selected suspicious requests. These detections are intended for educational purposes and do not replace a professional security assessment or a full intrusion detection system.

**Before publishing:** Remove hardcoded demo credentials from the source code, and ensure the database contains no private account or audit information. Never commit passwords, secret keys, email credentials, or other sensitive configuration to a public repository.

## ⚠️ Limitations

Passme is an educational project, not a production identity-management system. Some visual assets require an internet connection, and the application does not currently implement multi-factor authentication (MFA) or Attribute-Based Access Control (ABAC).

## 👨‍💻 Team

- **Gursimran Singh**
- **Parth**

## 🎯 Project Objective

The objective of Passme is to demonstrate practical web application security by combining authentication, role-based permissions, local data storage, audit trails, and security monitoring in one application.

---

*An educational project focused on access control and web application security.*
