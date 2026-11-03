# Passme — Security Operations & Role-Based Access Control

Passme is a local Flask + SQLite web application that demonstrates secure authentication, flat role-based access control (RBAC), password hashing, audit events, absolute session timeout controls (5, 15, or 30 minutes), and a security-finding workflow. The UI uses a dark blue security-operations theme with live audit-feed refresh.

## Included files

- `app.py` — Flask routes, SQLite schema, authentication, RBAC, audit logging, lockout controls, settings, CSV export, and Security Centre updates.
- `templates/` — login, overview dashboard, users, roles and permissions, audit logs, Security Centre, settings, and error pages.
- `static/css/style.css` — responsive dark dashboard styling.
- `requirements.txt` — Python dependencies.
- `tests/test_app.py` — integration tests for login, finding updates, lockout, password hashing, audit/security feeds, suspicious URL probes, repeated 404s, and CSRF protection.
- `RUN_PASSME.bat` — convenient Windows setup and run script.

## Requirements

- Python 3.10 or newer
- Internet access during first setup to download Flask and bcrypt
- Windows PowerShell or Command Prompt (other operating systems can run the Python commands directly)

## Run on Windows

1. Extract this folder to a location you can write to.
2. Open PowerShell in the `passme` folder.
3. Run these commands:

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
```

You can instead double-click `RUN_PASSME.bat` to create the virtual environment, install requirements, and start the app automatically. On the first run, Passme creates `passme.db` in this folder. No separate initialization command is required because `app.py` calls `init_db()` on startup.

Then visit **http://127.0.0.1:5000** in your browser.

If the PowerShell activation policy prevents activating the virtual environment, invoke it directly instead:

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe app.py
```

## Local administrator accounts

Both local administrator accounts use the same password:

- Username: `passme@gursimran` — account name: Gursimran
- Username: `passme@parth` — account name: Parth
- Password for both: `12345678passme`

The credentials are intentionally not displayed on the login page. On startup, Passme ensures both accounts exist, sets their role to Administrator, and removes the former sample accounts from earlier project versions. The shared password is for this local coursework demo only; use unique, stronger passwords before deployment or sharing the application.

## Functionality

### Authentication and passwords

- Passwords are stored as salted bcrypt hashes, never as plain text.
- Successful and failed sign-in attempts are added to the audit log.
- Successful sign-in clears the failed-attempt counter for that email.

### Failed-login protection

When enabled in **Settings**, five failed attempts for the same email within a 15-minute window trigger a temporary 15-minute lockout. The account's failed attempts and lockout events are audited. This is a basic educational protection; a deployed production system should combine per-account controls with IP/network rate limiting, monitoring, and account recovery.

### Role-based access control

The application defines four roles: Administrator, Security Analyst, Auditor, and Standard User. Authorization is checked on the server, not just by hiding navigation links. Use **Roles & Permissions** to inspect the configured permissions and try the permission decision tester.

### Audit logs and live feed

Audit events are stored in SQLite. **Audit Logs** polls an authenticated endpoint every eight seconds while the live feed is enabled in Settings. Turning off the live-feed option pauses automatic table updates; it does not delete or stop storing audit records. Eligible roles can export events as CSV.

### Security Centre and automatic request detections

The Security Centre includes an authenticated feed that refreshes every five seconds while **Real-time audit** is enabled in Settings. It creates records from actual requests and authentication/access events that reach this Passme instance; it does not generate random events. Detectors include:

- Repeated failed sign-ins, existing account lockouts, and possible password-spraying patterns across account identifiers.
- High-confidence URL/form indicators of path traversal or sensitive-file requests, SQL-injection patterns, XSS patterns, and command-injection patterns. Suspicious requests matched by these signatures are rejected with HTTP 400.
- Common admin/configuration path probes and User-Agent strings associated with common security-scanner tools; identified scanner User-Agents are rejected with HTTP 403.
- CSRF failures, route permission denials, and repeated unmatched URLs (404s); groups of repeated 404s are elevated to a medium-severity path-probing signal.

Repeated detections are grouped by a fingerprint and show an occurrence count. Feed timestamps and source address are based on what Flask sees; behind a reverse proxy, configure trusted-proxy handling before relying on client IP attribution. The filter inspects URL and ordinary form fields but does not inspect or store password/secret/token fields. These are lightweight defensive indicators, not a substitute for a WAF, external network monitoring, rate limiting by IP, or professional penetration testing. The local development server binds to `127.0.0.1`, so remote internet attacks cannot reach it in the default configuration. The feed only reports requests that actually reach the deployed app; it is not an internet-wide attack map.

Each tracked finding has a status menu with **Open**, **Pending**, **In Progress**, and **Resolved**. Select a new state and click **Save status**. Status changes are reversible, and each change is written to the audit trail. The initial findings are illustrative coursework records, not output from a live vulnerability scanner.

### Session and request protection

- Session cookie uses `HttpOnly` and `SameSite=Lax`.
- Configurable absolute session lifetime is 5, 15, or 30 minutes.
- State-changing forms require a session CSRF token.
- Server-side permission checks protect routes and CSV export.

## Run automated tests

Install dependencies first. From the `passme` folder, run:

```powershell
python -m unittest discover -s tests -v
```

The test suite creates a temporary SQLite database and checks key features without changing the normal `passme.db` file.

### Verify Security Centre detections locally

For a safe local check, start Passme and open Security Centre in an Administrator account, then visit these URLs in the same browser:

- `http://127.0.0.1:5000/.env` should be rejected with HTTP 400 and create a Critical sensitive-file probe event.
- `http://127.0.0.1:5000/?q=%27%20OR%201%3D1` should be rejected as a SQL-injection pattern.
- Submit an incorrect password five times for the same account identifier to verify that the existing temporary lockout and a High authentication detection are recorded.
- Visit eight different made-up URLs, such as `/missing-check-1` through `/missing-check-8`, to verify that repeated 404s are grouped and elevated to a path-probing signal.

These checks create records in the local database and may affect the failed-login lockout for the test account. Use a test account if you do not want to lock your administrator account. Do not expose the local development server to the public internet to try to generate attack traffic.

## Troubleshooting

- **`ModuleNotFoundError: No module named 'flask'` or `bcrypt`:** install requirements with the same interpreter used to start the app. Example: `C:\Python310\python.exe -m pip install -r requirements.txt`.
- **Port 5000 is already in use:** stop the other local Flask process before starting Passme again.
- **Login credentials no longer work:** on startup the application ensures both named administrator accounts and their configured local-demo password. Confirm you entered `passme@gursimran` or `passme@parth` as the username and used `12345678passme`. Back up `passme.db` before making manual database changes.
- **Icons or font look different offline:** Font Awesome and Inter are loaded from external CDNs; the core application can still run without them, but some decorative styling may not load.

## Important limitations

This project is an educational local MVP, not a production identity provider. Before deployment, use HTTPS, a stable high-entropy secret key, secure operational configuration, broader rate limiting, stronger audit-log tamper protection, backups, and a security review. Multi-factor authentication and attribute-based access control (ABAC) are not implemented. The security findings are seeded demo records and do not represent a real vulnerability scan.

## Project / assessment evidence

This source code covers the core technical scope of the proposal: authentication, bcrypt hashing, flat RBAC, local SQLite storage, permission decisions, auditing, session timeout, and user documentation. Add your own verified screenshots, recorded test results, public Git repository URL, Scrum/sprint evidence, references, and presentation to the assessment submission. Only report tests as passed after you run them yourself.

## Overview dashboard telemetry

The Overview page now includes an application security posture score and a 24-hour hourly activity graph. Both are calculated from the local SQLite database and current application settings: the graph groups stored audit events by hour and separates granted/successful from denied/failed outcomes. The posture score checks bcrypt password-hash formats, the supported session-timeout setting, failed-login protection, and audit-feed configuration, then applies a penalty for unresolved critical findings. It is an application-configuration indicator only; it is not a host malware scan or a full vulnerability assessment. Empty hours are shown as zero, and no demo activity is fabricated.
