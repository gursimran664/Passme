
# Import standard libraries for CSV export, hashing, database access, and security.
import csv
import hashlib
import io
import os
import re
import secrets
import sqlite3
import time

# Import date/time utilities for timestamps and session expiration.
from datetime import datetime, timedelta, timezone

# Import helpers for URL decoding, decorators, context managers, and file paths.
from urllib.parse import unquote_plus
from functools import wraps
from contextlib import contextmanager
from pathlib import Path

# Import third-party libraries and Flask components.
import bcrypt
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

# Configure the application directory and SQLite database location.
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("PASSME_DB", BASE_DIR / "passme.db"))

# Initialize Flask and configure secure session-cookie defaults.
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("PASSME_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("PASSME_HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
)

# Define the roles available in the application.
ROLES = (
    "Administrator",
    "Security Analyst",
    "Auditor",
    "Standard User",
)

# Define valid security-finding statuses.
FINDING_STATUSES = (
    "Open",
    "Pending",
    "In Progress",
    "Resolved",
)

# Assign permissions to each role using a flat RBAC model.
PERMISSIONS = {
    "Administrator": {
        "view_overview",
        "manage_users",
        "view_roles",
        "view_audit",
        "export_audit",
        "manage_findings",
        "manage_settings",
    },
    "Security Analyst": {
        "view_overview",
        "view_roles",
        "view_audit",
        "manage_findings",
    },
    "Auditor": {
        "view_overview",
        "view_audit",
        "export_audit",
    },
    "Standard User": {
        "view_overview",
    },
}

# Provide initial security findings for an empty demonstration database.
FINDINGS_SEED = [
    (
        "Critical",
        "Legacy SMB exposure (MS17-010)",
        "Windows 7 lab endpoint · Ports 139/445",
        "Disable SMBv1, enable the host firewall, install MS17-010 patches, "
        "and isolate the legacy endpoint.",
        "Open",
    ),
    (
        "High",
        "Insecure direct object reference",
        "User profile endpoint · /api/users/:id",
        "Enforce server-side ownership checks and role authorization "
        "on every object request.",
        "Investigating",
    ),
    (
        "Medium",
        "Repeated authentication failures",
        "Authentication",
        "Apply rate limiting or account lockout and review repeated failures.",
        "Open",
    ),
]


# Open a database connection and safely commit or roll back transactions.
@contextmanager
def db():
    """Open a short-lived SQLite connection and close it safely."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# Return the current local date and time for audit records.
def now_text():
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


# Record authentication, authorization, and administrative actions.
def audit(actor, action, resource, result):
    with db() as conn:
        conn.execute(
            """
            INSERT INTO audit_logs
                (user_name, action, resource, event_time, result)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                actor or "Anonymous",
                action[:250],
                resource[:250],
                now_text(),
                result,
            ),
        )


# Create the required tables, indexes, default settings, and administrator accounts.
def init_db():
    with db() as conn:
        # Create tables for users, audit history, findings, and settings.
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash BLOB NOT NULL,
                role TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Active',
                created_at TEXT NOT NULL,
                last_active TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_name TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                event_time TEXT NOT NULL,
                result TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                email TEXT PRIMARY KEY COLLATE NOCASE,
                attempts INTEGER NOT NULL DEFAULT 0,
                window_started TEXT NOT NULL,
                locked_until TEXT
            );

            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                event_time TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                last_seen_epoch REAL NOT NULL,
                source_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                method TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                details TEXT NOT NULL,
                status TEXT NOT NULL,
                occurrences INTEGER NOT NULL DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_security_events_recent
                ON security_events(last_seen_epoch DESC);

            CREATE INDEX IF NOT EXISTS idx_security_events_fingerprint
                ON security_events(fingerprint, last_seen_epoch DESC);
            """
        )

        # Remove obsolete demonstration accounts from earlier versions.
        legacy_emails = ("admin@passme.local", "noah@northstar.io")
        conn.execute(
            "DELETE FROM users WHERE lower(email) IN (?, ?)",
            legacy_emails,
        )
        conn.execute(
            "DELETE FROM login_attempts WHERE lower(email) IN (?, ?)",
            legacy_emails,
        )
        conn.execute(
            "DELETE FROM audit_logs WHERE user_name IN (?, ?)",
            ("Olivia Martin", "Noah Williams"),
        )

        # Create administrator accounts only when they do not already exist.
        # Existing passwords are not reset on every application restart.
        admin_accounts = (
            ("Gursimran", "passme@gursimran", "12345678passme"),
            ("Parth", "passme@parth", "12345678passme"),
        )

        for name, email, password in admin_accounts:
            existing = conn.execute(
                "SELECT id FROM users WHERE lower(email) = lower(?)",
                (email,),
            ).fetchone()

            if existing:
                continue

            password_hash = bcrypt.hashpw(
                password.encode("utf-8"),
                bcrypt.gensalt(),
            )

            conn.execute(
                """
                INSERT INTO users
                    (name, email, password_hash, role, status,
                     created_at, last_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    email,
                    password_hash,
                    "Administrator",
                    "Active",
                    now_text(),
                    now_text(),
                ),
            )

        # Insert the demonstration findings if no findings exist.
        if conn.execute(
            "SELECT COUNT(*) FROM findings"
        ).fetchone()[0] == 0:
            conn.executemany(
                """
                INSERT INTO findings
                    (severity, title, endpoint, recommendation, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                FINDINGS_SEED,
            )

        # Normalize statuses created by older project versions.
        conn.execute(
            "UPDATE findings SET status='In Progress' "
            "WHERE status='Investigating'"
        )
        conn.execute(
            "UPDATE findings SET status='Open' "
            "WHERE status='Not Resolved'"
        )

        # Set default security options without overwriting saved preferences.
        defaults = {
            "session_timeout": "15",
            "failed_login_protection": "1",
            "real_time_audit": "1",
        }

        for key, value in defaults.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)",
                (key, value),
            )

        # Replace unsupported legacy session timeout values.
        conn.execute(
            """
            UPDATE settings
            SET value='15'
            WHERE key='session_timeout'
              AND value NOT IN ('5', '15', '30')
            """
        )


# Rank security-event severity to prevent less severe repeats from downgrading an event.
SEVERITY_ORDER = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}


# Return the peer address Flask sees without trusting forwarded headers by default.
def client_ip():
    try:
        return (request.remote_addr or "unknown")[:80]
    except RuntimeError:
        return "local"


# Save a security event and combine repeated matching events into one record.
def record_security_event(
    *,
    fingerprint,
    severity,
    category,
    title,
    method=None,
    endpoint=None,
    details="",
    status="Observed",
    dedupe_seconds=600,
):
    moment = datetime.now().astimezone()
    display_time = moment.strftime("%Y-%m-%d %H:%M:%S %Z")
    epoch = moment.timestamp()
    cutoff = epoch - dedupe_seconds

    source = client_ip()
    method = (method or request.method)[:16]
    endpoint = (endpoint or request.path or "/")[:500]
    details = (details or "")[:1000]
    fingerprint = str(fingerprint)[:250]

    with db() as conn:
        # Find a recent event with the same fingerprint.
        prior = conn.execute(
            """
            SELECT *
            FROM security_events
            WHERE fingerprint = ? AND last_seen_epoch >= ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (fingerprint, cutoff),
        ).fetchone()

        if prior:
            occurrences = int(prior["occurrences"]) + 1

            # Keep the more severe classification when combining events.
            incoming_is_more_severe = (
                SEVERITY_ORDER.get(severity, 0)
                >= SEVERITY_ORDER.get(prior["severity"], 0)
            )

            effective_severity = (
                severity if incoming_is_more_severe else prior["severity"]
            )
            effective_category = (
                category if incoming_is_more_severe else prior["category"]
            )
            effective_title = (
                title if incoming_is_more_severe else prior["title"]
            )
            effective_details = (
                details
                if incoming_is_more_severe or not prior["details"]
                else prior["details"]
            )
            effective_status = (
                status if incoming_is_more_severe else prior["status"]
            )

            conn.execute(
                """
                UPDATE security_events
                SET last_seen=?, last_seen_epoch=?, source_ip=?, severity=?,
                    category=?, title=?, method=?, endpoint=?, details=?,
                    status=?, occurrences=?
                WHERE id=?
                """,
                (
                    display_time,
                    epoch,
                    source,
                    effective_severity,
                    effective_category,
                    effective_title,
                    method,
                    endpoint,
                    effective_details,
                    effective_status,
                    occurrences,
                    prior["id"],
                ),
            )
        else:
            # Insert a new record when no recent matching event exists.
            occurrences = 1
            conn.execute(
                """
                INSERT INTO security_events
                    (fingerprint, event_time, last_seen, last_seen_epoch,
                     source_ip, severity, category, title, method,
                     endpoint, details, status, occurrences)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fingerprint,
                    display_time,
                    display_time,
                    epoch,
                    source,
                    severity,
                    category,
                    title,
                    method,
                    endpoint,
                    details,
                    status,
                    occurrences,
                ),
            )

        # Limit database growth during local testing and repeated probes.
        conn.execute(
            """
            DELETE FROM security_events
            WHERE id NOT IN (
                SELECT id
                FROM security_events
                ORDER BY id DESC
                LIMIT 5000
            )
            """
        )

    return occurrences


# Escalate an existing event without counting another occurrence.
def promote_security_event(
    fingerprint,
    *,
    severity,
    title,
    details,
    status="Rejected (404)",
):
    with db() as conn:
        row = conn.execute(
            """
            SELECT id, severity
            FROM security_events
            WHERE fingerprint=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (fingerprint,),
        ).fetchone()

        if (
            row
            and SEVERITY_ORDER.get(severity, 0)
            >= SEVERITY_ORDER.get(row["severity"], 0)
        ):
            conn.execute(
                """
                UPDATE security_events
                SET severity=?, title=?, details=?, status=?
                WHERE id=?
                """,
                (severity, title, details[:1000], status, row["id"]),
            )


# Detect common exploit patterns in URL data and non-secret form fields.
# Passwords, tokens, and CSRF fields are deliberately excluded from inspection.
REQUEST_SIGNATURES = [
    (
        "Critical",
        "Web exploit probe",
        "Path traversal / sensitive-file probe",
        re.compile(
            r"(?:\.\./|\.\.\\|%2e%2e|/etc/passwd|/proc/self|"
            r"/windows/win\.ini|/\.env(?:/|\?|\s|$)|"
            r"/\.git(?:/|\?|\s|$))",
            re.I,
        ),
        "traversal",
    ),
    (
        "High",
        "Web exploit probe",
        "SQL injection pattern detected",
        re.compile(
            r"(?:union(?:%20|\s|\+)+select|"
            r"(?:'|%27)\s*(?:or|and)\s*(?:'|\d|%27)|"
            r"sleep\s*\(|benchmark\s*\(|information_schema|"
            r"waitfor\s+delay)",
            re.I,
        ),
        "sql-injection",
    ),
    (
        "High",
        "Web exploit probe",
        "Cross-site scripting (XSS) pattern detected",
        re.compile(
            r"(?:<\s*script|%3c\s*script|javascript\s*:|"
            r"onerror\s*=|<\s*iframe)",
            re.I,
        ),
        "xss",
    ),
    (
        "High",
        "Web exploit probe",
        "Command-injection pattern detected",
        re.compile(
            r"(?:(?:;|\||&&)\s*(?:cat|id|whoami|wget|curl|bash|sh|nc)\b|"
            r"\$\([^)]{1,100}\))",
            re.I,
        ),
        "command-injection",
    ),
    (
        "Medium",
        "Reconnaissance",
        "Common admin/configuration path probe",
        re.compile(
            r"(?:^|/)(?:wp-admin|wp-login\.php|phpmyadmin|"
            r"adminer|server-status)(?:/|\?|\s|$)",
            re.I,
        ),
        "path-probe",
    ),
]

# Identify common automated reconnaissance tools from request User-Agent headers.
SCANNER_USER_AGENT = re.compile(
    r"\b(?:sqlmap|nikto|nuclei|gobuster|dirbuster|zgrab|masscan|wpscan)\b",
    re.I,
)


# Inspect incoming requests and reject requests matching configured signatures.
def detect_suspicious_request():
    if request.endpoint == "static":
        return None

    raw_uri = (
        request.environ.get("RAW_URI")
        or request.environ.get("REQUEST_URI")
        or ""
    )
    query = request.query_string.decode("utf-8", errors="replace")

    # Inspect ordinary form values without collecting secret fields.
    safe_form_values = []

    for field_name, field_value in request.form.items():
        lowered_name = field_name.lower()

        if any(
            secret_word in lowered_name
            for secret_word in (
                "password",
                "passwd",
                "secret",
                "token",
                "csrf",
            )
        ):
            continue

        safe_form_values.append(field_value[:1000])

    inspected = unquote_plus(
        f"{request.path} {request.path}?{query} "
        f"{raw_uri} {' '.join(safe_form_values)}"
    ).lower()

    user_agent = request.headers.get("User-Agent", "")

    # Find the first matching exploit signature.
    match = next(
        (
            item
            for item in REQUEST_SIGNATURES
            if item[3].search(inspected)
        ),
        None,
    )
    scanner_match = SCANNER_USER_AGENT.search(user_agent)

    if match:
        severity, category, title, _pattern, key = match
        fingerprint = f"signature:{client_ip()}:{key}"

        record_security_event(
            fingerprint=fingerprint,
            severity=severity,
            category=category,
            title=title,
            details=(
                f"The requested URL matched the {key} detection rule. "
                "Passme rejected the request with HTTP 400."
            ),
            status="Blocked (400)",
            dedupe_seconds=600,
        )

        return (
            make_response(
                render_template(
                    "error.html",
                    code=400,
                    message=(
                        "This request was rejected by Passme's "
                        "suspicious-request protection."
                    ),
                ),
                400,
            )
        )

    # Record requests identified as originating from common scanner tools.
    if scanner_match:
        scanner = scanner_match.group(0).lower()

        record_security_event(
            fingerprint=f"scanner:{client_ip()}:{scanner}",
            severity="Medium",
            category="Reconnaissance",
            title="Automated scanner identified",
            details=(
                f"The User-Agent identified the tool '{scanner}'. "
                "This may be an authorised test or unauthorised reconnaissance."
            ),
            status="Blocked (403)",
            dedupe_seconds=600,
        )

        return make_response(
            render_template(
                "error.html",
                code=403,
                message=(
                    "This request was rejected by Passme's "
                    "scanner-detection rule."
                ),
            ),
            403,
        )

    return None


# Retrieve the currently authenticated user from the session.
def current_user():
    uid = session.get("user_id")

    if not uid:
        return None

    with db() as conn:
        return conn.execute(
            """
            SELECT id, name, email, role, status
            FROM users
            WHERE id=?
            """,
            (uid,),
        ).fetchone()


# Require an active account and a valid absolute session expiry.
def require_login(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()

        if not user or user["status"] != "Active":
            session.clear()
            flash("Please sign in to continue.", "error")
            return redirect(url_for("login"))

        # Activity does not extend the absolute session lifetime.
        expires_at = session.get("_session_expires_at")
        now = time.time()

        try:
            expired = (
                expires_at is None
                or now >= float(expires_at)
            )
        except (TypeError, ValueError):
            expired = True

        if expired:
            session.clear()
            flash(
                "Your session has expired. Please sign in again.",
                "error",
            )
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped


# Restrict routes according to the permissions assigned to the user's role.
def require_permission(permission):
    def decorator(view):
        @wraps(view)
        @require_login
        def wrapped(*args, **kwargs):
            user = current_user()

            if permission not in PERMISSIONS.get(user["role"], set()):
                # Log access denials for audit and security review.
                audit(
                    user["name"],
                    f"Denied {request.method} {request.path}",
                    request.path,
                    "Denied",
                )

                record_security_event(
                    fingerprint=(
                        f"authorization:{client_ip()}:"
                        f"{user['id']}:{request.path}"
                    ),
                    severity="Medium",
                    category="Access control",
                    title="Unauthorised access attempt",
                    details=(
                        f"Role '{user['role']}' attempted to access "
                        "a route without the required permission."
                    ),
                    status="Blocked (403)",
                    dedupe_seconds=300,
                )

                abort(403)

            return view(*args, **kwargs)

        return wrapped

    return decorator


# Apply suspicious-request detection before route handlers execute.
@app.before_request
def suspicious_request_guard():
    return detect_suspicious_request()


# Require a valid CSRF token for all state-changing HTTP requests.
@app.before_request
def csrf_guard():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        expected = session.get("_csrf_token")
        supplied = (
            request.form.get("_csrf_token")
            or request.headers.get("X-CSRF-Token")
        )

        if (
            not expected
            or not supplied
            or not secrets.compare_digest(expected, supplied)
        ):
            record_security_event(
                fingerprint=f"csrf:{client_ip()}:{request.path}",
                severity="Medium",
                category="Request integrity",
                title="Invalid or missing CSRF token",
                details=(
                    "A state-changing request did not include "
                    "a valid CSRF token."
                ),
                status="Blocked (400)",
                dedupe_seconds=300,
            )
            abort(400, description="Invalid or missing CSRF token.")


# Record repeated requests for nonexistent routes as reconnaissance signals.
@app.after_request
def record_not_found_probes(response):
    if response.status_code == 404 and request.endpoint is None:
        source = client_ip()
        fingerprint = f"not-found:{source}"

        occurrences = record_security_event(
            fingerprint=fingerprint,
            severity="Low",
            category="Reconnaissance",
            title="Unmatched URL request",
            details=(
                "Passme returned HTTP 404 for an unmatched URL."
            ),
            status="Rejected (404)",
            dedupe_seconds=300,
        )

        # Increase the severity after repeated unmatched paths.
        if occurrences >= 8:
            promote_security_event(
                fingerprint,
                severity="Medium",
                title="Repeated path-probing pattern",
                details=(
                    f"{occurrences} unmatched URL requests were observed "
                    "from this source within the recent detection window. "
                    "Passme returned HTTP 404 responses."
                ),
                status="Rejected (404)",
            )

    return response


# Make authenticated user data and template security helpers available to Jinja.
@app.context_processor
def template_globals():
    user = current_user()

    # Create a CSRF token for forms when the session does not have one.
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)

    return {
        "current_user": user,
        "csrf_token": session["_csrf_token"],
        "session_expires_at": session.get("_session_expires_at"),
        "can": lambda perm: bool(
            user and perm in PERMISSIONS.get(user["role"], set())
        ),
    }


# Read a saved application setting or return its fallback value.
def get_setting(key, default=None):
    with db() as conn:
        row = conn.execute(
            "SELECT value FROM settings WHERE key=?",
            (key,),
        ).fetchone()

    return row["value"] if row else default


# Redirect users to the dashboard or login page.
@app.route("/")
def index():
    if current_user():
        return redirect(url_for("overview"))

    return redirect(url_for("login"))


# Authenticate users and apply failed-login protection.
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET" and current_user():
        return redirect(url_for("overview"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()[:254]
        password = request.form.get("password", "")
        protection_on = get_setting("failed_login_protection", "1") == "1"
        now = datetime.now(timezone.utc)

        locked_until = None
        count = 0

        # Check whether failed-login protection has locked this account.
        if protection_on and email:
            with db() as conn:
                attempt = conn.execute(
                    "SELECT * FROM login_attempts WHERE email=?",
                    (email,),
                ).fetchone()

            if attempt and attempt["locked_until"]:
                try:
                    locked_until = datetime.fromisoformat(
                        attempt["locked_until"]
                    )

                    if locked_until.tzinfo is None:
                        locked_until = locked_until.replace(
                            tzinfo=timezone.utc
                        )
                except ValueError:
                    locked_until = None

        if locked_until and locked_until > now:
            audit(
                email,
                "Sign-in blocked by temporary lockout",
                "Authentication",
                "Denied",
            )

            account_key = hashlib.sha256(
                email.encode("utf-8")
            ).hexdigest()[:16]

            record_security_event(
                fingerprint=f"locked-login:{client_ip()}:{account_key}",
                severity="High",
                category="Authentication",
                title="Login attempt against a temporarily locked account",
                details=(
                    "Passme rejected a sign-in attempt because its "
                    "existing failed-login lockout is active."
                ),
                status="Blocked (429)",
                dedupe_seconds=300,
            )

            remaining = max(
                1,
                int((locked_until - now).total_seconds() // 60) + 1,
            )
            flash(
                f"Too many failed attempts. Try again in about "
                f"{remaining} minute(s).",
                "error",
            )
            return render_template("login.html"), 429

        # Retrieve the account using a parameterized query.
        with db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE email=?",
                (email,),
            ).fetchone()

        # Reject passwords exceeding bcrypt's 72-byte input limit.
        password_bytes = password.encode("utf-8")
        valid = bool(
            len(password_bytes) <= 72
            and user
            and user["status"] == "Active"
            and bcrypt.checkpw(
                password_bytes,
                user["password_hash"],
            )
        )

        if valid:
            # Clear failed attempts and update the user's last activity.
            with db() as conn:
                conn.execute(
                    "DELETE FROM login_attempts WHERE email=?",
                    (email,),
                )
                conn.execute(
                    "UPDATE users SET last_active=? WHERE id=?",
                    (now_text(), user["id"]),
                )

            # Start a fresh session after successful authentication.
            session.clear()
            session["user_id"] = user["id"]
            session["_csrf_token"] = secrets.token_urlsafe(32)

            try:
                timeout_minutes = int(
                    get_setting("session_timeout", "15")
                )
            except (ValueError, TypeError):
                timeout_minutes = 15

            if timeout_minutes not in {5, 15, 30}:
                timeout_minutes = 15

            app.permanent_session_lifetime = timedelta(
                minutes=timeout_minutes
            )

            session["_session_started_at"] = time.time()
            session["_session_expires_at"] = (
                session["_session_started_at"] + timeout_minutes * 60
            )
            session.permanent = True

            audit(
                user["name"],
                "Signed in successfully",
                "Authentication",
                "Granted",
            )
            return redirect(url_for("overview"))

        # Count failed attempts and apply a temporary account lockout.
        if protection_on and email:
            with db() as conn:
                attempt = conn.execute(
                    "SELECT * FROM login_attempts WHERE email=?",
                    (email,),
                ).fetchone()

                if not attempt:
                    conn.execute(
                        """
                        INSERT INTO login_attempts
                            (email, attempts, window_started, locked_until)
                        VALUES (?, ?, ?, NULL)
                        """,
                        (email, 1, now.isoformat()),
                    )
                    count = 1
                else:
                    try:
                        started = datetime.fromisoformat(
                            attempt["window_started"]
                        )
                        if started.tzinfo is None:
                            started = started.replace(
                                tzinfo=timezone.utc
                            )
                    except ValueError:
                        started = now

                    # Reset the attempt counter after the 15-minute window.
                    if (now - started).total_seconds() > 900:
                        count = 1
                        conn.execute(
                            """
                            UPDATE login_attempts
                            SET attempts=1, window_started=?, locked_until=NULL
                            WHERE email=?
                            """,
                            (now.isoformat(), email),
                        )
                    else:
                        count = int(attempt["attempts"]) + 1
                        lock_value = (
                            (now + timedelta(minutes=15)).isoformat()
                            if count >= 5
                            else None
                        )
                        conn.execute(
                            """
                            UPDATE login_attempts
                            SET attempts=?, locked_until=?
                            WHERE email=?
                            """,
                            (count, lock_value, email),
                        )

                # Ensure the fifth failed attempt starts a 15-minute lockout.
                if count >= 5:
                    conn.execute(
                        """
                        UPDATE login_attempts
                        SET locked_until=?
                        WHERE email=?
                        """,
                        (
                            (now + timedelta(minutes=15)).isoformat(),
                            email,
                        ),
                    )

        # Log the failed authentication without storing the submitted password.
        audit(
            email or "Anonymous",
            "Failed sign-in attempt",
            "Authentication",
            "Failed",
        )

        account_key = hashlib.sha256(
            (email or "<blank-account>").encode("utf-8")
        ).hexdigest()[:16]

        is_bruteforce = bool(
            protection_on and email and count >= 5
        )

        record_security_event(
            fingerprint=f"login-failure:{client_ip()}:{account_key}",
            severity="High" if is_bruteforce else "Low",
            category="Authentication",
            title=(
                "Brute-force login pattern detected"
                if is_bruteforce
                else "Failed login attempt"
            ),
            details=(
                "Five or more failed sign-in attempts were recorded for "
                "the submitted account identifier in the protection window; "
                "Passme triggered its temporary lockout."
                if is_bruteforce
                else "A sign-in attempt used an invalid email/password combination."
            ),
            status="Blocked (429)" if is_bruteforce else "Observed",
            dedupe_seconds=900,
        )

        # Track failed sign-ins across different account identifiers.
        source_fingerprint = f"failed-login-source:{client_ip()}"

        source_failures = record_security_event(
            fingerprint=source_fingerprint,
            severity="Low",
            category="Authentication",
            title="Multiple failed sign-ins from one source",
            details=(
                "Repeated invalid sign-in attempts were observed from "
                "this source. This signal aggregates attempts across "
                "submitted account identifiers."
            ),
            status="Observed",
            dedupe_seconds=900,
        )

        # Flag possible password spraying for investigation.
        if source_failures >= 10:
            promote_security_event(
                source_fingerprint,
                severity="High",
                title="Possible password-spraying activity",
                details=(
                    f"{source_failures} failed sign-in attempts were "
                    "observed from this source within 15 minutes, across "
                    "one or more account identifiers. Review the source "
                    "and account activity; this signal alone does not "
                    "prove compromise."
                ),
                status="Observed",
            )

        if protection_on and email and count >= 5:
            audit(
                email,
                "Account temporarily locked after repeated failures",
                "Authentication",
                "Denied",
            )
            flash(
                "Too many failed attempts. This sign-in is temporarily "
                "locked for 15 minutes.",
                "error",
            )
            return render_template("login.html"), 429

        flash("Invalid email or password.", "error")

    return render_template("login.html")


# Sign out the current user and invalidate the session.
@app.post("/logout")
@require_login
def logout():
    user = current_user()

    audit(
        user["name"],
        "Signed out",
        "Authentication",
        "Granted",
    )

    session.clear()
    return redirect(url_for("login"))


# Build the dashboard using current database records.
@app.route("/overview")
@require_permission("view_overview")
def overview():
    with db() as conn:
        # Collect account, role, finding, and audit metrics.
        users_count = conn.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]

        logs = conn.execute(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 6"
        ).fetchall()

        role_count = conn.execute(
            "SELECT COUNT(DISTINCT role) FROM users"
        ).fetchone()[0]

        open_findings = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE status!='Resolved'"
        ).fetchone()[0]

        critical_findings = conn.execute(
            """
            SELECT COUNT(*)
            FROM findings
            WHERE severity='Critical' AND status!='Resolved'
            """
        ).fetchone()[0]

        today = datetime.now().astimezone().strftime("%Y-%m-%d")

        recent_events = conn.execute(
            """
            SELECT COUNT(*)
            FROM audit_logs
            WHERE substr(event_time, 1, 10)=?
            """,
            (today,),
        ).fetchone()[0]

        # Group today's audit activity by hour.
        hourly_rows = conn.execute(
            """
            SELECT
                substr(event_time, 1, 13) AS hour_key,
                SUM(
                    CASE
                        WHEN result IN ('Granted', 'Success') THEN 1
                        ELSE 0
                    END
                ) AS granted,
                SUM(
                    CASE
                        WHEN result IN ('Failed', 'Denied') THEN 1
                        ELSE 0
                    END
                ) AS blocked,
                COUNT(*) AS total
            FROM audit_logs
            WHERE substr(event_time, 1, 10)=?
            GROUP BY hour_key
            ORDER BY hour_key
            """,
            (today,),
        ).fetchall()

        # Check whether stored passwords have bcrypt hash prefixes.
        password_rows = conn.execute(
            "SELECT password_hash FROM users"
        ).fetchall()

    # Include all 24 hours so inactive hours appear as zero.
    current_hour = datetime.now().astimezone().replace(
        minute=0,
        second=0,
        microsecond=0,
    )
    by_hour = {row["hour_key"]: row for row in hourly_rows}
    activity = []

    for offset in range(23, -1, -1):
        hour_dt = current_hour - timedelta(hours=offset)
        key = hour_dt.strftime("%Y-%m-%d %H")
        row = by_hour.get(key)

        activity.append(
            {
                "label": hour_dt.strftime("%H:%M"),
                "granted": int(row["granted"] or 0) if row else 0,
                "blocked": int(row["blocked"] or 0) if row else 0,
                "total": int(row["total"] or 0) if row else 0,
            }
        )

    # Read security settings used to evaluate the application configuration.
    timeout_value = get_setting("session_timeout", "15")
    failed_protection = (
        get_setting("failed_login_protection", "1") == "1"
    )
    realtime_audit = get_setting("real_time_audit", "1") == "1"

    hashes_valid = bool(password_rows) and all(
        bytes(row["password_hash"]).startswith(
            (b"$2a$", b"$2b$", b"$2y$")
        )
        for row in password_rows
    )

    # Build the security checklist displayed on the dashboard.
    checks = [
        {
            "name": "Password hashes",
            "detail": (
                "Stored user passwords use bcrypt hashes"
                if hashes_valid
                else "One or more stored password hashes need review"
            ),
            "passed": hashes_valid,
        },
        {
            "name": "Session timeout",
            "detail": (
                f"{timeout_value}-minute absolute session expiry"
                if timeout_value in {"5", "15", "30"}
                else "Timeout setting is invalid"
            ),
            "passed": timeout_value in {"5", "15", "30"},
        },
        {
            "name": "Failed-login protection",
            "detail": (
                "Temporary lockout is enabled"
                if failed_protection
                else "Temporary lockout is disabled"
            ),
            "passed": failed_protection,
        },
        {
            "name": "Audit logging",
            "detail": (
                "Application audit logging is enabled"
                if realtime_audit
                else "Real-time audit feed is disabled"
            ),
            "passed": realtime_audit,
        },
    ]

    # Calculate an application-configuration score, not a host security guarantee.
    security_score = round(
        sum(25 for check in checks if check["passed"])
        - min(critical_findings * 10, 30)
    )
    security_score = max(0, min(100, security_score))

    if security_score >= 85:
        security_label = "Strong application controls"
    elif security_score >= 60:
        security_label = "Needs improvement"
    else:
        security_label = "Action required"

    return render_template(
        "overview.html",
        users_count=users_count,
        audit_logs=logs,
        role_count=role_count,
        open_findings=open_findings,
        critical_findings=critical_findings,
        recent_events=recent_events,
        activity=activity,
        security_checks=checks,
        security_score=security_score,
        security_label=security_label,
        failed_protection=failed_protection,
        realtime_audit=realtime_audit,
        hashes_valid=hashes_valid,
        timeout_value=timeout_value,
    )


# List user accounts for administrators with user-management permission.
@app.route("/users")
@require_permission("manage_users")
def users():
    with db() as conn:
        rows = conn.execute(
            """
            SELECT id, name, email, role, status, last_active
            FROM users
            ORDER BY id
            """
        ).fetchall()

    result = []

    for row in rows:
        item = dict(row)
        item["initials"] = (
            "".join(
                part[0].upper()
                for part in item["name"].split()[:2]
            )
            or "U"
        )
        result.append(item)

    return render_template(
        "users.html",
        users=result,
        roles=ROLES,
    )


# Validate and create a new user with a bcrypt password hash.
@app.post("/add-user")
@require_permission("manage_users")
def add_user():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", "Standard User")

    if len(name) < 2 or len(name) > 100 or "@" not in email or len(email) > 254:
        flash("Enter a valid name and email address.", "error")
    elif role not in ROLES:
        flash("Select a valid role.", "error")
    elif len(password) < 12 or len(password.encode("utf-8")) > 72:
        flash(
            "Use a temporary password of at least 12 characters "
            "and no more than 72 UTF-8 bytes.",
            "error",
        )
    else:
        try:
            # Hash the password before storing the new account.
            password_hash = bcrypt.hashpw(
                password.encode("utf-8"),
                bcrypt.gensalt(),
            )

            with db() as conn:
                conn.execute(
                    """
                    INSERT INTO users
                        (name, email, password_hash, role, status,
                         created_at, last_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        name,
                        email,
                        password_hash,
                        role,
                        "Active",
                        now_text(),
                        "Never",
                    ),
                )

            audit(
                current_user()["name"],
                f"Created user {name}",
                "User Management",
                "Granted",
            )
            flash(f"User {name} was created.", "success")

        except sqlite3.IntegrityError:
            flash(
                "That email address is already registered.",
                "error",
            )

    return redirect(url_for("users"))


# Display role permissions and test whether a role can perform an action.
@app.route("/roles", methods=["GET", "POST"])
@require_permission("view_roles")
def roles():
    selected_role = request.args.get("role", "Administrator")

    if selected_role not in ROLES:
        selected_role = "Administrator"

    # Map visible access-testing actions to internal permission names.
    action_map = {
        "Access protected files": "view_overview",
        "Manage users": "manage_users",
        "Export audit logs": "export_audit",
    }

    evaluation_result = None

    if request.method == "POST":
        role = request.form.get("role", "")
        action = request.form.get("action", "")

        allowed = (
            role in ROLES
            and action in action_map
            and action_map[action] in PERMISSIONS.get(role, set())
        )

        status = "Granted" if allowed else "Denied"
        evaluation_result = {
            "status": status,
            "message": (
                f"{role} {'can' if allowed else 'cannot'} "
                f"perform '{action}'."
            ),
        }

        audit(
            current_user()["name"],
            f"Tested {role}: {action}",
            "Roles & Permissions",
            status,
        )

        if role in ROLES:
            selected_role = role

    # Count how many accounts are assigned to each role.
    role_counts = {}

    with db() as conn:
        for role in ROLES:
            role_counts[role] = conn.execute(
                "SELECT COUNT(*) FROM users WHERE role=?",
                (role,),
            ).fetchone()[0]

    # Describe the permissions shown on the role-management page.
    role_perms = {
        "Administrator": [
            ("Manage users", "Create and administer user accounts"),
            ("Manage roles", "Review role permissions"),
            ("View audit logs", "Review access history"),
            ("Edit system settings", "Configure security controls"),
        ],
        "Security Analyst": [
            ("Monitor security events", "Review findings and access events"),
            ("View audit logs", "Read authentication and access history"),
            ("Review findings", "Update security findings"),
        ],
        "Auditor": [
            ("View audit logs", "Inspect authentication and authorization records"),
            ("Export audit reports", "Download CSV audit records"),
        ],
        "Standard User": [
            ("Access assigned business resources", "Access only permitted workspace features"),
        ],
    }

    return render_template(
        "roles.html",
        roles=ROLES,
        selected_role=selected_role,
        permissions=role_perms[selected_role],
        role_counts=role_counts,
        role_perms_count={
            role: len(role_perms[role])
            for role in ROLES
        },
        evaluation_result=evaluation_result,
    )


# Display recent audit records to users with audit-view permission.
@app.route("/audit-logs")
@require_permission("view_audit")
def audit_logs():
    with db() as conn:
        logs = conn.execute(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 1000"
        ).fetchall()

    return render_template("audit_logs.html", logs=logs)


# Provide recent audit records to the authenticated live-feed interface.
@app.route("/api/audit-logs")
@require_permission("view_audit")
def audit_logs_feed():
    with db() as conn:
        rows = conn.execute(
            """
            SELECT id, user_name, action, resource, event_time, result
            FROM audit_logs
            ORDER BY id DESC
            LIMIT 100
            """
        ).fetchall()

    return jsonify(
        {
            "enabled": get_setting("real_time_audit", "1") == "1",
            "logs": [dict(row) for row in rows],
            "server_time": now_text(),
        }
    )


# Export audit records as a CSV file.
@app.route("/export-csv")
@require_permission("export_audit")
def export_csv():
    with db() as conn:
        logs = conn.execute(
            """
            SELECT user_name, action, resource, event_time, result
            FROM audit_logs
            ORDER BY id DESC
            """
        ).fetchall()

    # Write CSV content with column headings.
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["User", "Action", "Resource", "Time", "Result"])
    writer.writerows([tuple(row) for row in logs])

    audit(
        current_user()["name"],
        "Exported audit report",
        "Audit Log",
        "Granted",
    )

    # Add a UTF-8 BOM to improve compatibility with spreadsheet software.
    response = make_response("\ufeff" + output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = (
        "attachment; filename=audit_logs.csv"
    )

    return response


# Display security findings and recent security-event statistics.
@app.route("/security-centre")
@require_permission("manage_findings")
def security_centre():
    cutoff = time.time() - 86400

    with db() as conn:
        findings = conn.execute(
            "SELECT * FROM findings ORDER BY id"
        ).fetchall()

        critical_count = conn.execute(
            """
            SELECT COUNT(*)
            FROM findings
            WHERE severity='Critical' AND status!='Resolved'
            """
        ).fetchone()[0]

        events = conn.execute(
            "SELECT * FROM security_events ORDER BY id DESC LIMIT 50"
        ).fetchall()

        event_groups = conn.execute(
            """
            SELECT COUNT(*)
            FROM security_events
            WHERE last_seen_epoch>=?
            """,
            (cutoff,),
        ).fetchone()[0]

        event_occurrences = conn.execute(
            """
            SELECT COALESCE(SUM(occurrences), 0)
            FROM security_events
            WHERE last_seen_epoch>=?
            """,
            (cutoff,),
        ).fetchone()[0]

        high_count = conn.execute(
            """
            SELECT COUNT(*)
            FROM security_events
            WHERE severity IN ('High', 'Critical')
              AND last_seen_epoch>=?
            """,
            (cutoff,),
        ).fetchone()[0]

        rejected_count = conn.execute(
            """
            SELECT COALESCE(SUM(occurrences), 0)
            FROM security_events
            WHERE (status LIKE 'Blocked%' OR status LIKE 'Rejected%')
              AND last_seen_epoch>=?
            """,
            (cutoff,),
        ).fetchone()[0]

    return render_template(
        "security_centre.html",
        findings=findings,
        critical_count=critical_count,
        security_events=events,
        event_groups=event_groups,
        event_occurrences=event_occurrences,
        high_count=high_count,
        rejected_count=rejected_count,
        realtime_audit=get_setting("real_time_audit", "1") == "1",
    )


# Return recent security events and statistics to the live security feed.
@app.route("/api/security-events")
@require_permission("manage_findings")
def security_events_feed():
    cutoff = time.time() - 86400

    with db() as conn:
        rows = conn.execute(
            """
            SELECT id, event_time, last_seen, source_ip, severity, category,
                   title, method, endpoint, details, status, occurrences
            FROM security_events
            ORDER BY id DESC
            LIMIT 50
            """
        ).fetchall()

        event_groups = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE last_seen_epoch>=?",
            (cutoff,),
        ).fetchone()[0]

        event_occurrences = conn.execute(
            """
            SELECT COALESCE(SUM(occurrences), 0)
            FROM security_events
            WHERE last_seen_epoch>=?
            """,
            (cutoff,),
        ).fetchone()[0]

        high_count = conn.execute(
            """
            SELECT COUNT(*)
            FROM security_events
            WHERE severity IN ('High', 'Critical')
              AND last_seen_epoch>=?
            """,
            (cutoff,),
        ).fetchone()[0]

        rejected_count = conn.execute(
            """
            SELECT COALESCE(SUM(occurrences), 0)
            FROM security_events
            WHERE (status LIKE 'Blocked%' OR status LIKE 'Rejected%')
              AND last_seen_epoch>=?
            """,
            (cutoff,),
        ).fetchone()[0]

    return jsonify(
        {
            "enabled": get_setting("real_time_audit", "1") == "1",
            "events": [dict(row) for row in rows],
            "stats": {
                "groups": event_groups,
                "occurrences": event_occurrences,
                "high": high_count,
                "rejected": rejected_count,
            },
            "server_time": now_text(),
        }
    )


# Validate and update the status of a security finding.
@app.post("/update-finding/<int:finding_id>")
@require_permission("manage_findings")
def update_finding(finding_id):
    new_status = request.form.get("status", "").strip()

    if new_status not in FINDING_STATUSES:
        flash("Choose a valid finding status.", "error")
        return redirect(url_for("security_centre"))

    with db() as conn:
        finding = conn.execute(
            "SELECT title, status FROM findings WHERE id=?",
            (finding_id,),
        ).fetchone()

        if not finding:
            abort(404)

        old_status = finding["status"]

        if old_status != new_status:
            conn.execute(
                "UPDATE findings SET status=? WHERE id=?",
                (new_status, finding_id),
            )

    # Record status changes for accountability.
    if old_status != new_status:
        audit(
            current_user()["name"],
            f"Changed finding #{finding_id} status: "
            f"{old_status} → {new_status}",
            "Security Centre",
            "Granted",
        )
        flash(f"Finding status changed to {new_status}.", "success")
    else:
        flash("No status change was needed.", "success")

    return redirect(url_for("security_centre"))


# Preserve compatibility with older forms that resolve findings directly.
@app.post("/resolve-finding/<int:finding_id>")
@require_permission("manage_findings")
def resolve_finding(finding_id):
    with db() as conn:
        finding = conn.execute(
            "SELECT status FROM findings WHERE id=?",
            (finding_id,),
        ).fetchone()

        if not finding:
            abort(404)

        old_status = finding["status"]

        conn.execute(
            "UPDATE findings SET status='Resolved' WHERE id=?",
            (finding_id,),
        )

    # Audit the resolution when the status changes.
    if old_status != "Resolved":
        audit(
            current_user()["name"],
            f"Changed finding #{finding_id} status: "
            f"{old_status} → Resolved",
            "Security Centre",
            "Granted",
        )

    flash("Finding marked as resolved.", "success")
    return redirect(url_for("security_centre"))


# Save application security settings after validating the submitted values.
@app.route("/settings", methods=["GET", "POST"])
@require_permission("manage_settings")
def settings():
    if request.method == "POST":
        timeout = request.form.get("session_timeout", "")

        if timeout not in {"5", "15", "30"}:
            flash("Choose a valid session timeout.", "error")
        else:
            # Normalize checkbox values before saving settings.
            values = {
                "session_timeout": timeout,
                "failed_login_protection": (
                    "1" if request.form.get("failed_login_protection") else "0"
                ),
                "real_time_audit": (
                    "1" if request.form.get("real_time_audit") else "0"
                ),
            }

            with db() as conn:
                conn.executemany(
                    """
                    INSERT INTO settings(key, value)
                    VALUES (?, ?)
                    ON CONFLICT(key)
                    DO UPDATE SET value=excluded.value
                    """,
                    values.items(),
                )

            # Apply the new absolute timeout to the current session.
            timeout_minutes = int(timeout)
            app.permanent_session_lifetime = timedelta(
                minutes=timeout_minutes
            )

            session_started_at = session.get("_session_started_at")

            if session_started_at is not None:
                session["_session_expires_at"] = (
                    float(session_started_at) + timeout_minutes * 60
                )

            audit(
                current_user()["name"],
                "Updated system settings "
                f"(session timeout: {timeout_minutes} minutes)",
                "Settings",
                "Granted",
            )

            flash("Settings updated.", "success")
            return redirect(url_for("settings"))

    # Load the current settings for the page controls.
    settings_data = {
        "session_timeout": get_setting("session_timeout", "15"),
        "failed_login_protection": (
            get_setting("failed_login_protection", "1") == "1"
        ),
        "real_time_audit": (
            get_setting("real_time_audit", "1") == "1"
        ),
    }

    return render_template("settings.html", settings=settings_data)


# Render a friendly error page for malformed requests.
@app.errorhandler(400)
def bad_request(error):
    message = getattr(
        error,
        "description",
        "The request could not be processed.",
    )
    return render_template(
        "error.html",
        code=400,
        message=message,
    ), 400


# Render an access-denied page when the user lacks permission.
@app.errorhandler(403)
def forbidden(_error):
    return render_template(
        "error.html",
        code=403,
        message=(
            "Your role does not have permission to access this page."
        ),
    ), 403


# Render a not-found page for missing routes and resources.
@app.errorhandler(404)
def not_found(_error):
    return render_template(
        "error.html",
        code=404,
        message="The requested page was not found.",
    ), 404


# Initialize the database and start the local development server.
if __name__ == "__main__":
    init_db()

    # Bind to localhost for local development; do not enable the debugger.
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
