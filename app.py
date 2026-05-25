#!/usr/bin/env python3
import warnings

warnings.filterwarnings("ignore", message="'cgi' is deprecated.*", category=DeprecationWarning)

import cgi
import calendar
import hashlib
import hmac
import html
import mimetypes
import os
import secrets
import shutil
import sqlite3
from datetime import datetime, timedelta
from http import HTTPStatus
from http.cookies import SimpleCookie
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse
from wsgiref.handlers import format_date_time
from http.server import BaseHTTPRequestHandler, HTTPServer


APARTMENT_NAME = os.getenv("APARTMENT_NAME", "Ceahlau 43/2")
APP_NAME = os.getenv("APP_NAME", APARTMENT_NAME)
DATA_DIR = Path(os.getenv("DATA_DIR", "data"))
DB_PATH = Path(os.getenv("DATABASE_PATH", DATA_DIR / "chirie.sqlite3"))
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", DATA_DIR / "uploads"))
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
SESSION_DAYS = int(os.getenv("SESSION_DAYS", "30"))
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(8 * 1024 * 1024)))
LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "900"))
LOGIN_MAX_IP_ATTEMPTS = int(os.getenv("LOGIN_MAX_IP_ATTEMPTS", "30"))
LOGIN_MAX_ACCOUNT_ATTEMPTS = int(os.getenv("LOGIN_MAX_ACCOUNT_ATTEMPTS", "8"))
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".pdf"}
UTILITY_TYPES = {
    "electricity": "Electricity",
    "gas": "Gas",
    "common": "Common bills",
    "internet": "Internet",
}
CHARGE_TYPES = {
    "rent": "Rent",
    "other": "Other charge",
}
READING_MODES = {
    "actual": "Actual reading",
    "estimated": "Estimated invoice",
    "rollover": "Meter rollover",
    "correction": "Correction / credit",
    "final": "Final move-out reading",
}
LOGIN_ATTEMPTS: dict[str, list[float]] = {}


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat()


def money(value: Any) -> str:
    try:
        return f"{float(value):,.2f} RON"
    except (TypeError, ValueError):
        return "0.00 RON"


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def month_label(value: str) -> str:
    try:
        return datetime.strptime(value, "%Y-%m").strftime("%B %Y")
    except (TypeError, ValueError):
        return esc(value)


def today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def current_month() -> str:
    return datetime.now().strftime("%Y-%m")


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 260_000)
    return f"pbkdf2_sha256$260000${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations),
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def parse_float(value: Any, default: float = 0.0) -> float:
    if value in (None, ""):
        return default
    try:
        return float(str(value).replace(",", "."))
    except ValueError:
        return default


def parse_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def table_columns(db: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in db.execute(f"PRAGMA table_info({table})").fetchall()}


def add_column_if_missing(db: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    if column not in table_columns(db, table):
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def migrate() -> None:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'tenant')),
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tenancies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                label TEXT NOT NULL,
                start_date TEXT NOT NULL,
                end_date TEXT,
                start_electricity REAL,
                start_gas REAL,
                end_electricity REAL,
                end_gas REAL,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS utility_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenancy_id INTEGER REFERENCES tenancies(id) ON DELETE SET NULL,
                utility_type TEXT NOT NULL,
                month TEXT NOT NULL,
                service_start TEXT,
                service_end TEXT,
                reading_mode TEXT NOT NULL DEFAULT 'actual',
                previous_reading REAL,
                current_reading REAL,
                consumption REAL,
                rollover_limit REAL,
                adjustment_amount REAL NOT NULL DEFAULT 0,
                bill_amount REAL NOT NULL DEFAULT 0,
                due_date TEXT,
                paid INTEGER NOT NULL DEFAULT 0,
                paid_at TEXT,
                notes TEXT,
                created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS charges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenancy_id INTEGER REFERENCES tenancies(id) ON DELETE SET NULL,
                charge_type TEXT NOT NULL CHECK(charge_type IN ('rent', 'other')),
                month TEXT NOT NULL,
                service_start TEXT,
                service_end TEXT,
                title TEXT NOT NULL,
                amount REAL NOT NULL DEFAULT 0,
                due_date TEXT,
                paid INTEGER NOT NULL DEFAULT 0,
                paid_at TEXT,
                notes TEXT,
                created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                utility_entry_id INTEGER REFERENCES utility_entries(id) ON DELETE CASCADE,
                charge_id INTEGER REFERENCES charges(id) ON DELETE CASCADE,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                content_type TEXT,
                size INTEGER NOT NULL DEFAULT 0,
                uploaded_at TEXT NOT NULL,
                CHECK (
                    (utility_entry_id IS NOT NULL AND charge_id IS NULL)
                    OR (utility_entry_id IS NULL AND charge_id IS NOT NULL)
                )
            );

            CREATE INDEX IF NOT EXISTS idx_utility_month ON utility_entries(month DESC);
            CREATE INDEX IF NOT EXISTS idx_charges_month ON charges(month DESC);
            CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        for column, definition in {
            "tenancy_id": "INTEGER",
            "service_start": "TEXT",
            "service_end": "TEXT",
            "reading_mode": "TEXT NOT NULL DEFAULT 'actual'",
            "rollover_limit": "REAL",
            "adjustment_amount": "REAL NOT NULL DEFAULT 0",
        }.items():
            add_column_if_missing(db, "utility_entries", column, definition)
        for column, definition in {
            "tenancy_id": "INTEGER",
            "service_start": "TEXT",
            "service_end": "TEXT",
        }.items():
            add_column_if_missing(db, "charges", column, definition)
        db.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_tenancies_dates ON tenancies(start_date, end_date);
            CREATE INDEX IF NOT EXISTS idx_utility_tenancy ON utility_entries(tenancy_id);
            CREATE INDEX IF NOT EXISTS idx_charges_tenancy ON charges(tenancy_id);
            """
        )
        defaults = {
            "rent_amount": "0",
            "rent_due_day": "1",
            "rent_enabled": "1",
        }
        for key, value in defaults.items():
            db.execute("INSERT OR IGNORE INTO app_settings (key, value) VALUES (?, ?)", (key, value))
        admin_count = db.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
        if admin_count == 0:
            email = os.getenv("ADMIN_EMAIL", "admin@example.com")
            password = os.getenv("ADMIN_PASSWORD", "ChangeMe123!")
            name = os.getenv("ADMIN_NAME", "Apartment Admin")
            db.execute(
                """
                INSERT INTO users (name, email, password_hash, role, active, created_at)
                VALUES (?, ?, ?, 'admin', 1, ?)
                """,
                (name, email, password_hash(password), now_iso()),
            )


def query_one(sql: str, params: tuple = ()) -> sqlite3.Row | None:
    with get_db() as db:
        return db.execute(sql, params).fetchone()


def query_all(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    with get_db() as db:
        return db.execute(sql, params).fetchall()


def execute(sql: str, params: tuple = ()) -> int:
    with get_db() as db:
        cur = db.execute(sql, params)
        return int(cur.lastrowid)


def get_setting(key: str, default: str = "") -> str:
    row = query_one("SELECT value FROM app_settings WHERE key = ?", (key,))
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    execute(
        """
        INSERT INTO app_settings (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (key, value),
    )


def due_date_for_month(month: str, due_day: int) -> str:
    try:
        year, month_number = (int(part) for part in month.split("-", 1))
        max_day = calendar.monthrange(year, month_number)[1]
        safe_day = max(1, min(int(due_day), max_day))
        return f"{year:04d}-{month_number:02d}-{safe_day:02d}"
    except Exception:
        return today()


def month_bounds(month: str) -> tuple[str, str]:
    try:
        year, month_number = (int(part) for part in month.split("-", 1))
        last_day = calendar.monthrange(year, month_number)[1]
        return f"{year:04d}-{month_number:02d}-01", f"{year:04d}-{month_number:02d}-{last_day:02d}"
    except Exception:
        value = today()
        return value, value


def active_tenancy_for_date(date_value: str) -> sqlite3.Row | None:
    return query_one(
        """
        SELECT tenancies.*, users.name AS tenant_name, users.email AS tenant_email
        FROM tenancies
        JOIN users ON users.id = tenancies.user_id
        WHERE tenancies.start_date <= ?
          AND (tenancies.end_date IS NULL OR tenancies.end_date = '' OR tenancies.end_date >= ?)
        ORDER BY tenancies.start_date DESC, tenancies.id DESC
        LIMIT 1
        """,
        (date_value, date_value),
    )


def visible_tenancy_ids(user: sqlite3.Row) -> list[int] | None:
    if user["role"] == "admin":
        return None
    rows = query_all("SELECT id FROM tenancies WHERE user_id = ? ORDER BY start_date DESC", (user["id"],))
    return [int(row["id"]) for row in rows]


def scoped_query(sql: str, user: sqlite3.Row, params: tuple = (), tenancy_column: str = "tenancy_id") -> list[sqlite3.Row]:
    ids = visible_tenancy_ids(user)
    if ids is None:
        return query_all(sql, params)
    if not ids:
        return []
    placeholders = ",".join("?" for _ in ids)
    return query_all(f"{sql} AND {tenancy_column} IN ({placeholders})", params + tuple(ids))


def tenancy_label(row: sqlite3.Row | None) -> str:
    if not row:
        return "Unassigned"
    end = row["end_date"] or "present"
    return f'{row["label"]} · {row["tenant_name"]} · {row["start_date"]} to {end}'


def ensure_recurring_rent(update_unpaid: bool = False) -> None:
    if get_setting("rent_enabled", "1") != "1":
        return
    amount = parse_float(get_setting("rent_amount", "0"), 0)
    if amount <= 0:
        return
    due_day = parse_int(get_setting("rent_due_day", "1")) or 1
    month = current_month()
    due_date = due_date_for_month(month, due_day)
    service_start, service_end = month_bounds(month)
    tenancy = active_tenancy_for_date(due_date)
    tenancy_id = tenancy["id"] if tenancy else None
    if tenancy_id is None:
        existing = query_one("SELECT * FROM charges WHERE charge_type = 'rent' AND month = ? AND tenancy_id IS NULL ORDER BY id LIMIT 1", (month,))
    else:
        existing = query_one("SELECT * FROM charges WHERE charge_type = 'rent' AND month = ? AND tenancy_id = ? ORDER BY id LIMIT 1", (month, tenancy_id))
    if existing:
        if update_unpaid and not existing["paid"]:
            execute(
                "UPDATE charges SET title = 'Rent', amount = ?, due_date = ?, service_start = ?, service_end = ?, tenancy_id = ?, updated_at = ? WHERE id = ?",
                (amount, due_date, service_start, service_end, tenancy_id, now_iso(), existing["id"]),
            )
        return
    execute(
        """
        INSERT INTO charges (tenancy_id, charge_type, month, service_start, service_end, title, amount, due_date, notes, created_by, created_at, updated_at)
        VALUES (?, 'rent', ?, ?, ?, 'Rent', ?, ?, 'Recurring monthly rent', NULL, ?, ?)
        """,
        (tenancy_id, month, service_start, service_end, amount, due_date, now_iso(), now_iso()),
    )


def redirect(handler: BaseHTTPRequestHandler, path: str) -> None:
    handler.send_response(HTTPStatus.SEE_OTHER)
    send_security_headers(handler)
    handler.send_header("Location", path)
    handler.end_headers()


def static_response(handler: BaseHTTPRequestHandler, content: bytes, content_type: str, status: int = 200) -> None:
    handler.send_response(status)
    send_security_headers(handler)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(content)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(content)


def send_security_headers(handler: BaseHTTPRequestHandler) -> None:
    handler.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "same-origin")
    handler.send_header("Cross-Origin-Resource-Policy", "same-origin")
    handler.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    handler.send_header(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'",
    )


def make_cookie(name: str, value: str, max_age: int | None = None) -> str:
    cookie = SimpleCookie()
    cookie[name] = value
    cookie[name]["path"] = "/"
    cookie[name]["httponly"] = True
    cookie[name]["samesite"] = "Lax"
    if os.getenv("COOKIE_SECURE", "0") == "1":
        cookie[name]["secure"] = True
    if max_age is not None:
        cookie[name]["max-age"] = str(max_age)
    return cookie.output(header="").strip()


def layout(title: str, user: sqlite3.Row | None, content: str, active: str = "") -> bytes:
    nav = ""
    if user:
        links = [
            ("/dashboard", "Dashboard", "dashboard"),
            ("/history", "History", "history"),
        ]
        if user["role"] == "admin":
            links.extend(
                [
                    ("/admin/utility/new", "Add bill", "utility"),
                    ("/admin/charge/new", "Add charge", "charge"),
                    ("/admin/tenancies", "Tenancies", "tenancies"),
                    ("/admin/settings", "Settings", "settings"),
                    ("/admin/users", "Users", "users"),
                ]
            )
        nav_links = "".join(
            f'<a class="nav-link {"active" if key == active else ""}" href="{href}">{label}</a>'
            for href, label, key in links
        )
        nav = f"""
        <aside class="sidebar">
            <a class="brand" href="/dashboard">
                <span class="brand-mark">43</span>
                <span><strong>{esc(APARTMENT_NAME)}</strong><small>rental management</small></span>
            </a>
            <nav>{nav_links}</nav>
            <form method="post" action="/logout" class="logout">
                {csrf_input(user)}
                <button class="ghost full" type="submit">Sign out</button>
            </form>
        </aside>
        """
    shell_class = "app-shell" if user else "guest-shell"
    main_class = "main" if user else "guest-main"
    document_title = esc(APARTMENT_NAME if title == APARTMENT_NAME else f"{title} · {APARTMENT_NAME}")
    html_doc = f"""<!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{document_title}</title>
        <link rel="stylesheet" href="/static/app.css">
        <script src="/static/app.js" defer></script>
    </head>
    <body class="{"authenticated" if user else "guest"}">
        <div class="{shell_class}">
            {nav}
            <main class="{main_class}">
                {content}
            </main>
        </div>
    </body>
    </html>"""
    return html_doc.encode("utf-8")


def csrf_input(user: sqlite3.Row | None) -> str:
    if not user:
        return ""
    return f'<input type="hidden" name="csrf_token" value="{esc(user["csrf_token"])}">'


def flash(message: str, kind: str = "ok") -> str:
    if not message:
        return ""
    return f'<div class="flash {esc(kind)}">{esc(message)}</div>'


def status_pill(paid: Any) -> str:
    if int(paid or 0):
        return '<span class="pill paid">Paid</span>'
    return '<span class="pill due">To pay</span>'


def role_badge(role: str) -> str:
    return f'<span class="pill role">{esc(role.title())}</span>'


def tenancy_options(selected_id: Any = None, include_unassigned: bool = True) -> str:
    selected = "" if selected_id in (None, "") else str(selected_id)
    rows = query_all(
        """
        SELECT tenancies.*, users.name AS tenant_name, users.email AS tenant_email
        FROM tenancies
        JOIN users ON users.id = tenancies.user_id
        ORDER BY COALESCE(tenancies.end_date, '9999-12-31') DESC, tenancies.start_date DESC
        """
    )
    options = ['<option value="">Unassigned / choose later</option>'] if include_unassigned else []
    for row in rows:
        value = str(row["id"])
        options.append(f'<option value="{value}" {"selected" if selected == value else ""}>{esc(tenancy_label(row))}</option>')
    return "".join(options)


def page_header(title: str, subtitle: str, actions: str = "") -> str:
    return f"""
    <header class="page-header">
        <div>
            <p class="eyebrow">{esc(APARTMENT_NAME)}</p>
            <h1>{esc(title)}</h1>
            <p>{esc(subtitle)}</p>
        </div>
        <div class="header-actions">{actions}</div>
    </header>
    """


def attachment_links(row_id: int, target: str) -> str:
    column = "utility_entry_id" if target == "utility" else "charge_id"
    files = query_all(
        f"SELECT * FROM attachments WHERE {column} = ? ORDER BY uploaded_at DESC",
        (row_id,),
    )
    if not files:
        return '<span class="muted">No bill image</span>'
    return "".join(
        f'<a class="file-link" href="/attachments/{file["id"]}" target="_blank" rel="noopener">{esc(file["original_name"])}</a>'
        for file in files
    )


def tenancy_badge(tenancy_id: Any) -> str:
    if not tenancy_id:
        return '<span class="muted">No tenant period</span>'
    row = query_one(
        """
        SELECT tenancies.*, users.name AS tenant_name, users.email AS tenant_email
        FROM tenancies
        JOIN users ON users.id = tenancies.user_id
        WHERE tenancies.id = ?
        """,
        (tenancy_id,),
    )
    if not row:
        return '<span class="muted">No tenant period</span>'
    return f'<span class="tenant-chip">{esc(row["label"])} · {esc(row["tenant_name"])}</span>'


def resolve_tenancy_id(raw_id: Any, reference_date: str) -> int | None:
    parsed = parse_int(raw_id)
    if parsed:
        return parsed
    tenancy = active_tenancy_for_date(reference_date)
    return int(tenancy["id"]) if tenancy else None


def calculate_consumption(
    utility_type: str,
    previous_value: float | None,
    current_value: float | None,
    reading_mode: str,
    rollover_limit: float | None,
) -> tuple[float | None, str]:
    if previous_value is None or current_value is None:
        return None, ""
    if current_value >= previous_value:
        return current_value - previous_value, ""
    if reading_mode == "rollover":
        if rollover_limit is None or rollover_limit <= previous_value:
            return None, "For a rollover, add the meter maximum / rollover value so consumption can be calculated."
        return (rollover_limit - previous_value) + current_value, ""
    if reading_mode in ("estimated", "correction", "final"):
        return current_value - previous_value, ""
    if utility_type in ("electricity", "gas"):
        return None, "Current reading is lower than previous. Use Correction / credit, Final move-out reading, or Meter rollover if this is intentional."
    return current_value - previous_value, ""


def readings_match(left: float | None, right: float | None) -> bool:
    if left is None or right is None:
        return True
    return abs(float(left) - float(right)) < 0.0001


def expected_previous_reading(
    utility_type: str,
    tenancy_id: int | None = None,
    before_date: str = "",
    exclude_id: int | None = None,
) -> float | None:
    params: list[Any] = [utility_type]
    filters = ["utility_type = ?", "current_reading IS NOT NULL"]
    if exclude_id is not None:
        filters.append("id != ?")
        params.append(exclude_id)
    if tenancy_id is not None:
        filters.append("tenancy_id = ?")
        params.append(tenancy_id)
    if before_date:
        filters.append("COALESCE(service_end, due_date, month || '-31') < ?")
        params.append(before_date)
    row = query_one(
        f"""
        SELECT current_reading
        FROM utility_entries
        WHERE {" AND ".join(filters)}
        ORDER BY COALESCE(service_end, due_date, month || '-31') DESC, id DESC
        LIMIT 1
        """,
        tuple(params),
    )
    if row:
        return float(row["current_reading"])
    if tenancy_id is not None and utility_type in ("electricity", "gas"):
        tenancy = query_one("SELECT * FROM tenancies WHERE id = ?", (tenancy_id,))
        if tenancy:
            column = "start_electricity" if utility_type == "electricity" else "start_gas"
            if tenancy[column] is not None:
                return float(tenancy[column])
    return None


def utility_card(entry: sqlite3.Row, user: sqlite3.Row) -> str:
    reading = "No reading"
    if entry["current_reading"] is not None:
        reading = f'{entry["current_reading"]:g}'
        if entry["previous_reading"] is not None:
            reading = f'{entry["previous_reading"]:g} → {entry["current_reading"]:g}'
    consumption = ""
    if entry["consumption"] is not None:
        consumption = f'<span>{entry["consumption"]:g} consumed</span>'
    adjustment = ""
    if float(entry["adjustment_amount"] or 0) != 0:
        adjustment = f'<span>Adjustment {money(entry["adjustment_amount"])}</span>'
    service_period = ""
    if entry["service_start"] or entry["service_end"]:
        service_period = f'<span>{esc(entry["service_start"] or "?")} to {esc(entry["service_end"] or "?")}</span>'
    admin_actions = ""
    if user["role"] == "admin":
        admin_actions = f"""
        <form method="post" action="/admin/utility/{entry["id"]}/toggle-paid">
            {csrf_input(user)}
            <button class="small" type="submit">Mark {"unpaid" if entry["paid"] else "paid"}</button>
        </form>
        <a class="button small ghost" href="/admin/utility/{entry["id"]}/edit">Edit</a>
        <form method="post" action="/admin/utility/{entry["id"]}/delete">
            {csrf_input(user)}
            <button class="small danger" type="submit">Delete</button>
        </form>
        """
    return f"""
    <article class="item-card">
        <div class="item-top">
            <div>
                <h3>{esc(UTILITY_TYPES.get(entry["utility_type"], entry["utility_type"]))}</h3>
                <p>{esc(month_label(entry["month"]))}</p>
            </div>
            {status_pill(entry["paid"])}
        </div>
        <dl class="compact-list">
            <div><dt>Amount</dt><dd>{money(entry["bill_amount"])}</dd></div>
            <div><dt>Reading</dt><dd>{esc(reading)}</dd></div>
            <div><dt>Due</dt><dd>{esc(entry["due_date"] or "Not set")}</dd></div>
        </dl>
        <div class="meta-line"><span>{esc(READING_MODES.get(entry["reading_mode"], "Actual reading"))}</span>{service_period}{consumption}{adjustment}<span>{esc(entry["notes"] or "")}</span></div>
        <div class="files">{tenancy_badge(entry["tenancy_id"])}</div>
        <div class="files">{attachment_links(entry["id"], "utility")}</div>
        <div class="card-actions">{admin_actions}</div>
    </article>
    """


def charge_card(charge: sqlite3.Row, user: sqlite3.Row) -> str:
    admin_actions = ""
    if user["role"] == "admin":
        edit_link = (
            '<a class="button small ghost" href="/admin/settings">Edit rent rule</a>'
            if charge["charge_type"] == "rent"
            else f'<a class="button small ghost" href="/admin/charge/{charge["id"]}/edit">Edit</a>'
        )
        admin_actions = f"""
        <form method="post" action="/admin/charge/{charge["id"]}/toggle-paid">
            {csrf_input(user)}
            <button class="small" type="submit">Mark {"unpaid" if charge["paid"] else "paid"}</button>
        </form>
        {edit_link}
        <form method="post" action="/admin/charge/{charge["id"]}/delete">
            {csrf_input(user)}
            <button class="small danger" type="submit">Delete</button>
        </form>
        """
    service_period = ""
    if charge["service_start"] or charge["service_end"]:
        service_period = f'<span>{esc(charge["service_start"] or "?")} to {esc(charge["service_end"] or "?")}</span>'
    return f"""
    <article class="item-card">
        <div class="item-top">
            <div>
                <h3>{esc(charge["title"])}</h3>
                <p>{esc(month_label(charge["month"]))} · {esc(CHARGE_TYPES.get(charge["charge_type"], charge["charge_type"]))}</p>
            </div>
            {status_pill(charge["paid"])}
        </div>
        <dl class="compact-list">
            <div><dt>Amount</dt><dd>{money(charge["amount"])}</dd></div>
            <div><dt>Due</dt><dd>{esc(charge["due_date"] or "Not set")}</dd></div>
        </dl>
        <div class="meta-line">{service_period}<span>{esc(charge["notes"] or "")}</span></div>
        <div class="files">{tenancy_badge(charge["tenancy_id"])}</div>
        <div class="files">{attachment_links(charge["id"], "charge")}</div>
        <div class="card-actions">{admin_actions}</div>
    </article>
    """


def table_empty(message: str) -> str:
    return f'<div class="empty"><strong>{esc(message)}</strong><span>Once you add data, it will show up here.</span></div>'


def sparkline_svg(values: list[float]) -> str:
    if not values:
        return '<div class="spark-empty">No trend yet</div>'
    if len(values) == 1:
        points = "8,42 172,42"
    else:
        low = min(values)
        high = max(values)
        span = high - low or 1
        points_list = []
        for index, value in enumerate(values):
            x = 8 + (164 * index / (len(values) - 1))
            y = 62 - ((value - low) / span * 48)
            points_list.append(f"{x:.1f},{y:.1f}")
        points = " ".join(points_list)
    return f"""
    <svg class="sparkline" viewBox="0 0 180 72" role="img" aria-label="six month utility trend">
        <path d="M8 62H172" />
        <polyline points="{points}" />
    </svg>
    """


def utility_insight_cards(user: sqlite3.Row) -> str:
    tenancy_ids = visible_tenancy_ids(user)
    if tenancy_ids == []:
        rows = []
    elif tenancy_ids is None:
        rows = query_all("SELECT utility_type, month, bill_amount, consumption FROM utility_entries ORDER BY month ASC, id ASC")
    else:
        placeholders = ",".join("?" for _ in tenancy_ids)
        rows = query_all(
            f"SELECT utility_type, month, bill_amount, consumption FROM utility_entries WHERE tenancy_id IN ({placeholders}) ORDER BY month ASC, id ASC",
            tuple(tenancy_ids),
        )
    by_type: dict[str, list[sqlite3.Row]] = {key: [] for key in UTILITY_TYPES}
    for row in rows:
        by_type.setdefault(row["utility_type"], []).append(row)
    cards = []
    for key, label in UTILITY_TYPES.items():
        items = by_type.get(key, [])[-6:]
        values = [float(row["bill_amount"] or 0) for row in items]
        latest = items[-1] if items else None
        previous = items[-2] if len(items) > 1 else None
        delta_text = "Add a bill to start tracking."
        delta_class = "neutral"
        if latest and previous:
            delta = float(latest["bill_amount"] or 0) - float(previous["bill_amount"] or 0)
            delta_text = f"{'+' if delta > 0 else ''}{delta:,.2f} RON vs previous"
            delta_class = "up" if delta > 0 else "down" if delta < 0 else "neutral"
        elif latest:
            delta_text = f"Latest: {money(latest['bill_amount'])}"
        cards.append(
            f"""
            <article class="insight-card">
                <div class="insight-top">
                    <div>
                        <span class="utility-dot {esc(key)}"></span>
                        <h3>{esc(label)}</h3>
                    </div>
                    <span class="trend {delta_class}">{esc(delta_text)}</span>
                </div>
                {sparkline_svg(values)}
                <div class="insight-meta">
                    <span>{len(items)} month{"s" if len(items) != 1 else ""}</span>
                    <span>{esc(month_label(latest["month"])) if latest else "No data yet"}</span>
                </div>
            </article>
            """
        )
    return "".join(cards)


def auth_user(headers: Any) -> sqlite3.Row | None:
    cookie_header = headers.get("Cookie", "")
    cookie = SimpleCookie(cookie_header)
    if "session" not in cookie:
        return None
    raw_token = cookie["session"].value
    session_hash = token_hash(raw_token)
    with get_db() as db:
        row = db.execute(
            """
            SELECT users.*, sessions.csrf_token, sessions.expires_at
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ? AND users.active = 1
            """,
            (session_hash,),
        ).fetchone()
        if not row:
            return None
        try:
            expires_at = datetime.fromisoformat(row["expires_at"])
        except ValueError:
            return None
        if expires_at < datetime.utcnow():
            db.execute("DELETE FROM sessions WHERE token_hash = ?", (session_hash,))
            return None
        return row


def create_session(user_id: int) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    expires = datetime.utcnow() + timedelta(days=SESSION_DAYS)
    execute(
        """
        INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (token_hash(token), user_id, csrf, now_iso(), expires.replace(microsecond=0).isoformat()),
    )
    return token, csrf


def prune_attempts(key: str, timestamp: float) -> list[float]:
    attempts = [value for value in LOGIN_ATTEMPTS.get(key, []) if timestamp - value < LOGIN_WINDOW_SECONDS]
    if attempts:
        LOGIN_ATTEMPTS[key] = attempts
    else:
        LOGIN_ATTEMPTS.pop(key, None)
    return attempts


def login_limited(ip_address: str, email: str) -> bool:
    timestamp = datetime.utcnow().timestamp()
    ip_attempts = prune_attempts(f"ip:{ip_address}", timestamp)
    account_attempts = prune_attempts(f"account:{ip_address}:{email.lower()}", timestamp)
    return len(ip_attempts) >= LOGIN_MAX_IP_ATTEMPTS or len(account_attempts) >= LOGIN_MAX_ACCOUNT_ATTEMPTS


def record_failed_login(ip_address: str, email: str) -> None:
    timestamp = datetime.utcnow().timestamp()
    for key in (f"ip:{ip_address}", f"account:{ip_address}:{email.lower()}"):
        attempts = prune_attempts(key, timestamp)
        attempts.append(timestamp)
        LOGIN_ATTEMPTS[key] = attempts


def clear_failed_login(ip_address: str, email: str) -> None:
    LOGIN_ATTEMPTS.pop(f"account:{ip_address}:{email.lower()}", None)


def require_admin(handler: "ChirieHandler") -> bool:
    if not handler.user:
        redirect(handler, "/login")
        return False
    if handler.user["role"] != "admin":
        handler.render("Not allowed", "<div class='empty'><strong>Admin only.</strong><span>This area is reserved for the apartment admin.</span></div>", HTTPStatus.FORBIDDEN)
        return False
    return True


class ChirieHandler(BaseHTTPRequestHandler):
    server_version = "CeahlauRental"
    sys_version = ""
    user: sqlite3.Row | None = None

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {format_date_time(datetime.now().timestamp())} - {fmt % args}")

    def client_ip(self) -> str:
        forwarded_for = self.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            return forwarded_for.split(",", 1)[0].strip()
        return self.client_address[0]

    def do_GET(self) -> None:
        self.user = auth_user(self.headers)
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/static/app.css":
            return self.serve_static("static/app.css", "text/css; charset=utf-8")
        if path == "/static/app.js":
            return self.serve_static("static/app.js", "application/javascript; charset=utf-8")
        if path.startswith("/attachments/"):
            return self.serve_attachment(path)
        if path == "/login":
            return self.login_page()
        if not self.user:
            return redirect(self, "/login")
        routes = {
            "/": self.dashboard,
            "/dashboard": self.dashboard,
            "/history": self.history,
            "/admin/users": self.users_page,
            "/admin/tenancies": self.tenancies_page,
            "/admin/tenancies/new": self.tenancy_form,
            "/admin/settings": self.settings_page,
            "/admin/utility/new": self.utility_form,
            "/admin/charge/new": self.charge_form,
        }
        if path in routes:
            return routes[path]()
        if path.startswith("/admin/utility/") and path.endswith("/edit"):
            return self.utility_form(path.split("/")[3])
        if path.startswith("/admin/charge/") and path.endswith("/edit"):
            return self.charge_form(path.split("/")[3])
        if path.startswith("/admin/tenancies/") and path.endswith("/edit"):
            return self.tenancy_form(path.split("/")[3])
        self.not_found()

    def do_POST(self) -> None:
        self.user = auth_user(self.headers)
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/login":
            fields, _ = self.parse_form()
            return self.login_post(fields)
        if not self.user:
            return redirect(self, "/login")
        fields, files = self.parse_form()
        if fields.get("csrf_token") != self.user["csrf_token"]:
            return self.render("Invalid request", "<div class='empty'><strong>Session check failed.</strong><span>Please go back and try again.</span></div>", HTTPStatus.FORBIDDEN)
        if path == "/logout":
            return self.logout()
        if path == "/admin/users":
            return self.create_user(fields)
        if path == "/admin/tenancies":
            return self.save_tenancy(fields)
        if path.startswith("/admin/tenancies/") and path.endswith("/edit"):
            return self.save_tenancy(fields, path.split("/")[3])
        if path == "/admin/settings":
            return self.save_settings(fields)
        if path.startswith("/admin/users/") and path.endswith("/toggle"):
            return self.toggle_user(path.split("/")[3])
        if path == "/admin/utility":
            return self.save_utility(fields, files)
        if path.startswith("/admin/utility/") and path.endswith("/edit"):
            return self.save_utility(fields, files, path.split("/")[3])
        if path.startswith("/admin/utility/") and path.endswith("/toggle-paid"):
            return self.toggle_utility_paid(path.split("/")[3])
        if path.startswith("/admin/utility/") and path.endswith("/delete"):
            return self.delete_utility(path.split("/")[3])
        if path == "/admin/charge":
            return self.save_charge(fields, files)
        if path.startswith("/admin/charge/") and path.endswith("/edit"):
            return self.save_charge(fields, files, path.split("/")[3])
        if path.startswith("/admin/charge/") and path.endswith("/toggle-paid"):
            return self.toggle_charge_paid(path.split("/")[3])
        if path.startswith("/admin/charge/") and path.endswith("/delete"):
            return self.delete_charge(path.split("/")[3])
        self.not_found()

    def render(self, title: str, content: str, status: int = 200, active: str = "") -> None:
        body = layout(title, self.user, content, active)
        static_response(self, body, "text/html; charset=utf-8", status)

    def not_found(self) -> None:
        self.render("Not found", "<div class='empty'><strong>That page does not exist.</strong><span>Try the dashboard.</span></div>", HTTPStatus.NOT_FOUND)

    def parse_form(self) -> tuple[dict[str, str], list[dict[str, Any]]]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        content_type = self.headers.get("Content-Type", "")
        if length > MAX_UPLOAD_BYTES + 1024 * 1024:
            return {}, []
        if content_type.startswith("multipart/form-data"):
            fs = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": content_type,
                    "CONTENT_LENGTH": str(length),
                },
                keep_blank_values=True,
            )
            fields: dict[str, str] = {}
            files: list[dict[str, Any]] = []
            for key in fs:
                item = fs[key]
                items = item if isinstance(item, list) else [item]
                for part in items:
                    if part.filename:
                        original = Path(part.filename).name
                        payload = part.file.read(MAX_UPLOAD_BYTES + 1)
                        if payload:
                            files.append(
                                {
                                    "field": key,
                                    "original_name": original,
                                    "content_type": part.type or mimetypes.guess_type(original)[0] or "application/octet-stream",
                                    "data": payload,
                                }
                            )
                    else:
                        fields[key] = part.value
            return fields, files
        raw = self.rfile.read(length).decode("utf-8")
        parsed = parse_qs(raw, keep_blank_values=True)
        return {key: values[-1] for key, values in parsed.items()}, []

    def serve_static(self, file_path: str, content_type: str) -> None:
        path = Path(file_path)
        if not path.exists():
            return self.not_found()
        static_response(self, path.read_bytes(), content_type)

    def serve_attachment(self, path: str) -> None:
        if not self.user:
            return redirect(self, "/login")
        try:
            attachment_id = int(path.rsplit("/", 1)[1])
        except ValueError:
            return self.not_found()
        row = query_one("SELECT * FROM attachments WHERE id = ?", (attachment_id,))
        if not row:
            return self.not_found()
        if self.user["role"] != "admin":
            tenancy_ids = visible_tenancy_ids(self.user)
            if not tenancy_ids:
                return self.not_found()
            allowed = False
            if row["utility_entry_id"]:
                linked = query_one("SELECT tenancy_id FROM utility_entries WHERE id = ?", (row["utility_entry_id"],))
                allowed = bool(linked and linked["tenancy_id"] in tenancy_ids)
            if row["charge_id"]:
                linked = query_one("SELECT tenancy_id FROM charges WHERE id = ?", (row["charge_id"],))
                allowed = bool(linked and linked["tenancy_id"] in tenancy_ids)
            if not allowed:
                return self.not_found()
        stored = UPLOAD_DIR / row["stored_name"]
        if not stored.exists():
            return self.not_found()
        content_type = row["content_type"] or mimetypes.guess_type(row["original_name"])[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        send_security_headers(self)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(stored.stat().st_size))
        self.send_header("Content-Disposition", f'inline; filename="{quote(row["original_name"])}"')
        self.send_header("Cache-Control", "private, max-age=3600")
        self.end_headers()
        with stored.open("rb") as handle:
            shutil.copyfileobj(handle, self.wfile)

    def login_page(self, message: str = "", status: int = 200) -> None:
        if self.user:
            return redirect(self, "/dashboard")
        content = f"""
        <section class="login-wrap">
            <div class="login-panel">
                <div class="login-copy">
                    <div class="login-brand"><span class="brand-mark large">43</span><strong>{esc(APARTMENT_NAME)}</strong></div>
                    <p class="eyebrow">Apartment rental management</p>
                    <h1>Apartment rental management.</h1>
                    <p>Rent, utilities, readings, tenant periods, bill files, and payment status for {esc(APARTMENT_NAME)}.</p>
                    <div class="login-proof">
                        <span>Readings</span>
                        <span>Bills</span>
                        <span>Tenancies</span>
                    </div>
                </div>
                <form class="login-card" method="post" action="/login">
                    <h2>Sign in</h2>
                    {flash(message, "error") if message else ""}
                    <label>Email<input name="email" type="email" autocomplete="email" placeholder="you@example.com" required autofocus></label>
                    <label>Password<input name="password" type="password" autocomplete="current-password" placeholder="Your password" required></label>
                    <button class="full" type="submit">Enter dashboard</button>
                    <p class="hint">Admin access is created from your deployment environment.</p>
                </form>
            </div>
        </section>
        """
        static_response(self, layout("Sign in", None, content), "text/html; charset=utf-8", status)

    def login_post(self, fields: dict[str, str]) -> None:
        email = fields.get("email", "").strip()
        password = fields.get("password", "")
        ip_address = self.client_ip()
        if login_limited(ip_address, email):
            return self.login_page("Too many login attempts. Please wait a few minutes before trying again.", HTTPStatus.TOO_MANY_REQUESTS)
        row = query_one("SELECT * FROM users WHERE email = ? AND active = 1", (email,))
        if not row or not verify_password(password, row["password_hash"]):
            record_failed_login(ip_address, email)
            return self.login_page("Email or password is wrong.")
        clear_failed_login(ip_address, email)
        token, _ = create_session(row["id"])
        self.send_response(HTTPStatus.SEE_OTHER)
        send_security_headers(self)
        self.send_header("Location", "/dashboard")
        self.send_header("Set-Cookie", make_cookie("session", token, SESSION_DAYS * 86400))
        self.end_headers()

    def logout(self) -> None:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        if "session" in cookie:
            execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(cookie["session"].value),))
        self.send_response(HTTPStatus.SEE_OTHER)
        send_security_headers(self)
        self.send_header("Location", "/login")
        self.send_header("Set-Cookie", make_cookie("session", "", 0))
        self.end_headers()

    def dashboard(self) -> None:
        ensure_recurring_rent()
        tenancy_ids = visible_tenancy_ids(self.user)
        if tenancy_ids == []:
            unpaid_utilities = []
            unpaid_charges = []
            month_utilities = []
            total_due = 0.0
            paid_total = 0.0
        else:
            scope = ""
            params: tuple = ()
            if tenancy_ids is not None:
                placeholders = ",".join("?" for _ in tenancy_ids)
                scope = f" AND tenancy_id IN ({placeholders})"
                params = tuple(tenancy_ids)
            unpaid_utilities = query_all(f"SELECT * FROM utility_entries WHERE paid = 0{scope} ORDER BY month DESC, id DESC", params)
            unpaid_charges = query_all(f"SELECT * FROM charges WHERE paid = 0{scope} ORDER BY month DESC, id DESC", params)
            month_utilities = query_all(f"SELECT * FROM utility_entries WHERE month = ?{scope} ORDER BY utility_type", (current_month(),) + params)
            totals = query_one(
                f"""
                SELECT
                    COALESCE((SELECT SUM(bill_amount) FROM utility_entries WHERE paid = 0{scope}), 0) AS utilities_due,
                    COALESCE((SELECT SUM(amount) FROM charges WHERE paid = 0{scope}), 0) AS charges_due,
                    COALESCE((SELECT SUM(bill_amount) FROM utility_entries WHERE paid = 1{scope}), 0) AS utilities_paid,
                    COALESCE((SELECT SUM(amount) FROM charges WHERE paid = 1{scope}), 0) AS charges_paid
                """,
                params * 4,
            )
            total_due = float(totals["utilities_due"]) + float(totals["charges_due"])
            paid_total = float(totals["utilities_paid"]) + float(totals["charges_paid"])
        actions = ""
        if self.user["role"] == "admin":
            actions = '<a class="button" href="/admin/utility/new">Add utility bill</a><a class="button secondary" href="/admin/settings">Rent settings</a><a class="button ghost" href="/admin/charge/new">Add one-off charge</a>'
        due_cards = "".join(charge_card(row, self.user) for row in unpaid_charges) + "".join(utility_card(row, self.user) for row in unpaid_utilities)
        month_cards = "".join(utility_card(row, self.user) for row in month_utilities)
        rent_amount = parse_float(get_setting("rent_amount", "0"), 0)
        rent_due_day = parse_int(get_setting("rent_due_day", "1")) or 1
        content = f"""
        {page_header(APARTMENT_NAME, "A clean monthly view of what is owed, what is recorded, and how utilities are moving.", actions)}
        <section class="stats-grid">
            <div class="stat"><span>Currently due</span><strong>{money(total_due)}</strong><small>Rent + utilities awaiting payment</small></div>
            <div class="stat"><span>Paid total</span><strong>{money(paid_total)}</strong><small>All recorded paid entries</small></div>
            <div class="stat"><span>Rent rule</span><strong>{money(rent_amount)}</strong><small>Due on day {rent_due_day} every month</small></div>
        </section>
        <section class="dashboard-grid">
            <div class="section-block primary-section">
                <div class="section-title"><h2>Needs payment</h2><p>{len(unpaid_utilities) + len(unpaid_charges)} open item{"s" if len(unpaid_utilities) + len(unpaid_charges) != 1 else ""}; only admin can mark them paid.</p></div>
                <div class="cards-grid due-grid">{due_cards or table_empty("Nothing due right now.")}</div>
            </div>
            <aside class="month-panel">
                <div class="section-title compact-title"><h2>This month</h2><p>{esc(month_label(current_month()))}</p></div>
                <div class="mini-list">{month_cards or table_empty("No utility bills recorded for this month.")}</div>
            </aside>
        </section>
        <section class="section-block">
            <div class="section-title"><h2>Utility trends</h2><p>Six-month bill movement by category, so tenants can understand the pattern without digging through tables.</p></div>
            <div class="insights-grid">{utility_insight_cards(self.user)}</div>
        </section>
        """
        self.render(APARTMENT_NAME, content, active="dashboard")

    def history(self) -> None:
        tenancy_ids = visible_tenancy_ids(self.user)
        if tenancy_ids == []:
            utilities = []
            charges = []
        elif tenancy_ids is None:
            utilities = query_all("SELECT * FROM utility_entries ORDER BY month DESC, id DESC")
            charges = query_all("SELECT * FROM charges ORDER BY month DESC, id DESC")
        else:
            placeholders = ",".join("?" for _ in tenancy_ids)
            utilities = query_all(f"SELECT * FROM utility_entries WHERE tenancy_id IN ({placeholders}) ORDER BY month DESC, id DESC", tuple(tenancy_ids))
            charges = query_all(f"SELECT * FROM charges WHERE tenancy_id IN ({placeholders}) ORDER BY month DESC, id DESC", tuple(tenancy_ids))
        utility_rows = "".join(
            f"""
            <tr>
                <td>{esc(month_label(row["month"]))}</td>
                <td>{esc(UTILITY_TYPES.get(row["utility_type"], row["utility_type"]))}</td>
                <td>{money(row["bill_amount"])}</td>
                <td>{esc("" if row["current_reading"] is None else f'{row["current_reading"]:g}')}</td>
                <td>{esc(READING_MODES.get(row["reading_mode"], "Actual reading"))}</td>
                <td>{tenancy_badge(row["tenancy_id"])}</td>
                <td>{status_pill(row["paid"])}</td>
                <td>{attachment_links(row["id"], "utility")}</td>
            </tr>
            """
            for row in utilities
        )
        charge_rows = "".join(
            f"""
            <tr>
                <td>{esc(month_label(row["month"]))}</td>
                <td>{esc(row["title"])}</td>
                <td>{money(row["amount"])}</td>
                <td>{esc(row["due_date"] or "")}</td>
                <td>{tenancy_badge(row["tenancy_id"])}</td>
                <td>{status_pill(row["paid"])}</td>
                <td>{attachment_links(row["id"], "charge")}</td>
            </tr>
            """
            for row in charges
        )
        content = f"""
        {page_header("History", "All monthly readings, utility bills, rent, and extra charges.")}
        <section class="section-block">
            <div class="section-title"><h2>Utilities</h2><p>Electricity, gas, common bills and internet.</p></div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Month</th><th>Type</th><th>Amount</th><th>Reading</th><th>Mode</th><th>Tenancy</th><th>Status</th><th>Bill</th></tr></thead>
                    <tbody>{utility_rows or '<tr><td colspan="8">No utility history yet.</td></tr>'}</tbody>
                </table>
            </div>
        </section>
        <section class="section-block">
            <div class="section-title"><h2>Rent and charges</h2><p>Rent and any one-off apartment charges.</p></div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Month</th><th>Title</th><th>Amount</th><th>Due</th><th>Tenancy</th><th>Status</th><th>File</th></tr></thead>
                    <tbody>{charge_rows or '<tr><td colspan="7">No rent history yet.</td></tr>'}</tbody>
                </table>
            </div>
        </section>
        """
        self.render("History", content, active="history")

    def tenancies_page(self) -> None:
        if not require_admin(self):
            return
        rows = query_all(
            """
            SELECT tenancies.*, users.name AS tenant_name, users.email AS tenant_email
            FROM tenancies
            JOIN users ON users.id = tenancies.user_id
            ORDER BY COALESCE(tenancies.end_date, '9999-12-31') DESC, tenancies.start_date DESC
            """
        )
        table_rows = "".join(
            f"""
            <tr>
                <td><strong>{esc(row["label"])}</strong><span class="subtle">{esc(row["tenant_name"])} · {esc(row["tenant_email"])}</span></td>
                <td>{esc(row["start_date"])}</td>
                <td>{esc(row["end_date"] or "Active")}</td>
                <td>{esc("" if row["start_electricity"] is None else f'{row["start_electricity"]:g}')} / {esc("" if row["end_electricity"] is None else f'{row["end_electricity"]:g}')}</td>
                <td>{esc("" if row["start_gas"] is None else f'{row["start_gas"]:g}')} / {esc("" if row["end_gas"] is None else f'{row["end_gas"]:g}')}</td>
                <td><a class="button small ghost" href="/admin/tenancies/{row["id"]}/edit">Edit</a></td>
            </tr>
            """
            for row in rows
        )
        content = f"""
        {page_header("Tenancies", "Track who is responsible for each period, including move-in and move-out readings.", '<a class="button" href="/admin/tenancies/new">New tenancy</a>')}
        <section class="section-block">
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Tenant period</th><th>Start</th><th>End</th><th>Electricity start/end</th><th>Gas start/end</th><th></th></tr></thead>
                    <tbody>{table_rows or '<tr><td colspan="6">No tenancy periods yet.</td></tr>'}</tbody>
                </table>
            </div>
        </section>
        """
        self.render("Tenancies", content, active="tenancies")

    def tenancy_form(self, tenancy_id: str | None = None, error: str = "", values: dict[str, str] | None = None) -> None:
        if not require_admin(self):
            return
        tenancy = None
        if tenancy_id:
            tenancy = query_one("SELECT * FROM tenancies WHERE id = ?", (tenancy_id,))
            if not tenancy:
                return self.not_found()
        def field(name: str, default: Any = "") -> Any:
            if values is not None and name in values:
                return values[name]
            if tenancy and name in tenancy.keys():
                return tenancy[name]
            return default
        tenant_users = query_all("SELECT * FROM users WHERE role = 'tenant' ORDER BY name")
        selected_user = field("user_id", "")
        user_options = "".join(
            f'<option value="{user["id"]}" {"selected" if str(selected_user) == str(user["id"]) else ""}>{esc(user["name"])} · {esc(user["email"])}</option>'
            for user in tenant_users
        )
        title = "Edit tenancy" if tenancy else "New tenancy"
        action = f'/admin/tenancies/{tenancy["id"]}/edit' if tenancy else "/admin/tenancies"
        content = f"""
        {page_header(title, "Use tenancy periods to split responsibility cleanly when people move in or out.")}
        <form class="panel wide-form" method="post" action="{action}">
            {csrf_input(self.user)}
            {flash(error, "error") if error else ""}
            <div class="form-grid">
                <label>Tenant<select name="user_id" required>{user_options}</select></label>
                <label>Label<input name="label" value="{esc(field("label", "Current tenancy"))}" required></label>
                <label>Start date<input name="start_date" type="date" value="{esc(field("start_date", today()))}" required></label>
                <label>End date<input name="end_date" type="date" value="{esc(field("end_date", ""))}"></label>
                <label>Start electricity reading<input name="start_electricity" inputmode="decimal" value="{esc("" if field("start_electricity", "") is None else field("start_electricity", ""))}"></label>
                <label>End electricity reading<input name="end_electricity" inputmode="decimal" value="{esc("" if field("end_electricity", "") is None else field("end_electricity", ""))}"></label>
                <label>Start gas reading<input name="start_gas" inputmode="decimal" value="{esc("" if field("start_gas", "") is None else field("start_gas", ""))}"></label>
                <label>End gas reading<input name="end_gas" inputmode="decimal" value="{esc("" if field("end_gas", "") is None else field("end_gas", ""))}"></label>
            </div>
            <label>Notes<textarea name="notes" rows="3">{esc(field("notes", ""))}</textarea></label>
            <button type="submit">Save tenancy</button>
        </form>
        """
        self.render(title, content, active="tenancies")

    def save_tenancy(self, fields: dict[str, str], tenancy_id: str | None = None) -> None:
        if not require_admin(self):
            return
        parsed_id = parse_int(tenancy_id) if tenancy_id is not None else None
        if tenancy_id is not None and parsed_id is None:
            return self.not_found()
        user_id = parse_int(fields.get("user_id"))
        if user_id is None:
            return redirect(self, "/admin/tenancies")
        label = fields.get("label", "").strip() or "Tenancy"
        start_date = fields.get("start_date", today())
        end_date = fields.get("end_date", "")
        if end_date and end_date < start_date:
            return self.tenancy_form(tenancy_id, "End date cannot be before the start date.", fields)
        overlap_params: list[Any] = [user_id, end_date or "9999-12-31", start_date]
        overlap_sql = """
            SELECT id FROM tenancies
            WHERE user_id = ?
              AND start_date <= ?
              AND COALESCE(NULLIF(end_date, ''), '9999-12-31') >= ?
        """
        if parsed_id:
            overlap_sql += " AND id != ?"
            overlap_params.append(parsed_id)
        if query_one(overlap_sql, tuple(overlap_params)):
            return self.tenancy_form(tenancy_id, "This tenant already has an overlapping tenancy period.", fields)
        values = (
            user_id,
            label,
            start_date,
            end_date,
            None if fields.get("start_electricity", "") == "" else parse_float(fields.get("start_electricity")),
            None if fields.get("end_electricity", "") == "" else parse_float(fields.get("end_electricity")),
            None if fields.get("start_gas", "") == "" else parse_float(fields.get("start_gas")),
            None if fields.get("end_gas", "") == "" else parse_float(fields.get("end_gas")),
            fields.get("notes", "").strip(),
            now_iso(),
        )
        if parsed_id:
            execute(
                """
                UPDATE tenancies
                SET user_id = ?, label = ?, start_date = ?, end_date = ?, start_electricity = ?, end_electricity = ?,
                    start_gas = ?, end_gas = ?, notes = ?, updated_at = ?
                WHERE id = ?
                """,
                values + (parsed_id,),
            )
        else:
            execute(
                """
                INSERT INTO tenancies
                (user_id, label, start_date, end_date, start_electricity, end_electricity, start_gas, end_gas, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values[:-1] + (now_iso(), now_iso()),
            )
        redirect(self, "/admin/tenancies")

    def users_page(self) -> None:
        if not require_admin(self):
            return
        users = query_all("SELECT * FROM users ORDER BY role, name")
        rows = "".join(
            f"""
            <tr>
                <td><strong>{esc(user["name"])}</strong><span class="subtle">{esc(user["email"])}</span></td>
                <td>{role_badge(user["role"])}</td>
                <td>{'Active' if user["active"] else 'Disabled'}</td>
                <td>
                    <form method="post" action="/admin/users/{user["id"]}/toggle">
                        {csrf_input(self.user)}
                        <button class="small ghost" type="submit" {"disabled" if user["id"] == self.user["id"] else ""}>{'Disable' if user["active"] else 'Enable'}</button>
                    </form>
                </td>
            </tr>
            """
            for user in users
        )
        content = f"""
        {page_header("Users", "Create tenant logins and keep your admin account separate.")}
        <section class="two-column">
            <form class="panel" method="post" action="/admin/users">
                <h2>Create user</h2>
                {csrf_input(self.user)}
                <label>Name<input name="name" required></label>
                <label>Email<input name="email" type="email" required></label>
                <label>Password<input name="password" type="password" minlength="8" required></label>
                <label>Role
                    <select name="role">
                        <option value="tenant">Tenant</option>
                        <option value="admin">Admin</option>
                    </select>
                </label>
                <button type="submit">Create account</button>
            </form>
            <div class="panel">
                <h2>Existing users</h2>
                <div class="table-wrap compact">
                    <table><thead><tr><th>User</th><th>Role</th><th>Status</th><th></th></tr></thead><tbody>{rows}</tbody></table>
                </div>
            </div>
        </section>
        """
        self.render("Users", content, active="users")

    def settings_page(self) -> None:
        if not require_admin(self):
            return
        rent_amount = get_setting("rent_amount", "0")
        rent_due_day = get_setting("rent_due_day", "1")
        rent_enabled = get_setting("rent_enabled", "1") == "1"
        content = f"""
        {page_header("Settings", "Configure apartment-wide rules once and let the dashboard handle the monthly rhythm.")}
        <section class="two-column settings-layout">
            <form class="panel" method="post" action="/admin/settings">
                <h2>Recurring rent</h2>
                <p class="form-note">This creates one rent item for the current month automatically. After you mark it paid, next month's rent will appear as a fresh due item.</p>
                {csrf_input(self.user)}
                <label>Monthly rent (RON)<input name="rent_amount" inputmode="decimal" value="{esc(rent_amount)}" required></label>
                <label>Due day of month<input name="rent_due_day" type="number" min="1" max="31" value="{esc(rent_due_day)}" required></label>
                <label class="checkbox-row"><input name="rent_enabled" type="checkbox" value="1" {"checked" if rent_enabled else ""}> Enable recurring rent</label>
                <button type="submit">Save rent settings</button>
            </form>
            <div class="panel explain-panel">
                <h2>How it behaves</h2>
                <ul class="feature-list">
                    <li>Rent is generated from this rule, so you do not need to add it every month.</li>
                    <li>The due date is clamped safely for shorter months.</li>
                    <li>Existing paid rent records stay untouched for history.</li>
                    <li>If the current month's rent is still unpaid, saving settings updates its amount and due date.</li>
                </ul>
            </div>
        </section>
        """
        self.render("Settings", content, active="settings")

    def save_settings(self, fields: dict[str, str]) -> None:
        if not require_admin(self):
            return
        rent_amount = max(0, parse_float(fields.get("rent_amount"), 0))
        rent_due_day = max(1, min(parse_int(fields.get("rent_due_day")) or 1, 31))
        rent_enabled = "1" if fields.get("rent_enabled") == "1" else "0"
        set_setting("rent_amount", f"{rent_amount:.2f}")
        set_setting("rent_due_day", str(rent_due_day))
        set_setting("rent_enabled", rent_enabled)
        ensure_recurring_rent(update_unpaid=True)
        redirect(self, "/admin/settings")

    def create_user(self, fields: dict[str, str]) -> None:
        if not require_admin(self):
            return
        name = fields.get("name", "").strip()
        email = fields.get("email", "").strip()
        password = fields.get("password", "")
        role = fields.get("role", "tenant")
        if role not in ("admin", "tenant") or not name or not email or len(password) < 8:
            return redirect(self, "/admin/users")
        try:
            execute(
                "INSERT INTO users (name, email, password_hash, role, active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
                (name, email, password_hash(password), role, now_iso()),
            )
        except sqlite3.IntegrityError:
            pass
        redirect(self, "/admin/users")

    def toggle_user(self, user_id: str) -> None:
        if not require_admin(self):
            return
        try:
            uid = int(user_id)
        except ValueError:
            return self.not_found()
        if uid == self.user["id"]:
            return redirect(self, "/admin/users")
        execute("UPDATE users SET active = CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id = ?", (uid,))
        redirect(self, "/admin/users")

    def utility_form(self, entry_id: str | None = None, error: str = "", values: dict[str, str] | None = None) -> None:
        if not require_admin(self):
            return
        entry = None
        if entry_id:
            entry = query_one("SELECT * FROM utility_entries WHERE id = ?", (entry_id,))
            if not entry:
                return self.not_found()
        def field(name: str, default: Any = "") -> Any:
            if values is not None and name in values:
                return values[name]
            if entry and name in entry.keys():
                return entry[name]
            return default
        default_start, default_end = month_bounds(str(field("month", current_month())))
        default_tenancy = field("tenancy_id", "")
        if default_tenancy in ("", None):
            active = active_tenancy_for_date(default_end)
            default_tenancy = active["id"] if active else ""
        selected_utility = str(field("utility_type", "electricity"))
        default_previous = field("previous_reading", "")
        if default_previous in ("", None):
            default_previous = expected_previous_reading(
                selected_utility,
                parse_int(default_tenancy),
                str(field("service_start", default_start)),
                parse_int(entry_id),
            )
        utility_options = "".join(
            f'<option value="{key}" {"selected" if selected_utility == key else ""}>{esc(label)}</option>'
            for key, label in UTILITY_TYPES.items()
        )
        mode_options = "".join(
            f'<option value="{key}" {"selected" if str(field("reading_mode", "actual")) == key else ""}>{esc(label)}</option>'
            for key, label in READING_MODES.items()
        )
        title = "Edit utility bill" if entry else "Add utility bill"
        action = f'/admin/utility/{entry["id"]}/edit' if entry else "/admin/utility"
        content = f"""
        {page_header(title, "Record invoice periods, readings, adjustments, and who is responsible for the bill.")}
        <form class="panel wide-form" method="post" action="{action}" enctype="multipart/form-data">
            {csrf_input(self.user)}
            {flash(error, "error") if error else ""}
            <div class="form-grid">
                <label>Type<select name="utility_type">{utility_options}</select></label>
                <label>Tenant period<select name="tenancy_id">{tenancy_options(default_tenancy)}</select></label>
                <label>Month<input name="month" type="month" value="{esc(field("month", current_month()))}" required></label>
                <label>Invoice from<input name="service_start" type="date" value="{esc(field("service_start", default_start))}"></label>
                <label>Invoice to<input name="service_end" type="date" value="{esc(field("service_end", default_end))}"></label>
                <label>Reading type<select name="reading_mode">{mode_options}</select></label>
                <label>Previous reading<input name="previous_reading" inputmode="decimal" value="{esc("" if default_previous is None else default_previous)}"></label>
                <label>Current reading<input name="current_reading" inputmode="decimal" value="{esc("" if field("current_reading", "") is None else field("current_reading", ""))}"></label>
                <label>Rollover value<input name="rollover_limit" inputmode="decimal" value="{esc("" if field("rollover_limit", "") is None else field("rollover_limit", ""))}" placeholder="Example: 99999"></label>
                <label>Invoice adjustment / credit (RON)<input name="adjustment_amount" inputmode="decimal" value="{esc(field("adjustment_amount", "0"))}"></label>
                <label>Bill amount (RON)<input name="bill_amount" inputmode="decimal" value="{esc(field("bill_amount", ""))}" required></label>
                <label>Due date<input name="due_date" type="date" value="{esc(field("due_date", today()))}"></label>
            </div>
            <p class="form-note">Normal gas and electricity readings must go upward. The previous reading is filled from the last recorded index or the tenancy start reading; if an invoice corrects an estimate, gives a credit, rolls over, or closes a tenancy, choose the matching reading type.</p>
            <label>Notes<textarea name="notes" rows="3">{esc(field("notes", ""))}</textarea></label>
            <label>Bill photos or PDFs<input name="bill_files" type="file" accept=".jpg,.jpeg,.png,.webp,.pdf" multiple></label>
            <div class="paste-upload" tabindex="0" data-paste-upload>
                <strong>Paste screenshots here</strong>
                <span>Click this area, then paste a screen clipping from your clipboard. Pasted images will be attached to the bill.</span>
                <div class="paste-upload-list" data-paste-upload-list></div>
            </div>
            <div class="existing-files">{attachment_links(entry["id"], "utility") if entry else ""}</div>
            <button type="submit">Save utility bill</button>
        </form>
        """
        self.render(title, content, active="utility")

    def save_utility(self, fields: dict[str, str], files: list[dict[str, Any]], entry_id: str | None = None) -> None:
        if not require_admin(self):
            return
        parsed_entry_id = parse_int(entry_id) if entry_id is not None else None
        if entry_id is not None and parsed_entry_id is None:
            return self.not_found()
        utility_type = fields.get("utility_type", "")
        if utility_type not in UTILITY_TYPES:
            return redirect(self, "/admin/utility/new")
        month = fields.get("month", current_month())
        service_start = fields.get("service_start", "")
        service_end = fields.get("service_end", "")
        reference_date = service_end or fields.get("due_date", "") or due_date_for_month(month, 1)
        tenancy_id = resolve_tenancy_id(fields.get("tenancy_id"), reference_date)
        reading_mode = fields.get("reading_mode", "actual")
        if reading_mode not in READING_MODES:
            reading_mode = "actual"
        previous = fields.get("previous_reading", "")
        current = fields.get("current_reading", "")
        previous_value = None if previous == "" else parse_float(previous)
        current_value = None if current == "" else parse_float(current)
        expected_previous = expected_previous_reading(utility_type, tenancy_id, service_start, parsed_entry_id)
        if previous_value is None and expected_previous is not None:
            previous_value = expected_previous
        if (
            utility_type in ("electricity", "gas")
            and reading_mode in ("actual", "rollover", "final")
            and expected_previous is not None
            and not readings_match(previous_value, expected_previous)
        ):
            fields["previous_reading"] = "" if previous_value is None else f"{previous_value:g}"
            return self.utility_form(
                entry_id,
                f"Previous reading should match the last known index ({expected_previous:g}) for this meter. Use Correction / credit if this invoice intentionally breaks the chain.",
                fields,
            )
        rollover_limit = None if fields.get("rollover_limit", "") == "" else parse_float(fields.get("rollover_limit"))
        consumption, validation_error = calculate_consumption(utility_type, previous_value, current_value, reading_mode, rollover_limit)
        if validation_error:
            return self.utility_form(entry_id, validation_error, fields)
        adjustment_amount = parse_float(fields.get("adjustment_amount"), 0)
        bill_amount = parse_float(fields.get("bill_amount"), 0)
        due_date = fields.get("due_date", "")
        notes = fields.get("notes", "").strip()
        if entry_id:
            execute(
                """
                UPDATE utility_entries
                SET tenancy_id = ?, utility_type = ?, month = ?, service_start = ?, service_end = ?, reading_mode = ?,
                    previous_reading = ?, current_reading = ?, consumption = ?, rollover_limit = ?, adjustment_amount = ?,
                    bill_amount = ?, due_date = ?, notes = ?, updated_at = ?
                WHERE id = ?
                """,
                (tenancy_id, utility_type, month, service_start, service_end, reading_mode, previous_value, current_value, consumption, rollover_limit, adjustment_amount, bill_amount, due_date, notes, now_iso(), parsed_entry_id),
            )
            row_id = parsed_entry_id
        else:
            row_id = execute(
                """
                INSERT INTO utility_entries
                (tenancy_id, utility_type, month, service_start, service_end, reading_mode, previous_reading, current_reading,
                 consumption, rollover_limit, adjustment_amount, bill_amount, due_date, notes, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (tenancy_id, utility_type, month, service_start, service_end, reading_mode, previous_value, current_value, consumption, rollover_limit, adjustment_amount, bill_amount, due_date, notes, self.user["id"], now_iso(), now_iso()),
            )
        self.save_files(files, utility_entry_id=row_id)
        redirect(self, "/dashboard")

    def toggle_utility_paid(self, entry_id: str) -> None:
        if not require_admin(self):
            return
        parsed_entry_id = parse_int(entry_id)
        if parsed_entry_id is None:
            return self.not_found()
        execute(
            "UPDATE utility_entries SET paid = CASE paid WHEN 1 THEN 0 ELSE 1 END, paid_at = CASE paid WHEN 1 THEN NULL ELSE ? END, updated_at = ? WHERE id = ?",
            (now_iso(), now_iso(), parsed_entry_id),
        )
        redirect(self, "/dashboard")

    def delete_utility(self, entry_id: str) -> None:
        if not require_admin(self):
            return
        parsed_entry_id = parse_int(entry_id)
        if parsed_entry_id is None:
            return self.not_found()
        self.delete_attached_files("utility_entry_id", parsed_entry_id)
        execute("DELETE FROM utility_entries WHERE id = ?", (parsed_entry_id,))
        redirect(self, "/dashboard")

    def charge_form(self, charge_id: str | None = None) -> None:
        if not require_admin(self):
            return
        charge = None
        if charge_id:
            charge = query_one("SELECT * FROM charges WHERE id = ?", (charge_id,))
            if not charge:
                return self.not_found()
        charge_options = "".join(
            f'<option value="{key}" {"selected" if charge and charge["charge_type"] == key else ""}>{esc(label)}</option>'
            for key, label in CHARGE_TYPES.items()
        )
        default_start, default_end = month_bounds(charge["month"] if charge else current_month())
        title = "Edit charge" if charge else "Add one-off charge"
        action = f'/admin/charge/{charge["id"]}/edit' if charge else "/admin/charge"
        content = f"""
        {page_header(title, "Record one-off apartment costs. Monthly rent is best managed from Settings.")}
        <form class="panel wide-form" method="post" action="{action}" enctype="multipart/form-data">
            {csrf_input(self.user)}
            <div class="form-grid">
                <label>Type<select name="charge_type">{charge_options}</select></label>
                <label>Tenant period<select name="tenancy_id">{tenancy_options(charge["tenancy_id"] if charge else "")}</select></label>
                <label>Month<input name="month" type="month" value="{esc(charge["month"] if charge else current_month())}" required></label>
                <label>Charge from<input name="service_start" type="date" value="{esc(charge["service_start"] if charge and charge["service_start"] else default_start)}"></label>
                <label>Charge to<input name="service_end" type="date" value="{esc(charge["service_end"] if charge and charge["service_end"] else default_end)}"></label>
                <label>Title<input name="title" value="{esc(charge["title"] if charge else "One-off charge")}" required></label>
                <label>Amount (RON)<input name="amount" inputmode="decimal" value="{esc(charge["amount"] if charge else "")}" required></label>
                <label>Due date<input name="due_date" type="date" value="{esc(charge["due_date"] if charge else today())}"></label>
            </div>
            <label>Notes<textarea name="notes" rows="3">{esc(charge["notes"] if charge else "")}</textarea></label>
            <label>Receipt or related file<input name="bill_files" type="file" accept=".jpg,.jpeg,.png,.webp,.pdf" multiple></label>
            <div class="paste-upload" tabindex="0" data-paste-upload>
                <strong>Paste screenshots here</strong>
                <span>Click this area, then paste a screen clipping from your clipboard. Pasted images will be attached to the charge.</span>
                <div class="paste-upload-list" data-paste-upload-list></div>
            </div>
            <div class="existing-files">{attachment_links(charge["id"], "charge") if charge else ""}</div>
            <button type="submit">Save charge</button>
        </form>
        """
        self.render(title, content, active="charge")

    def save_charge(self, fields: dict[str, str], files: list[dict[str, Any]], charge_id: str | None = None) -> None:
        if not require_admin(self):
            return
        parsed_charge_id = parse_int(charge_id) if charge_id is not None else None
        if charge_id is not None and parsed_charge_id is None:
            return self.not_found()
        charge_type = fields.get("charge_type", "rent")
        if charge_type not in CHARGE_TYPES:
            charge_type = "rent"
        month = fields.get("month", current_month())
        service_start = fields.get("service_start", "")
        service_end = fields.get("service_end", "")
        tenancy_id = resolve_tenancy_id(fields.get("tenancy_id"), service_end or fields.get("due_date", "") or due_date_for_month(month, 1))
        title = fields.get("title", "Rent").strip() or "Rent"
        amount = parse_float(fields.get("amount"), 0)
        due_date = fields.get("due_date", "")
        notes = fields.get("notes", "").strip()
        if charge_id:
            execute(
                """
                UPDATE charges
                SET tenancy_id = ?, charge_type = ?, month = ?, service_start = ?, service_end = ?, title = ?, amount = ?, due_date = ?, notes = ?, updated_at = ?
                WHERE id = ?
                """,
                (tenancy_id, charge_type, month, service_start, service_end, title, amount, due_date, notes, now_iso(), parsed_charge_id),
            )
            row_id = parsed_charge_id
        else:
            row_id = execute(
                """
                INSERT INTO charges (tenancy_id, charge_type, month, service_start, service_end, title, amount, due_date, notes, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (tenancy_id, charge_type, month, service_start, service_end, title, amount, due_date, notes, self.user["id"], now_iso(), now_iso()),
            )
        self.save_files(files, charge_id=row_id)
        redirect(self, "/dashboard")

    def toggle_charge_paid(self, charge_id: str) -> None:
        if not require_admin(self):
            return
        parsed_charge_id = parse_int(charge_id)
        if parsed_charge_id is None:
            return self.not_found()
        execute(
            "UPDATE charges SET paid = CASE paid WHEN 1 THEN 0 ELSE 1 END, paid_at = CASE paid WHEN 1 THEN NULL ELSE ? END, updated_at = ? WHERE id = ?",
            (now_iso(), now_iso(), parsed_charge_id),
        )
        redirect(self, "/dashboard")

    def delete_charge(self, charge_id: str) -> None:
        if not require_admin(self):
            return
        parsed_charge_id = parse_int(charge_id)
        if parsed_charge_id is None:
            return self.not_found()
        self.delete_attached_files("charge_id", parsed_charge_id)
        execute("DELETE FROM charges WHERE id = ?", (parsed_charge_id,))
        redirect(self, "/dashboard")

    def delete_attached_files(self, column: str, row_id: int) -> None:
        if column not in ("utility_entry_id", "charge_id"):
            return
        files = query_all(f"SELECT stored_name FROM attachments WHERE {column} = ?", (row_id,))
        for file in files:
            try:
                (UPLOAD_DIR / file["stored_name"]).unlink(missing_ok=True)
            except OSError:
                pass

    def save_files(self, files: list[dict[str, Any]], utility_entry_id: int | None = None, charge_id: int | None = None) -> None:
        for upload in files:
            original = upload["original_name"]
            ext = Path(original).suffix.lower()
            data = upload["data"]
            if ext not in ALLOWED_EXTENSIONS or len(data) > MAX_UPLOAD_BYTES:
                continue
            stored_name = f"{secrets.token_hex(16)}{ext}"
            (UPLOAD_DIR / stored_name).write_bytes(data)
            execute(
                """
                INSERT INTO attachments
                (utility_entry_id, charge_id, original_name, stored_name, content_type, size, uploaded_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (utility_entry_id, charge_id, original, stored_name, upload["content_type"], len(data), now_iso()),
            )


def main() -> None:
    migrate()
    server = ThreadingHTTPServer((HOST, PORT), ChirieHandler)
    print(f"{APP_NAME} running on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
