import csv
import io
import os
import re
import secrets
import sqlite3
from datetime import date, datetime, timedelta
from functools import wraps

from flask import (Flask, abort, flash, g, jsonify, make_response, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("ACXIOMCRM_DB", os.path.join(BASE_DIR, "acxiomcrm.sqlite3"))
ROLES = ("Admin", "Manager", "Sales Executive")
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("ACXIOMCRM_SECRET", ""),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("ACXIOMCRM_HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=1_000_000,
)
if not app.config["SECRET_KEY"]:
    # Local development convenience. Set ACXIOMCRM_SECRET to a long random value in deployment.
    app.config["SECRET_KEY"] = secrets.token_hex(32)

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('Admin','Manager','Sales Executive')),
 active INTEGER NOT NULL DEFAULT 1, failed_logins INTEGER NOT NULL DEFAULT 0,
 lockout_until TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS customers (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL COLLATE NOCASE,
 phone TEXT NOT NULL, company TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '',
 city TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT '', status TEXT NOT NULL,
 owner_id INTEGER NOT NULL REFERENCES users(id), notes TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_customers_email ON customers(email);
CREATE UNIQUE INDEX IF NOT EXISTS ux_customers_phone ON customers(phone);
CREATE TABLE IF NOT EXISTS leads (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT NOT NULL,
 company TEXT NOT NULL DEFAULT '', source TEXT NOT NULL, status TEXT NOT NULL,
 priority TEXT NOT NULL, expected_value REAL NOT NULL DEFAULT 0,
 owner_id INTEGER NOT NULL REFERENCES users(id), notes TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL, converted_customer_id INTEGER REFERENCES customers(id)
);
CREATE TABLE IF NOT EXISTS opportunities (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, customer_id INTEGER REFERENCES customers(id),
 lead_id INTEGER REFERENCES leads(id), stage TEXT NOT NULL, amount REAL NOT NULL,
 probability INTEGER NOT NULL, close_date TEXT NOT NULL, status TEXT NOT NULL,
 owner_id INTEGER NOT NULL REFERENCES users(id), source TEXT NOT NULL DEFAULT '',
 notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS followups (
 id INTEGER PRIMARY KEY, related_type TEXT NOT NULL, related_id INTEGER NOT NULL,
 followup_date TEXT NOT NULL, subject TEXT NOT NULL, followup_type TEXT NOT NULL,
 status TEXT NOT NULL, assigned_id INTEGER NOT NULL REFERENCES users(id),
 notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS activities (
 id INTEGER PRIMARY KEY, activity_type TEXT NOT NULL, subject TEXT NOT NULL,
 description TEXT NOT NULL DEFAULT '', activity_date TEXT NOT NULL,
 customer_id INTEGER REFERENCES customers(id), lead_id INTEGER REFERENCES leads(id),
 assigned_id INTEGER NOT NULL REFERENCES users(id), status TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), action TEXT NOT NULL,
 entity_name TEXT NOT NULL, record_id TEXT, old_value TEXT, new_value TEXT,
 result TEXT NOT NULL, details TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
 ip_address TEXT
);
"""

COMMON_PHONE = re.compile(r"^\+?[0-9][0-9() .-]{7,18}[0-9]$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

# Each field definition drives the same simple form and its server-side validation.
MODULES = {
    "customers": {
        "title": "Customers", "singular": "Customer", "owner": "owner_id",
        "search": ["name", "email", "phone", "company"],
        "fields": [
            ("name", "Customer name", "text", True, 120),
            ("email", "Email", "email", True, 160),
            ("phone", "Phone", "tel", True, 20),
            ("company", "Company", "text", False, 120),
            ("address", "Address", "text", False, 240),
            ("city", "City", "text", False, 80),
            ("state", "State", "text", False, 80),
            ("status", "Status", "select", True, ["Active", "Inactive", "Prospect"]),
            ("owner_id", "Assigned executive", "user", True, None),
            ("notes", "Notes", "textarea", False, 2000),
        ],
        "columns": [("name", "Customer"), ("company", "Company"), ("email", "Email"),
                    ("phone", "Phone"), ("status", "Status"), ("owner_name", "Owner"), ("created_at", "Created")],
    },
    "leads": {
        "title": "Leads", "singular": "Lead", "owner": "owner_id",
        "search": ["name", "company", "status", "email", "phone"],
        "fields": [
            ("name", "Lead name", "text", True, 120), ("email", "Email", "email", True, 160),
            ("phone", "Phone", "tel", True, 20), ("company", "Company", "text", False, 120),
            ("source", "Source", "select", True, ["Website", "Referral", "Event", "Cold call", "Other"]),
            ("status", "Status", "select", True, ["New", "Contacted", "Qualified", "Unqualified", "Converted", "Lost"]),
            ("priority", "Priority", "select", True, ["Low", "Normal", "High"]),
            ("expected_value", "Expected value", "number", True, None),
            ("owner_id", "Assigned executive", "user", True, None),
            ("notes", "Notes", "textarea", False, 2000),
        ],
        "columns": [("name", "Lead"), ("company", "Company"), ("source", "Source"),
                    ("status", "Status"), ("priority", "Priority"), ("expected_value", "Expected value"), ("owner_name", "Owner")],
    },
    "opportunities": {
        "title": "Opportunities", "singular": "Opportunity", "owner": "owner_id",
        "search": ["o.name", "c.name", "o.stage", "o.status"],
        "fields": [
            ("name", "Opportunity name", "text", True, 140),
            ("customer_id", "Customer", "customer", False, None),
            ("lead_id", "Related lead", "lead", False, None),
            ("stage", "Stage", "select", True, ["Qualification", "Proposal", "Negotiation", "Won", "Lost"]),
            ("amount", "Amount (₹)", "number", True, None),
            ("probability", "Probability (%)", "number", True, None),
            ("close_date", "Expected close date", "date", True, None),
            ("status", "Status", "select", True, ["Open", "Won", "Lost"]),
            ("owner_id", "Owner", "user", True, None),
            ("source", "Source", "text", False, 100),
            ("notes", "Notes", "textarea", False, 2000),
        ],
        "columns": [("name", "Opportunity"), ("customer_name", "Customer"), ("stage", "Stage"),
                    ("amount", "Amount"), ("probability", "Probability"), ("close_date", "Close date"),
                    ("status", "Status"), ("owner_name", "Owner")],
    },
    "followups": {
        "title": "Follow-ups", "singular": "Follow-up", "owner": "assigned_id",
        "search": ["f.subject", "f.status", "f.followup_type", "c.name", "l.name"],
        "fields": [
            ("related", "Related record", "related", True, None),
            ("followup_date", "Follow-up date", "date", True, None),
            ("subject", "Subject", "text", True, 140),
            ("followup_type", "Type", "select", True, ["Call", "Meeting", "Email", "Task"]),
            ("status", "Status", "select", True, ["Planned", "Completed", "Missed", "Cancelled"]),
            ("assigned_id", "Assigned user", "user", True, None),
            ("notes", "Notes", "textarea", False, 2000),
        ],
        "columns": [("subject", "Subject"), ("related_label", "Related record"), ("followup_date", "Date"),
                    ("followup_type", "Type"), ("status", "Status"), ("owner_name", "Assigned to")],
    },
    "activities": {
        "title": "Activities", "singular": "Activity", "owner": "assigned_id",
        "search": ["a.subject", "a.activity_type", "a.status", "c.name", "l.name"],
        "fields": [
            ("activity_type", "Activity type", "select", True, ["Call", "Meeting", "Email", "Task"]),
            ("subject", "Subject", "text", True, 140),
            ("description", "Description", "textarea", False, 2000),
            ("activity_date", "Activity date", "date", True, None),
            ("customer_id", "Customer ID (optional)", "number", False, None),
            ("lead_id", "Lead ID (optional)", "number", False, None),
            ("assigned_id", "Assigned user", "user", True, None),
            ("status", "Status", "select", True, ["Planned", "Completed", "Cancelled"]),
        ],
        "columns": [("activity_type", "Type"), ("subject", "Subject"), ("activity_date", "Date"),
                    ("status", "Status"), ("owner_name", "Assigned to")],
    },
}


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db():
    connection = sqlite3.connect(DB_PATH)
    connection.executescript(SCHEMA)
    connection.commit()
    connection.close()


init_db()


def now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def current_user():
    if "user" not in g:
        user_id = session.get("user_id")
        g.user = db().execute("SELECT id,name,email,role,active FROM users WHERE id=?", (user_id,)).fetchone() if user_id else None
    return g.user


@app.before_request
def check_csrf():
    # JSON login cannot be submitted by a cross-site HTML form; it bootstraps the session token.
    if request.path == "/api/auth/login" and request.is_json:
        return None
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        expected = session.get("csrf_token", "")
        if not expected or not supplied or not secrets.compare_digest(str(expected), str(supplied)):
            if request.path.startswith("/api/"):
                return jsonify(error="csrf_failed", message="Please refresh the page and try again."), 400
            abort(400, description="The form expired. Please go back, refresh and try again.")


@app.context_processor
def template_context():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    user = current_user()
    overdue_count = 0
    if user:
        scope = "" if user["role"] in ("Admin", "Manager") else " AND assigned_id=?"
        params = (date.today().isoformat(), user["id"]) if scope else (date.today().isoformat(),)
        overdue_count = db().execute("SELECT COUNT(*) FROM followups WHERE status='Planned' AND date(followup_date)<date(?)" + scope, params).fetchone()[0]
    return {"current_user": user, "csrf_token": session["csrf_token"], "today": date.today().isoformat(), "current_time": now(), "overdue_count": overdue_count}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user or not user["active"]:
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify(error="unauthorized", message="Authentication is required."), 401
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user()["role"] not in roles:
                if request.path.startswith("/api/"):
                    return jsonify(error="forbidden", message="You do not have permission for this action."), 403
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def audit(action, entity, record_id=None, old=None, new=None, result="Success", details=""):
    user = current_user()
    db().execute(
        "INSERT INTO audit_log(user_id,action,entity_name,record_id,old_value,new_value,result,details,created_at,ip_address) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (user["id"] if user else None, action, entity, str(record_id) if record_id is not None else None,
         str(old)[:1000] if old is not None else None, str(new)[:1000] if new is not None else None,
         result, details[:500], now(), request.remote_addr),
    )
    db().commit()


def scope_clause(module, alias=""):
    user = current_user()
    if user["role"] == "Admin" or user["role"] == "Manager":
        return "1=1", []
    owner = MODULES[module]["owner"]
    col = f"{alias}.{owner}" if alias else owner
    return f"{col}=?", [user["id"]]


def module_query(module):
    if module == "customers":
        return "SELECT c.*,u.name AS owner_name FROM customers c JOIN users u ON u.id=c.owner_id", "c"
    if module == "leads":
        return "SELECT l.*,u.name AS owner_name FROM leads l JOIN users u ON u.id=l.owner_id", "l"
    if module == "opportunities":
        return "SELECT o.*,u.name AS owner_name,c.name AS customer_name FROM opportunities o JOIN users u ON u.id=o.owner_id LEFT JOIN customers c ON c.id=o.customer_id", "o"
    if module == "followups":
        return "SELECT f.*,u.name AS owner_name, CASE WHEN f.related_type='Customer' THEN (SELECT name FROM customers WHERE id=f.related_id) WHEN f.related_type='Lead' THEN (SELECT name FROM leads WHERE id=f.related_id) WHEN f.related_type='Opportunity' THEN (SELECT name FROM opportunities WHERE id=f.related_id) ELSE '' END AS related_label FROM followups f JOIN users u ON u.id=f.assigned_id", "f"
    return "SELECT a.*,u.name AS owner_name,c.name AS customer_name,l.name AS lead_name FROM activities a JOIN users u ON u.id=a.assigned_id LEFT JOIN customers c ON c.id=a.customer_id LEFT JOIN leads l ON l.id=a.lead_id", "a"


def visible_rows(module, search="", status="", sort="", direction="desc", overdue=False):
    base, alias = module_query(module)
    clause, params = scope_clause(module, alias)
    filters = [clause]
    if search:
        terms = MODULES[module]["search"]
        filters.append("(" + " OR ".join(f"{term} LIKE ?" for term in terms) + ")")
        params.extend([f"%{search}%"] * len(terms))
    if status and module in ("customers", "leads", "opportunities", "followups", "activities"):
        filters.append(f"{alias}.status=?")
        params.append(status)
    if overdue and module == "followups":
        filters.append("f.status='Planned' AND date(f.followup_date)<date(?)")
        params.append(date.today().isoformat())
    sort_columns = {
        "customers": {"name": "c.name", "company": "c.company", "email": "c.email", "status": "c.status", "owner_name": "owner_name", "created_at": "c.created_at"},
        "leads": {"name": "l.name", "company": "l.company", "source": "l.source", "status": "l.status", "priority": "l.priority", "expected_value": "l.expected_value", "owner_name": "owner_name"},
        "opportunities": {"name": "o.name", "customer_name": "customer_name", "stage": "o.stage", "amount": "o.amount", "probability": "o.probability", "close_date": "o.close_date", "status": "o.status", "owner_name": "owner_name"},
        "followups": {"subject": "f.subject", "related_label": "related_label", "followup_date": "f.followup_date", "followup_type": "f.followup_type", "status": "f.status", "owner_name": "owner_name"},
        "activities": {"activity_type": "a.activity_type", "subject": "a.subject", "activity_date": "a.activity_date", "status": "a.status", "owner_name": "owner_name"},
    }
    if sort in sort_columns[module]:
        order = sort_columns[module][sort] + (" ASC" if direction == "asc" else " DESC")
    else:
        order = {"customers": "c.created_at DESC", "leads": "l.created_at DESC", "opportunities": "o.close_date ASC", "followups": "f.followup_date ASC", "activities": "a.activity_date DESC"}[module]
    return db().execute(f"{base} WHERE {' AND '.join(filters)} ORDER BY {order}", params).fetchall()


def visible_record(module, record_id):
    base, alias = module_query(module)
    clause, params = scope_clause(module, alias)
    return db().execute(f"{base} WHERE {alias}.id=? AND {clause}", [record_id] + params).fetchone()


def valid_phone(value):
    if not COMMON_PHONE.fullmatch(value):
        return False
    digits = re.sub(r"\D", "", value)
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    return len(digits) == 10 and digits[0] in "6789"


def normalize_phone(value):
    digits = re.sub(r"\D", "", value)
    return "+91" + (digits[2:] if len(digits) == 12 and digits.startswith("91") else digits)


def field_options(field):
    if field == "user":
        users = db().execute("SELECT id,name,role FROM users WHERE active=1 ORDER BY name").fetchall()
        if current_user()["role"] == "Sales Executive":
            users = [row for row in users if row["id"] == current_user()["id"]]
        return [(str(row["id"]), f"{row['name']} ({row['role']})") for row in users]
    if field == "customer":
        rows = visible_rows("customers")
        return [(str(row["id"]), row["name"]) for row in rows]
    if field == "lead":
        rows = [row for row in visible_rows("leads") if row["status"] != "Converted"]
        return [(str(row["id"]), row["name"]) for row in rows]
    if field == "related":
        options = []
        for kind, module in (("Customer", "customers"), ("Lead", "leads"), ("Opportunity", "opportunities")):
            rows = visible_rows(module)
            for row in rows:
                label = row["name"] if "name" in row.keys() else row["subject"]
                options.append((f"{kind}:{row['id']}", f"{kind} · {label}"))
        return options
    return []


def form_fields(module, record=None):
    result = []
    for name, label, kind, required, extra in MODULES[module]["fields"]:
        value = record[name] if record is not None and name in record.keys() else ""
        if module == "followups" and name == "related" and record is not None:
            value = f"{record['related_type']}:{record['related_id']}"
        field = {"name": name, "label": label, "kind": "select" if kind == "related" else kind, "required": required, "value": value, "maxlength": extra if isinstance(extra, int) else None}
        if kind == "select":
            field["options"] = [(v, v) for v in extra]
        elif kind in ("user", "customer", "lead", "related"):
            field["options"] = field_options(kind)
        if kind == "date" and not value and module != "activities":
            field["min"] = date.today().isoformat()
        if kind == "number":
            field["step"] = "0.01" if name in ("amount", "expected_value") else "1"
        result.append(field)
    return result


def validate_form(module, form, record_id=None):
    errors, values = [], {}
    allowed = {item[0]: item for item in MODULES[module]["fields"]}
    for key, (_, label, kind, required, extra) in allowed.items():
        raw_value = form.get(key)
        raw = str(raw_value).strip() if raw_value is not None else ""
        if required and not raw:
            errors.append(f"{label} is required.")
            continue
        if len(raw) > 2000:
            errors.append(f"{label} is too long.")
            continue
        if not raw:
            values[key] = None if kind in ("user", "customer", "lead", "number") else ""
            continue
        if kind == "email":
            if not EMAIL_RE.fullmatch(raw) or len(raw) > 160:
                errors.append("Enter a valid email address.")
            values[key] = raw.lower()
        elif kind == "tel":
            if not valid_phone(raw):
                errors.append("Enter a valid phone number.")
            values[key] = normalize_phone(raw)
        elif kind == "number":
            try:
                number = float(raw)
                if not (number >= 0 and number < 1_000_000_000):
                    raise ValueError
                values[key] = int(number) if number.is_integer() else number
            except ValueError:
                errors.append(f"{label} must be a valid non-negative number.")
        elif kind == "date":
            try:
                parsed = date.fromisoformat(raw)
                if raw != parsed.isoformat():
                    raise ValueError
                values[key] = raw
            except ValueError:
                errors.append(f"Enter a valid {label.lower()}.")
        elif kind == "select":
            options = extra
            if raw not in options:
                errors.append(f"Choose a valid {label.lower()}.")
            values[key] = raw
        elif kind in ("user", "customer", "lead"):
            if kind == "user" and raw.isdigit() and current_user()["role"] == "Sales Executive" and int(raw) != current_user()["id"]:
                errors.append("You can only assign records to yourself.")
            exists = False
            if raw.isdigit():
                if kind == "user":
                    exists = bool(db().execute("SELECT id FROM users WHERE id=? AND active=1", (raw,)).fetchone())
                else:
                    exists = bool(visible_record("customers" if kind == "customer" else "leads", int(raw)))
            if not exists:
                errors.append(f"Choose a valid {label.lower()}.")
            values[key] = int(raw) if raw.isdigit() else None
        elif kind == "related":
            related_type, separator, related_id = raw.partition(":")
            related_module = {"Customer": "customers", "Lead": "leads", "Opportunity": "opportunities"}.get(related_type)
            if not separator or not related_id.isdigit() or not related_module or not visible_record(related_module, int(related_id)):
                errors.append("Choose an existing related record in your access scope.")
            else:
                values["related_type"] = related_type
                values["related_id"] = int(related_id)
        else:
            if isinstance(extra, int) and len(raw) > extra:
                errors.append(f"{label} must be {extra} characters or fewer.")
            values[key] = raw

    if module in ("customers", "leads"):
        phone = values.get("phone")
        email = values.get("email")
        if phone and email:
            for column, value, message in (("email", email, "A record with this email already exists."), ("phone", phone, "A record with this phone number already exists.")):
                query = f"SELECT id FROM {module} WHERE {column}=?"
                args = [value]
                if record_id:
                    query += " AND id!=?"
                    args.append(record_id)
                if db().execute(query, args).fetchone():
                    errors.append(message)
    if module == "opportunities":
        amount, probability, close_date = values.get("amount"), values.get("probability"), values.get("close_date")
        status, stage = values.get("status"), values.get("stage")
        if amount is not None and (amount <= 0 and status == "Open"):
            errors.append("Opportunity Amount must be greater than 0.")
        if probability is not None and not 0 <= probability <= 100:
            errors.append("Probability must be between 0 and 100.")
        if probability is not None and not float(probability).is_integer():
            errors.append("Probability must be between 0 and 100.")
        if close_date and close_date < date.today().isoformat() and status == "Open":
            errors.append("Expected Close Date cannot be in the past.")
        if stage == "Won":
            values["status"] = "Won"
        elif stage == "Lost":
            values["status"] = "Lost"
    if module == "followups" and values.get("status") == "Planned" and values.get("followup_date") and values["followup_date"] < date.today().isoformat():
        errors.append("Follow-up date cannot be earlier than today.")
    if module == "activities":
        if values.get("customer_id") and not visible_record("customers", values["customer_id"]):
            errors.append("Choose a valid customer.")
        if values.get("lead_id") and not visible_record("leads", values["lead_id"]):
            errors.append("Choose a valid lead.")
    if module == "followups":
        related_module = {"Customer": "customers", "Lead": "leads", "Opportunity": "opportunities"}.get(values.get("related_type"))
        if not related_module or not values.get("related_id") or not visible_record(related_module, values["related_id"]):
            errors.append("Select an existing related record ID.")
    return errors, values


def save_record(module, values, record_id=None):
    table = module
    fields = [item[0] for item in MODULES[module]["fields"]]
    if module == "followups":
        fields = ["related_type", "related_id"] + fields[1:]
    if module == "opportunities":
        values.setdefault("lead_id", None)
    if module == "activities":
        values.setdefault("customer_id", None)
        values.setdefault("lead_id", None)
    old = db().execute(f"SELECT * FROM {table} WHERE id=?", (record_id,)).fetchone() if record_id else None
    if record_id:
        updates = [*fields]
        if module == "leads" and old["status"] != values.get("status"):
            valid_transitions = {"New": {"Contacted", "Lost"}, "Contacted": {"Qualified", "Unqualified", "Lost"}, "Qualified": {"Converted", "Lost"}, "Unqualified": {"Contacted", "Lost"}, "Converted": set(), "Lost": set()}
            if values.get("status") != old["status"] and values.get("status") not in valid_transitions.get(old["status"], set()):
                raise ValueError(f"Cannot change a {old['status']} lead to {values.get('status')}.")
        if module == "leads" and old["status"] in ("Converted", "Lost") and values.get("status") != old["status"]:
            raise ValueError("A closed lead cannot be reopened.")
        db().execute(f"UPDATE {table} SET " + ",".join(f"{key}=?" for key in updates) + (",updated_at=?" if module == "customers" else "") + " WHERE id=?",
                     [values.get(key) for key in updates] + ([now()] if module == "customers" else []) + [record_id])
        audit("Update", MODULES[module]["singular"], record_id, dict(old), values)
    else:
        created = now()
        extras = ["created_at"]
        vals = [values.get(key) for key in fields]
        if module == "customers":
            extras.append("updated_at")
            vals.extend([created, created])
        else:
            vals.append(created)
        cols = fields + extras
        cursor = db().execute(f"INSERT INTO {table} (" + ",".join(cols) + ") VALUES (" + ",".join("?" for _ in cols) + ")", vals)
        record_id = cursor.lastrowid
        audit("Create", MODULES[module]["singular"], record_id, new=values)
    db().commit()
    return record_id


def delete_record(module, record_id):
    record = visible_record(module, record_id)
    if not record:
        abort(404)
    # Keep relationships intact; deactivation is the safe delete for customers and leads.
    if module == "customers":
        db().execute("UPDATE customers SET status='Inactive',updated_at=? WHERE id=?", (now(), record_id))
    elif module == "leads":
        db().execute("UPDATE leads SET status='Lost' WHERE id=?", (record_id,))
    elif module == "opportunities":
        db().execute("UPDATE opportunities SET status='Lost',stage='Lost' WHERE id=?", (record_id,))
    elif module == "followups":
        db().execute("UPDATE followups SET status='Cancelled' WHERE id=?", (record_id,))
    else:
        db().execute("DELETE FROM activities WHERE id=?", (record_id,))
    audit("Deactivate" if module != "activities" else "Delete", MODULES[module]["singular"], record_id, old=dict(record), new="inactive/deleted")
    db().commit()


@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user() else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        user = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user:
            audit("Login failed", "Authentication", result="Failure", details="Unknown email")
            flash("Email or password is incorrect.", "danger")
        elif user["lockout_until"] and user["lockout_until"] > now():
            audit("Login blocked", "Authentication", user["id"], result="Failure", details="Account is locked")
            flash("This account is temporarily locked. Try again later.", "danger")
        elif not user["active"]:
            audit("Login failed", "Authentication", user["id"], result="Failure", details="Inactive account")
            flash("This account is inactive. Contact an administrator.", "danger")
        elif not check_password_hash(user["password_hash"], password):
            failed = user["failed_logins"] + 1
            lock = (datetime.now().astimezone() + timedelta(minutes=15)).isoformat(timespec="seconds") if failed >= 5 else None
            db().execute("UPDATE users SET failed_logins=?,lockout_until=? WHERE id=?", (failed, lock, user["id"]))
            db().commit()
            audit("Login failed", "Authentication", user["id"], result="Failure", details="Invalid password" + ("; locked for 15 minutes" if lock else ""))
            flash("Email or password is incorrect." if not lock else "Too many attempts. This account is locked for 15 minutes.", "danger")
        else:
            db().execute("UPDATE users SET failed_logins=0,lockout_until=NULL WHERE id=?", (user["id"],))
            db().commit()
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            audit("Login", "Authentication", user["id"])
            target = request.args.get("next", "")
            return redirect(target if target.startswith("/") and not target.startswith("//") else url_for("dashboard"))
    return render_template("login.html", title="Sign in")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""
        errors = []
        if not name or len(name) > 120: errors.append("Name is required and must be 120 characters or fewer.")
        if not EMAIL_RE.fullmatch(email) or len(email) > 160: errors.append("Enter a valid email address.")
        if len(password) < 8 or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password): errors.append("Password must be at least 8 characters and include a letter and a number.")
        if password != confirm: errors.append("Passwords do not match.")
        if db().execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone(): errors.append("An account with this email already exists.")
        if errors:
            for error in errors: flash(error, "danger")
        else:
            role = "Admin" if db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0 else "Sales Executive"
            cur = db().execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                               (name, email, generate_password_hash(password), role, now()))
            db().commit()
            audit("Register", "User", cur.lastrowid, new=f"{email}; role={role}")
            flash("First account created as Admin." if role == "Admin" else "Your account is ready. An administrator can update your role if needed.", "success")
            return redirect(url_for("login"))
    return render_template("register.html", title="Create account")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    user_id = current_user()["id"]
    audit("Logout", "Authentication", user_id)
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


def dashboard_date_range():
    period = request.args.get("period", "all")
    today = date.today()
    start = end = None
    if period == "today":
        start = end = today.isoformat()
    elif period == "week":
        start, end = (today - timedelta(days=today.weekday())).isoformat(), today.isoformat()
    elif period == "month":
        start, end = today.replace(day=1).isoformat(), today.isoformat()
    elif period == "custom":
        raw_start, raw_end = request.args.get("start", ""), request.args.get("end", "")
        try:
            start = date.fromisoformat(raw_start).isoformat() if raw_start else None
            end = date.fromisoformat(raw_end).isoformat() if raw_end else None
            if start and end and start > end:
                start, end = end, start
        except ValueError:
            start = end = None
    else:
        period = "all"
    return period, start, end


def dashboard_stats(start_date=None, end_date=None):
    user = current_user()
    owner_sql, owner_params = ("", []) if user["role"] in ("Admin", "Manager") else (" AND owner_id=?", [user["id"]])
    date_sql, date_params = "", []
    if start_date:
        date_sql += " AND date(created_at)>=date(?)"
        date_params.append(start_date)
    if end_date:
        date_sql += " AND date(created_at)<=date(?)"
        date_params.append(end_date)
    counts = {}
    for key, query, params in [
        ("customers", f"SELECT COUNT(*) FROM customers WHERE status!='Inactive'{owner_sql}{date_sql}", owner_params + date_params),
        ("leads", f"SELECT COUNT(*) FROM leads WHERE 1=1{owner_sql}{date_sql}", owner_params + date_params),
        ("open_leads", f"SELECT COUNT(*) FROM leads WHERE status NOT IN ('Lost','Converted','Unqualified'){owner_sql}{date_sql}", owner_params + date_params),
        ("opportunities", f"SELECT COUNT(*) FROM opportunities WHERE 1=1{owner_sql}{date_sql}", owner_params + date_params),
        ("open_opportunities", f"SELECT COUNT(*) FROM opportunities WHERE status='Open'{owner_sql}{date_sql}", owner_params + date_params),
        ("won", f"SELECT COUNT(*) FROM opportunities WHERE status='Won'{owner_sql}{date_sql}", owner_params + date_params),
        ("lost", f"SELECT COUNT(*) FROM opportunities WHERE status='Lost'{owner_sql}{date_sql}", owner_params + date_params),
        ("pipeline", f"SELECT COALESCE(SUM(amount),0) FROM opportunities WHERE status='Open'{owner_sql}{date_sql}", owner_params + date_params),
    ]:
        counts[key] = db().execute(query, params).fetchone()[0]
    followup_scope = " AND assigned_id=?" if user["role"] == "Sales Executive" else ""
    followup_params = [user["id"]] if user["role"] == "Sales Executive" else []
    followup_dates = (" AND date(followup_date)>=date(?)" if start_date else "") + (" AND date(followup_date)<=date(?)" if end_date else "")
    counts["followups"] = db().execute("SELECT COUNT(*) FROM followups WHERE status='Planned'" + followup_scope + followup_dates, followup_params + date_params).fetchone()[0]
    leads = db().execute("SELECT status,COUNT(*) n FROM leads WHERE 1=1" + date_sql + " GROUP BY status", date_params).fetchall()
    opps = db().execute("SELECT stage,COUNT(*) n FROM opportunities WHERE 1=1" + date_sql + " GROUP BY stage", date_params).fetchall()
    if user["role"] == "Sales Executive":
        leads = db().execute("SELECT status,COUNT(*) n FROM leads WHERE owner_id=?" + date_sql + " GROUP BY status", [user["id"]] + date_params).fetchall()
        opps = db().execute("SELECT stage,COUNT(*) n FROM opportunities WHERE owner_id=?" + date_sql + " GROUP BY stage", [user["id"]] + date_params).fetchall()
    upcoming_start = max(date.today().isoformat(), start_date or date.today().isoformat())
    upcoming_end = end_date or (date.today() + timedelta(days=30)).isoformat()
    upcoming = db().execute("SELECT f.*, CASE WHEN related_type='Customer' THEN (SELECT name FROM customers WHERE id=related_id) WHEN related_type='Lead' THEN (SELECT name FROM leads WHERE id=related_id) ELSE (SELECT name FROM opportunities WHERE id=related_id) END related_name FROM followups f WHERE f.status='Planned' AND date(f.followup_date)>=date(?) AND date(f.followup_date)<=date(?) AND (? OR f.assigned_id=?) ORDER BY f.followup_date LIMIT 6",
                            (upcoming_start, upcoming_end, user["role"] != "Sales Executive", user["id"])).fetchall()
    sales_start = start_date or date.today().replace(day=1).isoformat()
    sales_end_sql = " AND date(close_date)<=date(?)" if end_date else ""
    sales_scope = " AND owner_id=?" if user["role"] == "Sales Executive" else ""
    sales_params = [sales_start] + ([end_date] if end_date else []) + ([user["id"]] if sales_scope else [])
    monthly = db().execute("SELECT substr(close_date,1,7) month,COALESCE(SUM(amount),0) amount FROM opportunities WHERE status='Won' AND date(close_date)>=date(?)" + sales_end_sql + sales_scope + " GROUP BY substr(close_date,1,7) ORDER BY month", sales_params).fetchall()
    return counts, leads, opps, upcoming, monthly


@app.route("/dashboard")
@login_required
def dashboard():
    period, start_date, end_date = dashboard_date_range()
    counts, leads, opps, upcoming, monthly = dashboard_stats(start_date, end_date)
    return render_template("dashboard.html", title="Dashboard", counts=counts, lead_chart=leads,
                           opp_chart=opps, upcoming=upcoming, monthly=monthly, period=period,
                           start_date=start_date or "", end_date=end_date or "")


@app.route("/<module>")
@login_required
def list_records(module):
    if module not in MODULES: abort(404)
    sort = request.args.get("sort", "")
    direction = "asc" if request.args.get("direction") == "asc" else "desc"
    overdue = request.args.get("overdue") == "1"
    records = visible_rows(module, request.args.get("q", "").strip(), request.args.get("status", "").strip(), sort, direction, overdue)
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 15
    total = len(records)
    records = records[(page - 1) * per_page:page * per_page]
    return render_template("records.html", title=MODULES[module]["title"], module=module,
                           config=MODULES[module], records=records, query=request.args.get("q", ""),
                           status=request.args.get("status", ""), page=page, sort=sort, direction=direction,
                           overdue=overdue, pages=max(1, (total + per_page - 1)//per_page), total=total)


@app.route("/<module>/new", methods=["GET", "POST"])
@login_required
def new_record(module):
    if module not in MODULES: abort(404)
    if current_user()["role"] == "Sales Executive" and module in ("users", "audit_log"): abort(403)
    errors = []
    if request.method == "POST":
        errors, values = validate_form(module, request.form)
        if not errors:
            try:
                new_id = save_record(module, values)
                flash(f"{MODULES[module]['singular']} created.", "success")
                return redirect(url_for("record_detail", module=module, record_id=new_id))
            except (sqlite3.IntegrityError, ValueError) as error:
                db().rollback()
                errors.append(str(error) if isinstance(error, ValueError) else "A matching record already exists or a related record is invalid.")
        for error in errors: flash(error, "danger")
    return render_template("form.html", title=f"New {MODULES[module]['singular']}", module=module,
                           config=MODULES[module], fields=form_fields(module), record=None)


@app.route("/<module>/<int:record_id>")
@login_required
def record_detail(module, record_id):
    if module not in MODULES: abort(404)
    record = visible_record(module, record_id)
    if not record: abort(404)
    history = db().execute("SELECT a.*,u.name user_name FROM audit_log a LEFT JOIN users u ON u.id=a.user_id WHERE a.entity_name=? AND a.record_id=? ORDER BY a.id DESC LIMIT 10", (MODULES[module]["singular"], str(record_id))).fetchall()
    return render_template("detail.html", title=f"{MODULES[module]['singular']} details", module=module,
                           config=MODULES[module], record=record, history=history)


@app.route("/<module>/<int:record_id>/edit", methods=["GET", "POST"])
@login_required
def edit_record(module, record_id):
    if module not in MODULES: abort(404)
    record = visible_record(module, record_id)
    if not record: abort(404)
    errors = []
    if request.method == "POST":
        errors, values = validate_form(module, request.form, record_id)
        if not errors:
            try:
                save_record(module, values, record_id)
                flash(f"{MODULES[module]['singular']} updated.", "success")
                return redirect(url_for("record_detail", module=module, record_id=record_id))
            except (sqlite3.IntegrityError, ValueError) as error:
                db().rollback()
                errors.append(str(error) if isinstance(error, ValueError) else "A related record is invalid.")
        for error in errors: flash(error, "danger")
    return render_template("form.html", title=f"Edit {MODULES[module]['singular']}", module=module,
                           config=MODULES[module], fields=form_fields(module, record), record=record)


@app.route("/<module>/<int:record_id>/delete", methods=["POST"])
@login_required
def remove_record(module, record_id):
    if module not in MODULES: abort(404)
    delete_record(module, record_id)
    flash(f"{MODULES[module]['singular']} removed or deactivated.", "success")
    return redirect(url_for("list_records", module=module))


@app.route("/leads/<int:record_id>/convert", methods=["POST"])
@login_required
def convert_lead(record_id):
    lead = visible_record("leads", record_id)
    if not lead: abort(404)
    if lead["status"] != "Qualified":
        flash("Only qualified leads can be converted.", "danger")
        return redirect(url_for("record_detail", module="leads", record_id=record_id))
    try:
        cur = db().execute("INSERT INTO customers(name,email,phone,company,status,owner_id,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (lead["name"], lead["email"], lead["phone"], lead["company"], "Active", lead["owner_id"], lead["notes"], now(), now()))
        customer_id = cur.lastrowid
        if lead["expected_value"] and lead["expected_value"] > 0:
            db().execute("INSERT INTO opportunities(name,customer_id,lead_id,stage,amount,probability,close_date,status,owner_id,source,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (f"{lead['company'] or lead['name']} opportunity", customer_id, record_id, "Qualification", lead["expected_value"], 25, (date.today()+timedelta(days=30)).isoformat(), "Open", lead["owner_id"], lead["source"], lead["notes"], now()))
        db().execute("UPDATE leads SET status='Converted',converted_customer_id=? WHERE id=?", (customer_id, record_id))
        db().commit()
        audit("Convert", "Lead", record_id, old="Qualified", new=f"Customer {customer_id}")
        flash("Lead converted to a customer." + (" An opportunity was also created." if lead["expected_value"] else ""), "success")
        return redirect(url_for("record_detail", module="customers", record_id=customer_id))
    except sqlite3.IntegrityError:
        db().rollback()
        flash("This lead duplicates an existing customer email or phone number.", "danger")
        return redirect(url_for("record_detail", module="leads", record_id=record_id))


@app.route("/users")
@roles_required("Admin")
def users_page():
    q = (request.args.get("q") or "").strip()
    users = db().execute("SELECT id,name,email,role,active,failed_logins,lockout_until,created_at FROM users WHERE name LIKE ? OR email LIKE ? ORDER BY id", (f"%{q}%", f"%{q}%")).fetchall()
    return render_template("users.html", title="Users", users=users, query=q, roles=ROLES)


@app.route("/users/new", methods=["POST"])
@roles_required("Admin")
def create_user():
    name, email = (request.form.get("name") or "").strip(), (request.form.get("email") or "").strip().lower()
    role, password = request.form.get("role", ""), request.form.get("password", "")
    errors = []
    if not name or len(name) > 120: errors.append("Enter a name (up to 120 characters).")
    if not EMAIL_RE.fullmatch(email): errors.append("Enter a valid email address.")
    if role not in ROLES: errors.append("Choose a valid role.")
    if len(password) < 8 or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password): errors.append("Password must be at least 8 characters and include a letter and a number.")
    if db().execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone(): errors.append("That email is already registered.")
    if errors:
        for error in errors: flash(error, "danger")
    else:
        try:
            cur = db().execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)", (name,email,generate_password_hash(password),role,now()))
            db().commit(); audit("Create", "User", cur.lastrowid, new=f"{email}; role={role}")
            flash("User created.", "success")
        except sqlite3.IntegrityError:
            flash("Could not create this user. Check that the email is unique.", "danger")
    return redirect(url_for("users_page"))


@app.route("/users/<int:user_id>/update", methods=["POST"])
@roles_required("Admin")
def update_user(user_id):
    target = db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not target: abort(404)
    action = request.form.get("action")
    if action == "profile":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        duplicate = db().execute("SELECT id FROM users WHERE email=? AND id!=?", (email, user_id)).fetchone()
        if not name or len(name) > 120:
            flash("Name is required and must be 120 characters or fewer.", "danger")
        elif not EMAIL_RE.fullmatch(email) or len(email) > 160:
            flash("Enter a valid email address.", "danger")
        elif duplicate:
            flash("That email is already assigned to another user.", "danger")
        else:
            db().execute("UPDATE users SET name=?,email=? WHERE id=?", (name,email,user_id)); db().commit()
            audit("Profile update", "User", user_id, old=f"{target['name']} <{target['email']}>", new=f"{name} <{email}>")
            flash("User details updated.", "success")
    elif action == "role":
        role = request.form.get("role")
        if role not in ROLES: abort(400)
        if target["id"] == current_user()["id"] and role != "Admin":
            flash("You cannot remove your own administrator role.", "danger")
        else:
            db().execute("UPDATE users SET role=? WHERE id=?", (role,user_id)); db().commit()
            audit("Role change", "User", user_id, old=target["role"], new=role); flash("Role updated.", "success")
    elif action == "active":
        active = 0 if target["active"] else 1
        if target["id"] == current_user()["id"] and not active:
            flash("You cannot deactivate your own account.", "danger")
        elif target["role"] == "Admin" and target["active"] and db().execute("SELECT COUNT(*) FROM users WHERE role='Admin' AND active=1").fetchone()[0] <= 1:
            flash("At least one active administrator must remain.", "danger")
        else:
            db().execute("UPDATE users SET active=?,failed_logins=0,lockout_until=NULL WHERE id=?", (active,user_id)); db().commit()
            audit("Account status", "User", user_id, old=target["active"], new=active); flash("Account status updated.", "success")
    elif action == "reset":
        password = request.form.get("password", "")
        if len(password) < 8 or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
            flash("New password must be at least 8 characters and include a letter and a number.", "danger")
        else:
            db().execute("UPDATE users SET password_hash=?,failed_logins=0,lockout_until=NULL WHERE id=?", (generate_password_hash(password),user_id)); db().commit()
            audit("Password reset", "User", user_id, details="Administrator reset password"); flash("Password reset.", "success")
    return redirect(url_for("users_page"))


@app.route("/reports")
@login_required
def reports():
    report = request.args.get("type", "pipeline")
    allowed = {"pipeline", "customers", "leads", "opportunities", "followups", "conversion", "activity"}
    if report not in allowed: report = "pipeline"
    user = current_user()
    owner_filter = "" if user["role"] in ("Admin", "Manager") else " AND owner_id=?"
    params = [] if not owner_filter else [user["id"]]
    if report == "pipeline":
        rows = db().execute("SELECT stage,COUNT(*) count,COALESCE(SUM(amount),0) amount,COALESCE(SUM(CASE WHEN status='Open' THEN amount*probability/100.0 ELSE 0 END),0) weighted FROM opportunities WHERE 1=1"+owner_filter+" GROUP BY stage ORDER BY stage", params).fetchall()
        headers = [("stage","Stage"),("count","Opportunities"),("amount","Amount"),("weighted","Weighted pipeline")]
    elif report == "customers":
        rows = visible_rows("customers")
        headers = [("name","Customer"),("company","Company"),("email","Email"),("status","Status"),("owner_name","Owner"),("created_at","Created")]
    elif report == "leads":
        rows = visible_rows("leads")
        headers = [("name","Lead"),("source","Source"),("status","Status"),("priority","Priority"),("expected_value","Expected value"),("owner_name","Owner")]
    elif report == "opportunities":
        rows = visible_rows("opportunities")
        headers = [("name","Opportunity"),("customer_name","Customer"),("stage","Stage"),("amount","Amount"),("probability","Probability"),("close_date","Close date"),("owner_name","Owner")]
    elif report == "followups":
        rows = visible_rows("followups")
        headers = [("subject","Subject"),("related_label","Related record"),("followup_date","Date"),("status","Status"),("owner_name","Assigned to")]
    elif report == "conversion":
        rows = db().execute("SELECT status,COUNT(*) count,COALESCE(SUM(expected_value),0) expected_value FROM leads WHERE 1=1"+owner_filter+" GROUP BY status", params).fetchall()
        headers = [("status","Lead status"),("count","Leads"),("expected_value","Expected value")]
    else:
        if user["role"] == "Sales Executive": abort(403)
        rows = db().execute("SELECT u.name user_name,a.action,a.entity_name,a.record_id,a.result,a.created_at FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 200").fetchall()
        headers = [("user_name","User"),("action","Action"),("entity_name","Module"),("record_id","Record"),("result","Result"),("created_at","Date")]
    q = request.args.get("q", "").strip()
    if q:
        rows = [row for row in rows if q.lower() in " ".join(str(row[key] or "") for key, _ in headers).lower()]
    sort = request.args.get("sort", "")
    direction = "asc" if request.args.get("direction") == "asc" else "desc"
    if sort in {key for key, _ in headers}:
        def sort_value(row):
            value = row[sort]
            normalized = value if isinstance(value, (int, float)) else str(value or "").lower()
            return value is None, normalized
        rows = sorted(rows, key=sort_value, reverse=direction == "desc")
    if request.args.get("export") == "csv":
        out = io.StringIO(); writer = csv.writer(out); writer.writerow([label for _,label in headers])
        def csv_cell(value):
            if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
                return "'" + value
            return value
        writer.writerows([[csv_cell(row[key]) for key,_ in headers] for row in rows])
        response = make_response(out.getvalue()); response.headers["Content-Type"] = "text/csv; charset=utf-8"
        response.headers["Content-Disposition"] = f"attachment; filename=acxiomcrm-{report}.csv"
        return response
    page = max(1, request.args.get("page", 1, type=int)); per_page=20; total=len(rows)
    rows=rows[(page-1)*per_page:page*per_page]
    return render_template("reports.html", title="Reports", report=report, rows=rows, headers=headers,
                           query=q, page=page, sort=sort, direction=direction,
                           pages=max(1,(total+per_page-1)//per_page), total=total)


@app.route("/audit")
@roles_required("Admin")
def audit_page():
    filters=[]; params=[]
    for key, column in (("user", "a.user_id"),("module","a.entity_name"),("action","a.action")):
        value=(request.args.get(key) or "").strip()
        if value: filters.append(f"{column} LIKE ?"); params.append(f"%{value}%")
    start=request.args.get("start",""); end=request.args.get("end","")
    if start: filters.append("date(a.created_at)>=date(?)"); params.append(start)
    if end: filters.append("date(a.created_at)<=date(?)"); params.append(end)
    where=" WHERE "+" AND ".join(filters) if filters else ""
    rows=db().execute("SELECT a.*,u.name user_name FROM audit_log a LEFT JOIN users u ON u.id=a.user_id"+where+" ORDER BY a.id DESC LIMIT 250",params).fetchall()
    names=db().execute("SELECT id,name FROM users ORDER BY name").fetchall()
    return render_template("audit.html", title="Audit log", rows=rows, names=names,
                           filters={"user":request.args.get("user",""),"module":request.args.get("module",""),"action":request.args.get("action",""),"start":start,"end":end})


@app.route("/api/docs")
@login_required
def api_docs():
    return render_template("api_docs.html", title="API reference")


def api_error(message, status, code="invalid_request"):
    return jsonify(error=code, message=message), status


def api_data(module, row):
    result = {key: row[key] for key in row.keys() if key not in ("password_hash", "failed_logins", "lockout_until")}
    return result


def api_record(module, record_id):
    record = visible_record(module, record_id)
    return api_data(module, record) if record else None


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data=request.get_json(silent=True) or {}
    email=str(data.get("email", "")).strip().lower(); password=str(data.get("password", ""))
    user=db().execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
    if not user or not user["active"] or (user["lockout_until"] and user["lockout_until"]>now()) or not check_password_hash(user["password_hash"],password):
        if user:
            failed=user["failed_logins"]+1; lock=(datetime.now().astimezone()+timedelta(minutes=15)).isoformat(timespec="seconds") if failed>=5 else None
            db().execute("UPDATE users SET failed_logins=?,lockout_until=? WHERE id=?",(failed,lock,user["id"])); db().commit()
            audit("Login failed","Authentication",user["id"],result="Failure",details="API login failure")
        else: audit("Login failed","Authentication",result="Failure",details="API unknown email")
        return api_error("Email or password is incorrect.",401,"unauthorized")
    db().execute("UPDATE users SET failed_logins=0,lockout_until=NULL WHERE id=?",(user["id"],)); db().commit()
    session.clear(); session["user_id"]=user["id"]; session["csrf_token"]=secrets.token_urlsafe(32); session.permanent=True
    audit("Login","Authentication",user["id"],details="API login")
    response=jsonify(user={"id":user["id"],"name":user["name"],"email":user["email"],"role":user["role"]},csrf_token=session["csrf_token"])
    response.headers["Cache-Control"]="no-store"
    return response,200


@app.route("/api/auth/logout", methods=["POST"])
@login_required
def api_logout():
    user_id=current_user()["id"]; audit("Logout","Authentication",user_id); session.clear()
    return "",204


def api_list(module):
    q=(request.args.get("q") or "").strip()
    rows=visible_rows(module,q,request.args.get("status", "").strip())
    return jsonify(items=[api_data(module,row) for row in rows],count=len(rows))


def api_create(module):
    data=request.get_json(silent=True)
    if not isinstance(data,dict): return api_error("A JSON object is required.",400)
    if module == "followups" and not data.get("related") and data.get("related_type") and data.get("related_id") is not None:
        data["related"] = f"{data['related_type']}:{data['related_id']}"
    errors,values=validate_form(module,data)
    if errors: return jsonify(error="validation_error",message="Please correct the submitted fields.",details=errors),400
    try:
        record_id=save_record(module,values)
    except (sqlite3.IntegrityError,ValueError):
        db().rollback(); return api_error("The record could not be saved. Check duplicate and related values.",409,"conflict")
    return jsonify(item=api_record(module,record_id)),201


@app.route("/api/customers", methods=["GET","POST"])
@login_required
def api_customers():
    if request.method=="GET": return api_list("customers")
    return api_create("customers")


@app.route("/api/customers/<int:record_id>", methods=["GET","PUT","DELETE"])
@login_required
def api_customer(record_id):
    record=api_record("customers",record_id)
    if not record: return api_error("Customer was not found.",404,"not_found")
    if request.method=="GET": return jsonify(item=record)
    if request.method=="DELETE":
        delete_record("customers",record_id); return "",204
    data=request.get_json(silent=True)
    if not isinstance(data,dict): return api_error("A JSON object is required.",400)
    errors,values=validate_form("customers",data,record_id)
    if errors: return jsonify(error="validation_error",message="Please correct the submitted fields.",details=errors),400
    try: save_record("customers",values,record_id)
    except (sqlite3.IntegrityError,ValueError): db().rollback(); return api_error("The record conflicts with existing data.",409,"conflict")
    return jsonify(item=api_record("customers",record_id))


@app.route("/api/leads", methods=["GET","POST"])
@login_required
def api_leads():
    return api_list("leads") if request.method=="GET" else api_create("leads")


@app.route("/api/opportunities", methods=["GET","POST"])
@login_required
def api_opportunities():
    return api_list("opportunities") if request.method=="GET" else api_create("opportunities")


@app.route("/api/followups", methods=["GET","POST"])
@login_required
def api_followups():
    return api_list("followups") if request.method=="GET" else api_create("followups")


@app.route("/api/reports/pipeline")
@roles_required("Admin","Manager","Sales Executive")
def api_pipeline():
    owner_filter="" if current_user()["role"] in ("Admin","Manager") else " AND owner_id=?"
    params=[] if not owner_filter else [current_user()["id"]]
    rows=db().execute("SELECT stage,COUNT(*) count,COALESCE(SUM(amount),0) amount,COALESCE(SUM(CASE WHEN status='Open' THEN amount*probability/100.0 ELSE 0 END),0) weighted FROM opportunities WHERE 1=1"+owner_filter+" GROUP BY stage",params).fetchall()
    return jsonify(items=[dict(row) for row in rows])


@app.errorhandler(403)
def forbidden(_error):
    if request.path.startswith("/api/"): return jsonify(error="forbidden",message="You do not have permission for this action."),403
    return render_template("error.html", title="Access denied", message="You do not have permission to view this page."),403


@app.errorhandler(404)
def not_found(_error):
    if request.path.startswith("/api/"): return jsonify(error="not_found",message="The requested resource was not found."),404
    return render_template("error.html", title="Not found", message="That page or record could not be found."),404


@app.errorhandler(400)
def bad_request(error):
    if request.path.startswith("/api/"): return jsonify(error="bad_request",message="The request could not be processed."),400
    return render_template("error.html", title="Form expired", message=getattr(error,"description","Please refresh the page and try again.")),400


@app.cli.command("init-db")
def init_db_command():
    init_db(); print(f"Database is ready at {DB_PATH}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
