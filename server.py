import json
import os
import re
import sqlite3
import hmac
import hashlib
import base64
import secrets
from datetime import datetime, timezone
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

DB_PATH = os.getenv("DB_PATH", "app.db")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8080"))
SECRET = os.getenv("APP_SECRET", "change-me-in-production")


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('admin','member')),
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS projects (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          description TEXT,
          created_by INTEGER NOT NULL,
          created_at TEXT NOT NULL,
          FOREIGN KEY(created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS project_members (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          project_id INTEGER NOT NULL,
          user_id INTEGER NOT NULL,
          UNIQUE(project_id, user_id),
          FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS tasks (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          project_id INTEGER NOT NULL,
          title TEXT NOT NULL,
          description TEXT,
          status TEXT NOT NULL CHECK(status IN ('todo','in_progress','done')) DEFAULT 'todo',
          assigned_to INTEGER,
          due_date TEXT,
          created_by INTEGER NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
          FOREIGN KEY(assigned_to) REFERENCES users(id) ON DELETE SET NULL,
          FOREIGN KEY(created_by) REFERENCES users(id)
        );
        """
    )
    conn.commit()
    conn.close()


def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def json_response(start_response, status_code, payload):
    status_text = {
        200: "200 OK",
        201: "201 Created",
        400: "400 Bad Request",
        401: "401 Unauthorized",
        403: "403 Forbidden",
        404: "404 Not Found",
        405: "405 Method Not Allowed",
        500: "500 Internal Server Error",
    }[status_code]
    body = json.dumps(payload).encode("utf-8")
    start_response(status_text, [("Content-Type", "application/json"), ("Content-Length", str(len(body))), ("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Headers", "Content-Type, Authorization"), ("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")])
    return [body]


def parse_json_body(environ):
    try:
        size = int(environ.get("CONTENT_LENGTH", "0") or 0)
    except ValueError:
        size = 0
    data = environ["wsgi.input"].read(size) if size > 0 else b"{}"
    return json.loads(data.decode("utf-8") or "{}")


def hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return f"{salt}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password, stored):
    salt, existing = stored.split("$", 1)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return hmac.compare_digest(existing, base64.urlsafe_b64encode(digest).decode())


def make_token(user_id, role):
    payload = f"{user_id}:{role}:{int(datetime.now(timezone.utc).timestamp())}"
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}.{sig}".encode()).decode()


def parse_token(token):
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        payload, sig = raw.rsplit(".", 1)
        expected = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        user_id, role, _ = payload.split(":")
        return {"user_id": int(user_id), "role": role}
    except Exception:
        return None


def auth_user(environ):
    auth = environ.get("HTTP_AUTHORIZATION", "")
    if not auth.startswith("Bearer "):
        return None
    return parse_token(auth.split(" ", 1)[1])


def app(environ, start_response):
    method = environ["REQUEST_METHOD"]
    path = environ.get("PATH_INFO", "")

    if method == "OPTIONS":
        return json_response(start_response, 200, {"ok": True})

    if path == "/" and method == "GET":
        html = open("static/index.html", "rb").read()
        start_response("200 OK", [("Content-Type", "text/html"), ("Content-Length", str(len(html)))])
        return [html]

    if path == "/app.js" and method == "GET":
        js = open("static/app.js", "rb").read()
        start_response("200 OK", [("Content-Type", "application/javascript"), ("Content-Length", str(len(js)))])
        return [js]

    if path == "/api/auth/signup" and method == "POST":
        body = parse_json_body(environ)
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", body.get("email", "")):
            return json_response(start_response, 400, {"error": "Invalid email"})
        if len(body.get("password", "")) < 6:
            return json_response(start_response, 400, {"error": "Password must be at least 6 chars"})
        role = body.get("role", "member")
        if role not in ["admin", "member"]:
            return json_response(start_response, 400, {"error": "Role must be admin/member"})
        conn = db_conn()
        try:
            cur = conn.execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES (?,?,?,?,?)", (body.get("name", ""), body["email"].lower(), hash_password(body["password"]), role, now_iso()))
            conn.commit()
            user_id = cur.lastrowid
        except sqlite3.IntegrityError:
            conn.close()
            return json_response(start_response, 400, {"error": "Email already exists"})
        conn.close()
        token = make_token(user_id, role)
        return json_response(start_response, 201, {"token": token, "user": {"id": user_id, "name": body.get("name", ""), "email": body["email"].lower(), "role": role}})

    if path == "/api/auth/login" and method == "POST":
        body = parse_json_body(environ)
        conn = db_conn()
        row = conn.execute("SELECT * FROM users WHERE email = ?", (body.get("email", "").lower(),)).fetchone()
        conn.close()
        if not row or not verify_password(body.get("password", ""), row["password_hash"]):
            return json_response(start_response, 401, {"error": "Invalid credentials"})
        token = make_token(row["id"], row["role"])
        return json_response(start_response, 200, {"token": token, "user": {"id": row["id"], "name": row["name"], "email": row["email"], "role": row["role"]}})

    user = auth_user(environ)
    if path.startswith("/api/") and not user:
        return json_response(start_response, 401, {"error": "Unauthorized"})

    if path == "/api/projects" and method == "POST":
        body = parse_json_body(environ)
        if user["role"] != "admin":
            return json_response(start_response, 403, {"error": "Only admin can create projects"})
        conn = db_conn()
        cur = conn.execute("INSERT INTO projects(name,description,created_by,created_at) VALUES (?,?,?,?)", (body.get("name", ""), body.get("description", ""), user["user_id"], now_iso()))
        pid = cur.lastrowid
        conn.execute("INSERT INTO project_members(project_id,user_id) VALUES (?,?)", (pid, user["user_id"]))
        conn.commit(); conn.close()
        return json_response(start_response, 201, {"id": pid, "name": body.get("name", ""), "description": body.get("description", "")})

    if path == "/api/projects" and method == "GET":
        conn = db_conn()
        rows = conn.execute("SELECT p.* FROM projects p JOIN project_members pm ON pm.project_id=p.id WHERE pm.user_id=?", (user["user_id"],)).fetchall()
        conn.close()
        return json_response(start_response, 200, {"projects": [dict(r) for r in rows]})

    m = re.match(r"^/api/projects/(\d+)/members$", path)
    if m and method == "POST":
        if user["role"] != "admin":
            return json_response(start_response, 403, {"error": "Only admin can add members"})
        pid = int(m.group(1)); body = parse_json_body(environ)
        conn = db_conn()
        member = conn.execute("SELECT id FROM users WHERE email=?", (body.get("email", "").lower(),)).fetchone()
        if not member:
            conn.close(); return json_response(start_response, 404, {"error": "User not found"})
        try:
            conn.execute("INSERT INTO project_members(project_id,user_id) VALUES (?,?)", (pid, member["id"]))
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        conn.close()
        return json_response(start_response, 200, {"ok": True})

    if path == "/api/tasks" and method == "POST":
        body = parse_json_body(environ)
        conn = db_conn()
        is_member = conn.execute("SELECT 1 FROM project_members WHERE project_id=? AND user_id=?", (body.get("project_id"), user["user_id"])).fetchone()
        if not is_member:
            conn.close(); return json_response(start_response, 403, {"error": "Not in project"})
        cur = conn.execute("INSERT INTO tasks(project_id,title,description,status,assigned_to,due_date,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)", (body.get("project_id"), body.get("title", ""), body.get("description", ""), body.get("status", "todo"), body.get("assigned_to"), body.get("due_date"), user["user_id"], now_iso(), now_iso()))
        conn.commit(); tid = cur.lastrowid; conn.close()
        return json_response(start_response, 201, {"id": tid})

    m = re.match(r"^/api/tasks/(\d+)$", path)
    if m and method == "PUT":
        tid = int(m.group(1)); body = parse_json_body(environ)
        conn = db_conn()
        task = conn.execute("SELECT t.*, pm.user_id as member FROM tasks t JOIN project_members pm ON pm.project_id=t.project_id WHERE t.id=? AND pm.user_id=?", (tid, user["user_id"])).fetchone()
        if not task:
            conn.close(); return json_response(start_response, 404, {"error": "Task not found"})
        fields = []
        vals = []
        for k in ["title", "description", "status", "assigned_to", "due_date"]:
            if k in body:
                fields.append(f"{k}=?")
                vals.append(body[k])
        fields.append("updated_at=?"); vals.append(now_iso()); vals.append(tid)
        conn.execute(f"UPDATE tasks SET {', '.join(fields)} WHERE id=?", vals)
        conn.commit(); conn.close()
        return json_response(start_response, 200, {"ok": True})

    if path == "/api/dashboard" and method == "GET":
        conn = db_conn()
        rows = conn.execute("SELECT t.* FROM tasks t JOIN project_members pm ON pm.project_id=t.project_id WHERE pm.user_id=?", (user["user_id"],)).fetchall()
        conn.close()
        now = datetime.now(timezone.utc)
        out = {"total": len(rows), "todo": 0, "in_progress": 0, "done": 0, "overdue": 0, "tasks": []}
        for r in rows:
            d = dict(r)
            out[d["status"]] += 1
            if d.get("due_date"):
                try:
                    due = datetime.fromisoformat(d["due_date"]) if "T" in d["due_date"] else datetime.fromisoformat(d["due_date"] + "T00:00:00+00:00")
                    if due < now and d["status"] != "done":
                        out["overdue"] += 1
                except Exception:
                    pass
            out["tasks"].append(d)
        return json_response(start_response, 200, out)

    return json_response(start_response, 404, {"error": "Not found"})


if __name__ == "__main__":
    init_db()
    print(f"Server running on http://{HOST}:{PORT}")
    make_server(HOST, PORT, app).serve_forever()
