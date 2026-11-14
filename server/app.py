import os
import hashlib
import secrets
import psycopg

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from psycopg.rows import dict_row

app = FastAPI(title="ROS QII API", version="1.0.0")

DATABASE_URL = os.environ["DATABASE_URL"]
ADMIN_KEY = os.environ["ADMIN_KEY"]
TEST_USER = os.getenv("TEST_ACCOUNT_USERNAME", "qii_test")
TEST_PASSWORD = os.getenv("TEST_ACCOUNT_PASSWORD", "")

def db():
    url = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    return psycopg.connect(url, row_factory=dict_row)

def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 200000
    ).hex()
    return salt, digest

def verify_password(password, salt, expected):
    return secrets.compare_digest(
        password_hash(password, salt)[1], expected
    )

def current_user(authorization):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Login required")

    token = authorization[7:]
    with db() as conn:
        row = conn.execute(
            """SELECT users.id, users.username, users.diamonds
               FROM sessions JOIN users ON users.id=sessions.user_id
               WHERE sessions.token=%s""",
            (token,)
        ).fetchone()

    if not row:
        raise HTTPException(401, "Invalid session")
    return row

@app.on_event("startup")
def startup():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                diamonds BIGINT NOT NULL DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS queue (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                status TEXT NOT NULL DEFAULT 'waiting',
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)

        if TEST_PASSWORD:
            salt, hashed = password_hash(TEST_PASSWORD)
            conn.execute("""
                INSERT INTO users(username, salt, password_hash, diamonds)
                VALUES (%s, %s, %s, 99999999)
                ON CONFLICT(username) DO NOTHING
            """, (TEST_USER, salt, hashed))

@app.get("/health")
def health():
    with db() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok", "service": "ROS QII"}

class Credentials(BaseModel):
    username: str
    password: str

@app.post("/register")
def register(data: Credentials):
    if len(data.username) < 3 or len(data.password) < 8:
        raise HTTPException(400, "Username min 3, password min 8 characters")

    salt, hashed = password_hash(data.password)
    try:
        with db() as conn:
            conn.execute("""
                INSERT INTO users(username, salt, password_hash)
                VALUES (%s, %s, %s)
            """, (data.username, salt, hashed))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(409, "Username already exists")

    return {"ok": True}

@app.post("/login")
def login(data: Credentials):
    with db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username=%s",
            (data.username,)
        ).fetchone()

        if not user or not verify_password(
            data.password, user["salt"], user["password_hash"]
        ):
            raise HTTPException(401, "Incorrect username or password")

        token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO sessions(token, user_id) VALUES (%s, %s)",
            (token, user["id"])
        )

    return {"token": token, "token_type": "Bearer"}

@app.get("/me")
def me(authorization: str | None = Header(default=None)):
    user = current_user(authorization)
    return dict(user)

@app.get("/lobby")
def lobby(authorization: str | None = Header(default=None)):
    current_user(authorization)
    with db() as conn:
        users = conn.execute(
            "SELECT username FROM users ORDER BY id LIMIT 50"
        ).fetchall()
    return {"players": users}

@app.post("/queue")
def join_queue(authorization: str | None = Header(default=None)):
    user = current_user(authorization)
    with db() as conn:
        conn.execute("""
            INSERT INTO queue(user_id, status)
            VALUES (%s, 'waiting')
        """, (user["id"],))
    return {"status": "waiting"}

@app.post("/admin/diamonds")
def set_diamonds(
    username: str,
    amount: int,
    x_admin_key: str | None = Header(default=None)
):
    if not secrets.compare_digest(x_admin_key or "", ADMIN_KEY):
        raise HTTPException(403, "Admin access denied")
    if amount < 0 or amount > 999999999999:
        raise HTTPException(400, "Invalid diamond amount")

    with db() as conn:
        result = conn.execute("""
            UPDATE users SET diamonds=%s
            WHERE username=%s RETURNING username, diamonds
        """, (amount, username)).fetchone()

    if not result:
        raise HTTPException(404, "User not found")
    return dict(result)
