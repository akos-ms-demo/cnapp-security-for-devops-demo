"""
Intentionally vulnerable Flask app for the CNAPP / DevSecOps demo.

DO NOT deploy to production. Every issue below is deliberate so that
GitHub Advanced Security (CodeQL + secret scanning + Dependabot) and
Microsoft Defender for Cloud can flag it.
"""

import sys
print(">>> app.py starting, python", sys.version, flush=True)

import hashlib
import os
import sqlite3
import subprocess

from flask import Flask, request, render_template_string

print(">>> imports OK", flush=True)

app = Flask(__name__)

# --- VULN 1: Hardcoded secrets (secret scanning / CodeQL py/hardcoded-credentials)
# Mix of partner-detector patterns and generic high-entropy strings so that
# GitHub Advanced Security secret scanning fires regardless of allowlists.
# All values are inert demo placeholders.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
# Azure Storage account connection string (GHAS partner detector, no allowlist).
AZURE_STORAGE_CONNECTION_STRING = (
    "DefaultEndpointsProtocol=https;AccountName=cnappdemoacct;"
    "AccountKey=Q2RlbW9LZXlGb3JDTkFQUFNlY3VyaXR5RGVtb09ubHlOb3RSZWFsMTIzNDU2Nzg5MA==;"
    "EndpointSuffix=core.windows.net"
)
# GitHub PAT-shaped token (ghp_ prefix is detected even when revoked/inactive).
GITHUB_TOKEN = "ghp_1A2b3C4d5E6f7G8h9I0jK1L2m3N4o5P6q7R8"
# Generic high-entropy secret -- caught by "non-provider patterns" detector.
API_KEY = "8f7d9c1b2e4a6f3d5c7b9e1a3f5d7c9b1e3a5f7d"
FLASK_SECRET = "super-secret-demo-key-do-not-use"

app.config["SECRET_KEY"] = FLASK_SECRET

DB_PATH = os.environ.get("DB_PATH", "demo.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        );
        """
    )
    cur = conn.execute("SELECT COUNT(*) AS n FROM users")
    if cur.fetchone()["n"] == 0:
        conn.executemany(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            [("alice", "password123"), ("bob", "hunter2")],
        )
    conn.commit()
    conn.close()


init_db()


@app.route("/")
def index():
    return "CNAPP DevSecOps demo app. Try /login, /search, /ping, /hash."


# --- VULN 2: SQL injection (CodeQL py/sql-injection)
@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    conn = get_db()
    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )
    row = conn.execute(query).fetchone()
    return "ok" if row else "denied"


# --- VULN 3: Reflected XSS via render_template_string (CodeQL py/reflective-xss)
@app.route("/search")
def search():
    q = request.args.get("q", "")
    template = "<h1>Results for " + q + "</h1>"
    return render_template_string(template)


# --- VULN 4: Command injection (CodeQL py/command-line-injection)
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


# --- VULN 5: Weak hash (CodeQL py/weak-sensitive-data-hashing)
@app.route("/hash")
def weak_hash():
    data = request.args.get("data", "")
    return hashlib.md5(data.encode()).hexdigest()


if __name__ == "__main__":
    # --- VULN 6: Bind to all interfaces + debug=True (CodeQL py/flask-debug)
    app.run(host="0.0.0.0", port=8080, debug=True, use_reloader=False)
