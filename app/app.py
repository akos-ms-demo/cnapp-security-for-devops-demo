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

# --- VULN 1: Hardcoded secret (secret scanning / CodeQL py/hardcoded-credentials)
# Looks like an AWS access key so GitHub secret scanning triggers.
AWS_ACCESS_KEY_ID = "AKIAZ7XDEMO4CNAPPDEV2"
AWS_SECRET_ACCESS_KEY = "Xy9pQ2vR7sT4uVwZ1aB3cD5eF6gH8iJ0kLmNoPqR"
FLASK_SECRET = "super-secret-demo-key-do-not-use"

app.config["SECRET_KEY"] = FLASK_SECRET

DB_PATH = os.environ.get("DB_PATH", "demo.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


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
