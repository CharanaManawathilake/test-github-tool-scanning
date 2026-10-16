"""
Deliberately vulnerable Flask application.

DO NOT DEPLOY. Every route here contains an intentional security flaw so that
static analysis tools (CodeQL, Semgrep, ...) have something to report in the
GitHub "Security" -> "Code scanning" tab.
"""

import hashlib
import logging
import os
import pickle
import sqlite3
import subprocess
import traceback

import requests
import yaml
from flask import Flask, make_response, redirect, request
from jinja2 import Environment
from lxml import etree

from vulnerable_app.config import ADMIN_PASSWORD, SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY

logger = logging.getLogger(__name__)

DB_PATH = "users.db"
UPLOAD_DIR = "/var/www/uploads"


def get_db():
    return sqlite3.connect(DB_PATH)


# --------------------------------------------------------------------------- #
# Injection
# --------------------------------------------------------------------------- #

@app.route("/users")
def find_user():
    # SQL injection: user input concatenated into the query string.
    username = request.args.get("name", "")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email FROM users WHERE username = '" + username + "'")
    return {"users": cursor.fetchall()}


@app.route("/ping")
def ping():
    # OS command injection: user input passed to a shell.
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


@app.route("/dns")
def dns_lookup():
    # OS command injection via os.system.
    domain = request.args.get("domain", "")
    os.system("nslookup " + domain)
    return "done"


@app.route("/calc")
def calculate():
    # Code injection: eval() on user input.
    expression = request.args.get("expr", "1+1")
    return str(eval(expression))


# --------------------------------------------------------------------------- #
# Cross-site scripting / template injection
# --------------------------------------------------------------------------- #

@app.route("/hello")
def hello():
    # Reflected XSS: user input written directly into HTML.
    name = request.args.get("name", "world")
    return make_response("<h1>Hello " + name + "!</h1>")


@app.route("/greet")
def greet():
    # Jinja2 environment with autoescaping disabled + template built from input.
    env = Environment(autoescape=False)
    template = env.from_string("<p>Welcome " + request.args.get("user", "") + "</p>")
    return template.render()


# --------------------------------------------------------------------------- #
# File system
# --------------------------------------------------------------------------- #

@app.route("/download")
def download():
    # Path traversal: ?file=../../etc/passwd
    filename = request.args.get("file")
    with open(os.path.join(UPLOAD_DIR, filename), "rb") as f:
        return f.read()


# --------------------------------------------------------------------------- #
# Deserialization / XML
# --------------------------------------------------------------------------- #

@app.route("/session", methods=["POST"])
def load_session():
    # Insecure deserialization of untrusted data with pickle.
    data = pickle.loads(request.data)
    return {"restored": str(data)}


@app.route("/config", methods=["POST"])
def load_config():
    # Unsafe YAML loading (arbitrary object construction).
    config = yaml.load(request.data, Loader=yaml.Loader)
    return {"config": str(config)}


@app.route("/xml", methods=["POST"])
def parse_xml():
    # XML External Entity (XXE) injection.
    parser = etree.XMLParser(resolve_entities=True)
    doc = etree.fromstring(request.data, parser)
    return etree.tostring(doc)


# --------------------------------------------------------------------------- #
# SSRF / redirects / TLS
# --------------------------------------------------------------------------- #

@app.route("/fetch")
def fetch_url():
    # Full server-side request forgery: attacker controls the whole URL.
    url = request.args.get("url")
    resp = requests.get(url, timeout=5)
    return resp.text


@app.route("/fetch-insecure")
def fetch_insecure():
    # TLS certificate validation disabled.
    resp = requests.get("https://internal.example.com/api", verify=False, timeout=5)
    return resp.text


@app.route("/login/callback")
def login_callback():
    # Open redirect.
    target = request.args.get("next", "/")
    return redirect(target)


# --------------------------------------------------------------------------- #
# Crypto / secrets / information exposure
# --------------------------------------------------------------------------- #

@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    # Weak hashing algorithm for passwords.
    password_hash = hashlib.md5(password.encode()).hexdigest()
    # Clear-text logging of sensitive data.
    logger.info("Registering user %s with password %s", username, password)
    conn = get_db()
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, password_hash),
    )
    conn.commit()
    return {"status": "ok"}


@app.route("/admin")
def admin():
    if request.args.get("password") == ADMIN_PASSWORD:
        return "Welcome, admin"
    return "Forbidden", 403


@app.route("/debug-error")
def debug_error():
    try:
        1 / 0
    except Exception:
        # Stack trace exposed to the end user.
        return traceback.format_exc(), 500


if __name__ == "__main__":
    # Flask debug mode exposes the Werkzeug interactive debugger (RCE).
    app.run(host="0.0.0.0", port=5000, debug=True)
