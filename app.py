import os
import re
import sqlite3
import subprocess
from flask import Flask, request
from markupsafe import escape
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Secret lu depuis l'environnement
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(32).hex()

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "txt", "pdf"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_db():
    conn = sqlite3.connect("users.db")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    return conn


@app.route("/")
def index():
    return "Hello DevSecOps!"


# Injection SQL corrigée
@app.route("/user")
def user():
    username = request.args.get("name", "")
    rows = get_db().execute(
        "SELECT id, username FROM users WHERE username = ?", (username,)
    ).fetchall()
    return str(rows)


# Injection de commande corrigée
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", host):
        return "invalid host", 400
    output = subprocess.check_output(["ping", "-c", "1", host], timeout=5)
    return output


# XSS corrigé
@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return "<h1>Hello " + str(escape(name)) + "</h1>"


# Upload corrigé
@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    filename = secure_filename(f.filename)
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if extension not in ALLOWED_EXTENSIONS:
        return "file type not allowed", 400
    f.save(os.path.join(UPLOAD_FOLDER, filename))
    return "uploaded"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
