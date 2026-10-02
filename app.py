import os
import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)

# Vulnérabilité : secret codé en dur dans le code source
app.config["SECRET_KEY"] = "super-secret-key-123"

UPLOAD_FOLDER = "uploads"
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


# Vulnérabilité 1 : injection SQL
@app.route("/user")
def user():
    username = request.args.get("name", "")
    query = "SELECT id, username FROM users WHERE username = '" + username + "'"
    rows = get_db().execute(query).fetchall()
    return str(rows)


# Vulnérabilité 2 : injection de commande
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


# Vulnérabilité 3 : XSS
@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return "<h1>Hello " + name + "</h1>"


# Vulnérabilité 4 : upload non contrôlé + path traversal
@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    f.save(os.path.join(UPLOAD_FOLDER, f.filename))
    return "uploaded"


if __name__ == "__main__":
    # Vulnérabilité 5 : mode debug activé
    app.run(host="127.0.0.1", port=5001, debug=True)
