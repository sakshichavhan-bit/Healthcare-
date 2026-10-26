from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import sqlite3, os, json, hashlib, hmac
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
ENCRYPTION_KEY = os.environ.get("APP_ENCRYPTION_KEY", Fernet.generate_key())

cipher = Fernet(ENCRYPTION_KEY)

def get_db():
    conn = sqlite3.connect("healthcare.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'clinician'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT,
            last_name TEXT,
            dob TEXT,
            ssn_encrypted TEXT,
            mrn TEXT,
            diagnosis TEXT,
            last_visit TEXT,
            integrity_hash TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            action TEXT,
            resource TEXT,
            event_time TEXT,
            ip TEXT,
            details TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_event(user, action, resource, ip, details):
    conn = get_db()
    conn.execute("""
        INSERT INTO audit_log (user, action, resource, event_time, ip, details)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user, action, resource, datetime.utcnow().isoformat(), ip, details))
    conn.commit()
    conn.close()

def encrypt_value(value):
    return cipher.encrypt(value.encode()).decode()

def decrypt_value(value):
    return cipher.decrypt(value.encode()).decode()

def patient_hash(patient_record):
    payload = json.dumps(patient_record, sort_keys=True).encode()
    return hmac.new(app.secret_key.encode(), payload, hashlib.sha256).hexdigest()

@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if user and check_password_hash(user["password_hash"], password):
        session["username"] = user["username"]
        session["role"] = user["role"]
        log_event(user["username"], "login", "auth", request.remote_addr, "Successful login")
        return redirect(url_for("dashboard"))
    flash("Invalid credentials")
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    user = session.get("username")
    if user:
        log_event(user, "logout", "auth", request.remote_addr, "User logged out")
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("index"))
    conn = get_db()
    patients = conn.execute("SELECT * FROM patients ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    return render_template("dashboard.html", patients=patients, user=session["username"], role=session["role"])

@app.route("/patients")
def patients():
    if "username" not in session:
        return redirect(url_for("index"))
    conn = get_db()
    patients = conn.execute("SELECT * FROM patients ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("patients.html", patients=patients)

@app.route("/patient/<int:patient_id>")
def patient_detail(patient_id):
    if "username" not in session:
        return redirect(url_for("index"))
    if session.get("role") not in ("admin", "clinician"):
        flash("Access denied")
        return redirect(url_for("dashboard"))
    conn = get_db()
    patient = conn.execute("SELECT * FROM patients WHERE id = ?", (patient_id,)).fetchone()
    conn.close()
    if not patient:
        flash("Patient not found")
        return redirect(url_for("patients"))
    decrypted = {
        "first_name": patient["first_name"],
        "last_name": patient["last_name"],
        "dob": patient["dob"],
        "ssn": decrypt_value(patient["ssn_encrypted"]) if patient["ssn_encrypted"] else "",
        "mrn": patient["mrn"],
        "diagnosis": patient["diagnosis"],
        "last_visit": patient["last_visit"]
    }
    return render_template("patient_detail.html", patient=decrypted)

@app.route("/seed")
def seed_data():
    if "username" not in session:
        return redirect(url_for("index"))
    conn = get_db()
    conn.execute("DELETE FROM patients")
    patients = [
        {
            "first_name": "Ava",
            "last_name": "Smith",
            "dob": "1988-03-12",
            "ssn": "123-45-6789",
            "mrn": "MRN-1001",
            "diagnosis": "Hypertension",
            "last_visit": "2026-10-12"
        },
        {
            "first_name": "Liam",
            "last_name": "Jones",
            "dob": "1975-08-02",
            "ssn": "987-65-4321",
            "mrn": "MRN-1002",
            "diagnosis": "Type 2 Diabetes",
            "last_visit": "2026-10-18"
        }
    ]
    for p in patients:
        integrity = patient_hash(p)
        conn.execute("""
            INSERT INTO patients (first_name, last_name, dob, ssn_encrypted, mrn, diagnosis, last_visit, integrity_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            p["first_name"], p["last_name"], p["dob"], encrypt_value(p["ssn"]), p["mrn"], p["diagnosis"], p["last_visit"], integrity
        ))
    conn.commit()
    conn.close()
    log_event(session.get("username", "system"), "seed", "patients", request.remote_addr, "Synthetic patient records loaded")
    flash("Synthetic patient data loaded")
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    init_db()
    conn = get_db()
    admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'").fetchone()[0]
    if admin_count == 0:
        conn.execute("""
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
        """, ("admin", generate_password_hash("ChangeMe123!"), "admin"))
    conn.commit()
    conn.close()
    app.run(host="0.0.0.0", port=5000, debug=False)