"""
University Lecturer Performance Review System
Secure Flask backend with CSRF protection, rate limiting,
input sanitization, and proper authentication.
"""
import os, sqlite3, csv, io, re, html, secrets, time
from functools import wraps
from collections import defaultdict
from flask import (Flask, render_template, request, redirect, url_for,
    session, flash, make_response, abort)
from werkzeug.security import generate_password_hash, check_password_hash
from config import get_config

app = Flask(__name__, template_folder="templates", static_folder="static")
config = get_config()
app.config.from_object(config)
app.secret_key = config.SECRET_KEY
DB_PATH = config.DB_PATH
ADMIN_USERNAME = config.ADMIN_USERNAME
ADMIN_PASSWORD = config.ADMIN_PASSWORD

class RateLimiter:
    def __init__(self):
        self._req = defaultdict(list)
        self._limit = config.RATE_LIMIT_PER_MINUTE
    def is_allowed(self, key):
        now = time.time()
        self._req[key] = [t for t in self._req[key] if now - t < 60]
        if len(self._req[key]) >= self._limit: return False
        self._req[key].append(now)
        return True
rate_limiter = RateLimiter()

def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

def csrf_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "POST":
            token = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token")
            expected = session.get("_csrf_token")
            if not expected or not token or not secrets.compare_digest(expected, token):
                flash("Security token expired. Please try again.", "error")
                return redirect(request.referrer or url_for("index"))
        return f(*args, **kwargs)
    return decorated

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = ("default-src 'self'; style-src 'self' 'unsafe-inline' https://unpkg.com; script-src 'self' 'unsafe-inline' https://unpkg.com; img-src 'self' data: https:; connect-src 'self'")
    return response

def sanitize_text(value, max_length=500):
    if not value: return ""
    return html.escape(value.strip())[:max_length]

def validate_student_id(value):
    return bool(re.match(r"^[A-Za-z0-9\-]{3,20}$", value))

def validate_rating(value):
    try:
        v = int(value)
        if 1 <= v <= 5: return v
    except (ValueError, TypeError): pass
    return None

def validate_email(value):
    return bool(re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", value))

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS lecturers (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, department TEXT NOT NULL, email TEXT, phone TEXT, pin_hash TEXT, is_active INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY AUTOINCREMENT, student_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL, email TEXT, course TEXT, year_of_study TEXT, password_hash TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, lecturer_id INTEGER NOT NULL, student_id INTEGER NOT NULL, clarity INTEGER NOT NULL CHECK(clarity BETWEEN 1 AND 5), engagement INTEGER NOT NULL CHECK(engagement BETWEEN 1 AND 5), punctuality INTEGER NOT NULL CHECK(punctuality BETWEEN 1 AND 5), comment TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (lecturer_id) REFERENCES lecturers(id), FOREIGN KEY (student_id) REFERENCES students(id), UNIQUE (lecturer_id, student_id));
    """)
    conn.close()

@app.before_request
def setup():
    if not hasattr(app, "_db_initialized"):
        init_db()
        app._db_initialized = True

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in.", "error")
            return redirect(url_for("student_login", next=request.path))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Admin access required.", "error")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated

def lecturer_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_lecturer"):
            flash("Please log in as a lecturer.", "error")
            return redirect(url_for("lecturer_login"))
        return f(*args, **kwargs)
    return decorated

def get_current_student():
    sid = session.get("user_id")
    if not sid or not session.get("is_student"): return None
    conn = get_db()
    s = conn.execute("SELECT * FROM students WHERE id = ?", (sid,)).fetchone()
    conn.close()
    return s

def get_current_lecturer():
    lid = session.get("user_id")
    if not lid or not session.get("is_lecturer"): return None
    conn = get_db()
    l = conn.execute("SELECT * FROM lecturers WHERE id = ?", (lid,)).fetchone()
    conn.close()
    return l

@app.context_processor
def inject_globals():
    return {"csrf_token": generate_csrf_token(), "current_year": __import__("datetime").datetime.now().year}


# ==================== PUBLIC ROUTES ====================

@app.route("/")
def index():
    if not rate_limiter.is_allowed(f"ip:{request.remote_addr}:index"):
        abort(429)
    conn = get_db()
    lecturers = conn.execute("SELECT * FROM lecturers WHERE is_active = 1 ORDER BY name").fetchall()
    conn.close()
    return render_template("index.html", lecturers=lecturers)


@app.route("/review/<int:lecturer_id>", methods=["GET", "POST"])
@csrf_required
def review(lecturer_id):
    if not rate_limiter.is_allowed(f"ip:{request.remote_addr}:review"): abort(429)
    conn = get_db()
    lecturer = conn.execute("SELECT * FROM lecturers WHERE id = ? AND is_active = 1", (lecturer_id,)).fetchone()
    if not lecturer:
        conn.close()
        flash("Lecturer not found.", "error")
        return redirect(url_for("index"))
    student = get_current_student()
    if request.method == "POST":
        if not student:
            conn.close()
            flash("You must be logged in to submit a review.", "error")
            return redirect(url_for("student_login", next=request.path))
        clarity = validate_rating(request.form.get("clarity"))
        engagement = validate_rating(request.form.get("engagement"))
        punctuality = validate_rating(request.form.get("punctuality"))
        comment = sanitize_text(request.form.get("comment", ""), 1000)
        if not all([clarity, engagement, punctuality]):
            conn.close()
            flash("All ratings must be between 1 and 5.", "error")
            return redirect(url_for("review", lecturer_id=lecturer_id))
        if conn.execute("SELECT id FROM reviews WHERE lecturer_id = ? AND student_id = ?",
           (lecturer_id, student["id"])).fetchone():
            conn.close()
            flash("You have already reviewed this lecturer.", "error")
            return redirect(url_for("student_dashboard"))
        conn.execute(
            "INSERT INTO reviews (lecturer_id, student_id, clarity, engagement, punctuality, comment) VALUES (?, ?, ?, ?, ?, ?)",
            (lecturer_id, student["id"], clarity, engagement, punctuality, comment))
        conn.commit()
        conn.close()
        flash("Thank you! Your review has been submitted.", "success")
        return redirect(url_for("thank_you"))
    conn.close()
    return render_template("student/review.html", lecturer=lecturer, student=student)


@app.route("/thank-you")
def thank_you():
    return render_template("thank_you.html")

# ==================== STUDENT AUTH ====================

@app.route("/student/register", methods=["GET", "POST"])
@csrf_required
def student_register():
    if not rate_limiter.is_allowed(f"ip:{request.remote_addr}:register"): abort(429)
    if request.method == "POST":
        name = sanitize_text(request.form.get("name", ""), 100)
        student_id = sanitize_text(request.form.get("student_id", ""), 20)
        email = sanitize_text(request.form.get("email", ""), 100)
        course = sanitize_text(request.form.get("course", ""), 100)
        year = sanitize_text(request.form.get("year_of_study", ""), 20)
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        errors = []
        if not name or len(name) < 2: errors.append("Name must be at least 2 characters.")
        if not validate_student_id(student_id): errors.append("Student ID must be 3-20 alphanumeric characters.")
        if email and not validate_email(email): errors.append("Please enter a valid email address.")
        if len(password) < 6: errors.append("Password must be at least 6 characters.")
        if password != confirm: errors.append("Passwords do not match.")
        conn = get_db()
        if conn.execute("SELECT id FROM students WHERE student_id = ?", (student_id,)).fetchone():
            errors.append("This Student ID is already registered.")
        conn.close()
        if errors:
            for e in errors: flash(e, "error")
            return redirect(url_for("student_register"))
        conn = get_db()
        conn.execute("INSERT INTO students (student_id, name, email, course, year_of_study, password_hash) VALUES (?, ?, ?, ?, ?, ?)",
            (student_id, name, email, course, year, generate_password_hash(password)))
        conn.commit(); conn.close()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("student_login"))
    return render_template("auth/student_register.html")


@app.route("/student/login", methods=["GET", "POST"])
@csrf_required
def student_login():
    if not rate_limiter.is_allowed(f"ip:{request.remote_addr}:login"): abort(429)
    if request.method == "POST":
        student_id = sanitize_text(request.form.get("student_id", ""), 20)
        password = request.form.get("password", "")
        conn = get_db()
        student = conn.execute("SELECT * FROM students WHERE student_id = ?", (student_id,)).fetchone()
        conn.close()
        if student and check_password_hash(student["password_hash"], password):
            session.clear()
            session["user_id"] = student["id"]
            session["user_name"] = student["name"]
            session["is_student"] = True
            session.permanent = True
            return redirect(request.args.get("next", url_for("student_dashboard")))
        flash("Invalid Student ID or password.", "error")
        return redirect(url_for("student_login"))
    return render_template("auth/student_login.html")


@app.route("/student/logout")
def student_logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.route("/student/dashboard")
@login_required
def student_dashboard():
    student = get_current_student()
    if not student: return redirect(url_for("student_logout"))
    conn = get_db()
    reviews = conn.execute(
        "SELECT r.*, l.name AS lecturer_name, l.department AS lecturer_department FROM reviews r JOIN lecturers l ON r.lecturer_id = l.id WHERE r.student_id = ? ORDER BY r.created_at DESC",
        (student["id"],)).fetchall()
    reviewed_ids = [r["lecturer_id"] for r in reviews]
    if reviewed_ids:
        ph = ",".join("?" * len(reviewed_ids))
        lecturers = conn.execute(
            f"SELECT * FROM lecturers WHERE is_active = 1 AND id NOT IN ({ph}) ORDER BY name", reviewed_ids).fetchall()
    else:
        lecturers = conn.execute("SELECT * FROM lecturers WHERE is_active = 1 ORDER BY name").fetchall()
    conn.close()
    return render_template("student/dashboard.html", student=student, reviews=reviews, lecturers=lecturers)

# ==================== LECTURER AUTH ====================

@app.route("/lecturer/register", methods=["GET", "POST"])
@csrf_required
def lecturer_register():
    if not rate_limiter.is_allowed(f"ip:{request.remote_addr}:lec_register"): abort(429)
    if request.method == "POST":
        name = sanitize_text(request.form.get("name", ""), 100)
        dept = sanitize_text(request.form.get("department", ""), 100)
        email = sanitize_text(request.form.get("email", ""), 100)
        phone = sanitize_text(request.form.get("phone", ""), 20)
        pin = request.form.get("pin", "")
        confirm = request.form.get("confirm_pin", "")
        errors = []
        if not name or len(name) < 2: errors.append("Name must be at least 2 characters.")
        if not dept: errors.append("Department is required.")
        if len(pin) < 4: errors.append("PIN must be at least 4 characters.")
        if pin != confirm: errors.append("PINs do not match.")
        if errors:
            for e in errors: flash(e, "error")
            return redirect(url_for("lecturer_register"))
        conn = get_db()
        conn.execute("INSERT INTO lecturers (name, department, email, phone, pin_hash) VALUES (?, ?, ?, ?, ?)",
            (name, dept, email, phone, generate_password_hash(pin)))
        conn.commit(); conn.close()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("lecturer_login"))
    return render_template("auth/lecturer_register.html")


@app.route("/lecturer/login", methods=["GET", "POST"])
@csrf_required
def lecturer_login():
    if not rate_limiter.is_allowed(f"ip:{request.remote_addr}:lec_login"): abort(429)
    if request.method == "POST":
        name = sanitize_text(request.form.get("name", ""), 100)
        pin = request.form.get("pin", "")
        conn = get_db()
        lecturer = conn.execute("SELECT * FROM lecturers WHERE name = ? AND is_active = 1", (name,)).fetchone()
        conn.close()
        if lecturer and check_password_hash(lecturer["pin_hash"], pin):
            session.clear()
            session["user_id"] = lecturer["id"]
            session["user_name"] = lecturer["name"]
            session["is_lecturer"] = True
            session.permanent = True
            return redirect(url_for("lecturer_dashboard"))
        flash("Invalid name or PIN.", "error")
        return redirect(url_for("lecturer_login"))
    return render_template("auth/lecturer_login.html")


@app.route("/lecturer/logout")
def lecturer_logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.route("/lecturer/dashboard")
@lecturer_required
def lecturer_dashboard():
    lecturer = get_current_lecturer()
    if not lecturer: return redirect(url_for("lecturer_logout"))
    conn = get_db()
    reviews = conn.execute(
        "SELECT r.*, s.student_id AS student_number, s.name AS student_name FROM reviews r JOIN students s ON r.student_id = s.id WHERE r.lecturer_id = ? ORDER BY r.created_at DESC",
        (lecturer["id"],)).fetchall()
    stats = conn.execute(
        "SELECT COUNT(*) AS num_reviews, ROUND(AVG(clarity),2) AS avg_clarity, ROUND(AVG(engagement),2) AS avg_engagement, ROUND(AVG(punctuality),2) AS avg_punctuality, ROUND(AVG((clarity+engagement+punctuality)/3.0),2) AS avg_overall FROM reviews WHERE lecturer_id = ?",
        (lecturer["id"],)).fetchone()
    conn.close()
    return render_template("lecturer/dashboard.html", lecturer=lecturer, reviews=reviews, stats=stats)


# ==================== ADMIN ====================

@app.route("/admin/login", methods=["GET", "POST"])
@csrf_required
def admin_login():
    if not rate_limiter.is_allowed(f"ip:{request.remote_addr}:admin_login"): abort(429)
    if request.method == "POST":
        username = sanitize_text(request.form.get("username", ""), 50)
        password = request.form.get("password", "")
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session.clear()
            session["is_admin"] = True
            session["user_name"] = "Admin"
            session.permanent = True
            return redirect(url_for("admin_dashboard"))
        flash("Invalid admin credentials.", "error")
        return redirect(url_for("admin_login"))
    return render_template("auth/admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    conn = get_db()
    total_students = conn.execute("SELECT COUNT(*) FROM students").fetchone()[0]
    total_lecturers = conn.execute("SELECT COUNT(*) FROM lecturers WHERE is_active = 1").fetchone()[0]
    total_reviews = conn.execute("SELECT COUNT(*) FROM reviews").fetchone()[0]
    avg_rating = conn.execute("SELECT ROUND(AVG((clarity+engagement+punctuality)/3.0),2) FROM reviews").fetchone()[0] or 0
    lecturers = conn.execute(
        "SELECT l.*, COUNT(r.id) AS num_reviews, ROUND(AVG((r.clarity+r.engagement+r.punctuality)/3.0),2) AS avg_rating FROM lecturers l LEFT JOIN reviews r ON l.id = r.lecturer_id WHERE l.is_active = 1 GROUP BY l.id ORDER BY l.name").fetchall()
    students = conn.execute("SELECT * FROM students ORDER BY name LIMIT 50").fetchall()
    conn.close()
    return render_template("admin/dashboard.html", total_students=total_students, total_lecturers=total_lecturers,
        total_reviews=total_reviews, avg_rating=avg_rating, lecturers=lecturers, students=students)


@app.route("/admin/lecturer/add", methods=["POST"])
@admin_required
@csrf_required
def admin_add_lecturer():
    name = sanitize_text(request.form.get("name", ""), 100)
    dept = sanitize_text(request.form.get("department", ""), 100)
    email = sanitize_text(request.form.get("email", ""), 100)
    if not name or not dept:
        flash("Name and department are required.", "error")
        return redirect(url_for("admin_dashboard"))
    conn = get_db()
    conn.execute("INSERT INTO lecturers (name, department, email) VALUES (?, ?, ?)", (name, dept, email))
    conn.commit(); conn.close()
    flash("Lecturer added successfully.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/lecturer/deactivate/<int:lecturer_id>", methods=["POST"])
@admin_required
@csrf_required
def admin_deactivate_lecturer(lecturer_id):
    conn = get_db()
    conn.execute("UPDATE lecturers SET is_active = 0 WHERE id = ?", (lecturer_id,))
    conn.commit(); conn.close()
    flash("Lecturer deactivated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/lecturer/delete/<int:lecturer_id>", methods=["POST"])
@admin_required
@csrf_required
def admin_delete_lecturer(lecturer_id):
    conn = get_db()
    conn.execute("DELETE FROM reviews WHERE lecturer_id = ?", (lecturer_id,))
    conn.execute("DELETE FROM lecturers WHERE id = ?", (lecturer_id,))
    conn.commit(); conn.close()
    flash("Lecturer deleted.", "success")
    return redirect(url_for("admin_dashboard"))


# ==================== EXPORT ====================

@app.route("/admin/export/reviews")
@admin_required
def export_all_reviews():
    conn = get_db()
    rows = conn.execute(
        "SELECT r.id, s.student_id AS sn, s.name AS sname, l.name AS lname, l.department AS ldept, r.clarity, r.engagement, r.punctuality, r.comment, r.created_at FROM reviews r JOIN lecturers l ON r.lecturer_id = l.id LEFT JOIN students s ON r.student_id = s.id ORDER BY l.name, r.created_at").fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Review ID", "Student ID", "Student Name", "Lecturer Name", "Department", "Clarity", "Engagement", "Punctuality", "Comment", "Created At"])
    for row in rows:
        writer.writerow([row["id"], row["sn"], row["sname"], row["lname"], row["ldept"], row["clarity"], row["engagement"], row["punctuality"], row["comment"], row["created_at"]])
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=all_reviews.csv"
    response.headers["Content-Type"] = "text/csv"
    return response


@app.route("/admin/export/reviews/lecturer/<int:lecturer_id>")
@admin_required
def export_reviews_by_lecturer(lecturer_id):
    conn = get_db()
    lecturer = conn.execute("SELECT * FROM lecturers WHERE id = ?", (lecturer_id,)).fetchone()
    if not lecturer:
        conn.close()
        flash("Lecturer not found.", "error")
        return redirect(url_for("admin_dashboard"))
    rows = conn.execute(
        "SELECT r.id, s.student_id AS sn, s.name AS sname, l.name AS lname, l.department AS ldept, r.clarity, r.engagement, r.punctuality, r.comment, r.created_at FROM reviews r JOIN lecturers l ON r.lecturer_id = l.id LEFT JOIN students s ON r.student_id = s.id WHERE l.id = ? ORDER BY r.created_at",
        (lecturer_id,)).fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Review ID", "Student ID", "Student Name", "Lecturer Name", "Department", "Clarity", "Engagement", "Punctuality", "Comment", "Created At"])
    for row in rows:
        writer.writerow([row["id"], row["sn"], row["sname"], row["lname"], row["ldept"], row["clarity"], row["engagement"], row["punctuality"], row["comment"], row["created_at"]])
    fname = lecturer["name"].replace(" ", "_")
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename=reviews_{fname}.csv"
    response.headers["Content-Type"] = "text/csv"
    return response


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found"), 404

@app.errorhandler(429)
def too_many_requests(e):
    return render_template("error.html", code=429, message="Too many requests."), 429

@app.errorhandler(500)
def internal_error(e):
    return render_template("error.html", code=500, message="Internal server error"), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
