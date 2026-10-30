import os
import sqlite3
from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "super_secret_oil_in_water_key"

# Database file path
DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), "users.db")

# Accepted date variations for 19/9/25
VALID_GA_DATES = {"19/9/25", "19/09/25", "19/9/2025", "19/09/2025"}


def get_db():
    """Connect to SQLite database and return connection."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Close the database connection at the end of each request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Initialize the database table if it doesn't exist."""
    with app.app_context():
        db = get_db()
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                ga_start_date TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        db.commit()


@app.route("/", methods=["GET", "POST"])
def login():
    """Root route: Login page. Protects the dashboard from unauthenticated access."""
    # If already logged in, redirect directly to dashboard
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            error = "Please fill in all fields."
            return render_template("index.html", error=error, email=email)

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid email or password."
            return render_template("index.html", error=error, email=email)

    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    """Dashboard page: Only accessible after logging in."""
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", email=session.get("email"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Sign up page: Requires the correct G + A start date (19/9/25)."""
    # If already logged in, redirect to dashboard
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        ga_date = request.form.get("ga", "").strip()

        # 1. Validate required fields
        if not email or not password or not ga_date:
            error = "Please fill in all fields."
            return render_template("sign_up.html", error=error, email=email)

        # 2. Check if G + A start date is 19/9/25
        if ga_date not in VALID_GA_DATES:
            error = "Incorrect G + A start date. Sign up is not allowed."
            return render_template("sign_up.html", error=error, email=email)

        db = get_db()
        # 3. Check if user already exists
        existing_user = db.execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()
        if existing_user:
            error = "An account with this email already exists."
            return render_template("sign_up.html", error=error, email=email)

        # 4. Hash password and insert into database
        hashed_password = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (email, password_hash, ga_start_date) VALUES (?, ?, ?)",
            (email, hashed_password, ga_date),
        )
        db.commit()

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("sign_up.html", error=error)


@app.route("/logout")
def logout():
    """Log out: Clears session and returns to login page."""
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# Initialize database table on startup
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1")
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
