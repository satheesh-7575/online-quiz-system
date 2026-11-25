import io
import time
import os
import secrets
import smtplib
import socket
import ssl
from datetime import datetime, timedelta
from email.message import EmailMessage

import qrcode
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from werkzeug.security import check_password_hash, generate_password_hash


# ============================================================
# Flask configuration
# ============================================================
app = Flask(__name__)

# Set these in PyCharm > Run > Edit Configurations > Environment variables.
# SECRET_KEY: generate locally with:
# python -c "import secrets; print(secrets.token_hex(32))"
app.secret_key = os.environ.get("SECRET_KEY", "").strip()
if not app.secret_key:
    raise RuntimeError(
        "SECRET_KEY is missing. Add SECRET_KEY to your PyCharm environment variables."
    )

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///quiz.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "connect_args": {"check_same_thread": False}
}
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Set COOKIE_SECURE=true only after deploying the site over HTTPS.
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("COOKIE_SECURE", "false").lower() in {"1", "true", "yes"}
)

db = SQLAlchemy(app)


# ============================================================
# Gmail SMTP configuration
# ============================================================
GMAIL_SMTP_SERVER = "smtp.gmail.com"
GMAIL_SMTP_PORT = 587
OTP_VALID_MINUTES = 10
OTP_RESEND_COOLDOWN_SECONDS = 60
OTP_MAX_ATTEMPTS = 5
OTP_VERIFIED_RESET_WINDOW_MINUTES = 10
CAPTCHA_VALID_MINUTES = 5
CAPTCHA_MAX_ATTEMPTS = 3
QUIZ_TIME_LIMIT_SECONDS = 90  # 1 minute 30 seconds


# ---------------- Gmail SMTP Configuration ----------------

GMAIL_SMTP_SERVER = "smtp.gmail.com"
GMAIL_SMTP_PORT = 587


# ---------------- Send Email Function ----------------

def send_email(to_email, subject, body):
    """
    Send an email using Gmail SMTP and Google App Password.
    Includes Python 3.13 SSL certificate compatibility.
    """

    gmail_address = os.environ.get(
        "GMAIL_ADDRESS", ""
    ).strip()

    app_password = os.environ.get(
        "GMAIL_APP_PASSWORD", ""
    ).replace(" ", "").strip()

    # Check Gmail address
    if not gmail_address:
        app.logger.error(
            "GMAIL_ADDRESS is missing from environment variables."
        )
        return False

    # Check Gmail App Password
    if not app_password:
        app.logger.error(
            "GMAIL_APP_PASSWORD is missing from environment variables."
        )
        return False
        # Create email message
    message = EmailMessage()

    message["From"] = gmail_address
    message["To"] = to_email
    message["Subject"] = subject

    message.set_content(body)

    try:

        # Create secure SSL context
        tls_context = ssl.create_default_context()

        # Python 3.13 compatibility adjustment.
        # Keep certificate and hostname verification enabled.
        if hasattr(ssl, "VERIFY_X509_STRICT"):
            tls_context.verify_flags &= ~ssl.VERIFY_X509_STRICT

        # Connect to Gmail SMTP server
        with smtplib.SMTP(
                GMAIL_SMTP_SERVER,
                GMAIL_SMTP_PORT,
                timeout=30
        ) as server:

            # Identify client
            server.ehlo()

            # Establish secure TLS connection
            server.starttls(context=tls_context)

            # Identify client again after TLS
            server.ehlo()

            # Login using Gmail App Password
            server.login(
                gmail_address,
                app_password
            )

            # Send email
            server.send_message(message)

        app.logger.info(
            "Email sent successfully to recipient."
        )

        return True

    except smtplib.SMTPAuthenticationError:

        app.logger.exception(
            "Gmail authentication failed. "
            "Check Gmail address and App Password."
        )

        return False

    except ssl.SSLCertVerificationError:

        app.logger.exception(
            "SSL certificate verification failed. "
            "Check your certificate chain or network."
        )

        return False

    except (smtplib.SMTPException, OSError):

        app.logger.exception(
            "Gmail SMTP email sending failed."
        )

        return False

    except Exception:

        app.logger.exception(
            "Unexpected error while sending email."
        )

        return False
# ============================================================
# Helpers
# ============================================================
def utcnow():
    """Return a naive UTC datetime for consistent SQLite comparisons."""
    return datetime.utcnow()


def make_captcha():
    """Create a short arithmetic CAPTCHA and store only its answer hash."""
    # Remove old challenges to keep the table small.
    expiry_cutoff = utcnow() - timedelta(minutes=CAPTCHA_VALID_MINUTES)
    CaptchaChallenge.query.filter(
        CaptchaChallenge.created_at < expiry_cutoff
    ).delete(synchronize_session=False)

    first = secrets.randbelow(8) + 2
    second = secrets.randbelow(8) + 2
    if secrets.randbelow(2):
        question = f"What is {first} + {second}?"
        answer = str(first + second)
    else:
        larger = max(first, second)
        smaller = min(first, second)
        question = f"What is {larger} - {smaller}?"
        answer = str(larger - smaller)

    challenge_id = secrets.token_urlsafe(24)
    challenge = CaptchaChallenge(
        id=challenge_id,
        question=question,
        answer_hash=generate_password_hash(answer),
        created_at=utcnow(),
        attempts=0,
    )
    db.session.add(challenge)
    db.session.commit()
    return challenge

def get_active_reset_otp():
    """Find the OTP record associated with this browser session."""
    otp_id = session.get("password_reset_otp_id")
    if not otp_id:
        return None
    return db.session.get(PasswordResetOTP, otp_id)

def validate_csrf():
    """Validate the CSRF token on password-reset forms."""
    submitted = request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")
    if not submitted or not expected or not secrets.compare_digest(submitted, expected):
        abort(400, description="The form expired. Please go back and try again.")


@app.context_processor
def inject_csrf_token():
    def csrf_token():
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_urlsafe(32)
        return session["_csrf_token"]

    return {"csrf_token": csrf_token}


# ============================================================
# Database models
# ============================================================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)  # stored email
    password = db.Column(db.String(200), nullable=False)


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.String(300), nullable=False)
    option_a = db.Column(db.String(100), nullable=False)
    option_b = db.Column(db.String(100), nullable=False)
    option_c = db.Column(db.String(100), nullable=False)
    option_d = db.Column(db.String(100), nullable=False)
    correct_answer = db.Column(db.String(1), nullable=False)
    category = db.Column(db.String(100), nullable=False)
class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    user = db.relationship("User", backref=db.backref("scores", lazy=True))
class CaptchaChallenge(db.Model):
    __tablename__ = "captcha_challenge"
    id = db.Column(db.String(100), primary_key=True)
    question = db.Column(db.String(100), nullable=False)
    answer_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
class PasswordResetOTP(db.Model):
    __tablename__ = "password_reset_otp"
    id = db.Column(db.String(100), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    otp_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    verified_at = db.Column(db.DateTime, nullable=True)
    used = db.Column(db.Boolean, nullable=False, default=False)
    user = db.relationship("User", backref=db.backref("password_reset_otps", lazy=True))


# ============================================================
# Main routes
# ============================================================
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip().lower()

        password = request.form.get("password", "")

        # Check empty fields
        if not username or not password:
            flash(
                "Please enter your email and password.",
                "error"
            )
            return redirect(url_for("signup"))

        # Check minimum password length
        if len(password) < 8:
            flash(
                "Password must contain at least 8 characters.",
                "error"
            )
            return redirect(url_for("signup"))

        # Check whether the account already exists
        existing_user = User.query.filter_by(
            username=username
        ).first()

        if existing_user:
            flash(
                "This email is already registered. Please log in.",
                "error"
            )
            return redirect(url_for("signup"))

        # Hash the password before saving
        hashed_password = generate_password_hash(password)

        new_user = User(
            username=username,
            password=hashed_password
        )

        try:
            db.session.add(new_user)
            db.session.commit()

            flash(
                "Account created successfully! You can now log in.",
                "success"
            )

            return redirect(url_for("login"))

        except Exception:
            db.session.rollback()

            app.logger.exception("Signup failed.")

            flash(
                "Unable to create your account. Please try again.",
                "error"
            )

            return redirect(url_for("signup"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["username"] = user.username
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password. Please try again.", "error")
        return redirect(url_for("login"))

    return render_template("login.html")
@app.route("/dashboard")
def dashboard():
    if "user_id" in session:
        return render_template("dashboard.html", username=session["username"])
    return redirect(url_for("login"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out safely.", "success")
    return redirect(url_for("home"))
# ============================================================
# QR-code routes
# ============================================================
def get_local_ip():
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        if sock is not None:
            sock.close()
@app.route("/qr")
def qr():
    server_url = f"http://{get_local_ip()}:5000"
    image = qrcode.make(server_url)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    buffer.seek(0)
    return send_file(buffer, mimetype="image/png")

# ============================================================
# Forgot password: CAPTCHA -> Gmail OTP -> new password
# ============================================================
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        challenge = make_captcha()
        return render_template(
            "forgot_password.html",
            captcha_id=challenge.id,
            captcha_question=challenge.question,
        )
    validate_csrf()

    email = request.form.get("username", "").strip().lower()
    captcha_id = request.form.get("captcha_id", "")
    captcha_answer = request.form.get("captcha_answer", "").strip()
    challenge = db.session.get(CaptchaChallenge, captcha_id)

    if not challenge:
        flash("CAPTCHA expired. Please try again.", "error")
        new_challenge = make_captcha()
        return render_template(
            "forgot_password.html",
            captcha_id=new_challenge.id,
            captcha_question=new_challenge.question,
        ), 400
    if (
            challenge.created_at + timedelta(minutes=CAPTCHA_VALID_MINUTES) < utcnow()
            or challenge.attempts >= CAPTCHA_MAX_ATTEMPTS
    ):
        db.session.delete(challenge)
        db.session.commit()
        flash("CAPTCHA expired. Please solve the new question.", "error")
        new_challenge = make_captcha()
        return render_template(
            "forgot_password.html",
            captcha_id=new_challenge.id,
            captcha_question=new_challenge.question,
        ), 400
    challenge.attempts += 1
    captcha_valid = check_password_hash(challenge.answer_hash, captcha_answer)

    if not captcha_valid:
        if challenge.attempts >= CAPTCHA_MAX_ATTEMPTS:
            db.session.delete(challenge)
            db.session.commit()
            flash("Too many incorrect CAPTCHA answers. Solve a new question.", "error")
            new_challenge = make_captcha()
            return render_template(
                "forgot_password.html",
                captcha_id=new_challenge.id,
                captcha_question=new_challenge.question,
            ), 400
        db.session.commit()
        flash(
            f"CAPTCHA answer is incorrect. Try again ({CAPTCHA_MAX_ATTEMPTS - challenge.attempts} attempt(s) left).",
            "error",
        )
        return render_template(
            "forgot_password.html",
            captcha_id=challenge.id,
            captcha_question=challenge.question,
        ), 400
        # A CAPTCHA challenge can be used only once.
    db.session.delete(challenge)
    db.session.commit()

    if not email:
        flash("Please enter your registered email address.", "error")
        new_challenge = make_captcha()
        return render_template(
            "forgot_password.html",
            captcha_id=new_challenge.id,
            captcha_question=new_challenge.question,
        ), 400
    user = User.query.filter_by(username=email).first()
    # Keep the response wording general so the page does not disclose account status.
    if not user:
        flash(
            "If that email is registered, a verification code will be sent. "
            "Please check your inbox and Spam folder.",
            "success",
        )
        return redirect(url_for("forgot_password"))

    now = utcnow()
    latest_otp = (
        PasswordResetOTP.query.filter_by(user_id=user.id, used=False)
        .order_by(desc(PasswordResetOTP.created_at))
        .first()
    )

    if latest_otp and latest_otp.created_at + timedelta(
            seconds=OTP_RESEND_COOLDOWN_SECONDS
    ) > now:
        session["password_reset_otp_id"] = latest_otp.id
        flash(
            "A code was sent recently. Please use the code in your email or wait "
            "before requesting another one.",
            "info",
        )
        return redirect(url_for("verify_otp"))
    # Invalidate older unused OTPs before creating a new code.
    PasswordResetOTP.query.filter_by(user_id=user.id, used=False).update(
        {PasswordResetOTP.used: True}, synchronize_session=False
    )
    otp = f"{secrets.randbelow(1_000_000):06d}"
    otp_record = PasswordResetOTP(
        id=secrets.token_urlsafe(32),
        user_id=user.id,
        otp_hash=generate_password_hash(otp),
        created_at=now,
        expires_at=now + timedelta(minutes=OTP_VALID_MINUTES),
        attempts=0,
        verified_at=None,
        used=False,
    )
    db.session.add(otp_record)
    db.session.commit()

    subject = "Your Online Quiz System password-reset code"
    body = (
        f"Your password-reset verification code is: {otp}\n\n"
        f"This code expires in {OTP_VALID_MINUTES} minutes and can be used once.\n"
        "If you did not request a password reset, you can ignore this email.\n\n"
        "Online Quiz System"
    )

    if not send_email(user.username, subject, body):
        otp_record.used = True
        db.session.commit()
        app.logger.error("Could not send password-reset OTP email.")
        flash(
            "We could not send the email. Check the Gmail settings in PyCharm "
            "and try again.",
            "error",
        )
        return redirect(url_for("forgot_password"))
    session["password_reset_otp_id"] = otp_record.id
    flash(
        f"A six-digit verification code was sent to {user.username}. "
        f"It expires in {OTP_VALID_MINUTES} minutes.",
        "success",
    )
    return redirect(url_for("verify_otp"))


@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    otp_record = get_active_reset_otp()
    if not otp_record or otp_record.used:
        session.pop("password_reset_otp_id", None)
        flash("Please request a new password-reset code.", "error")
        return redirect(url_for("forgot_password"))

    if otp_record.expires_at < utcnow():
        otp_record.used = True
        db.session.commit()
        session.pop("password_reset_otp_id", None)
        flash("Your verification code has expired. Please request a new one.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        validate_csrf()
        entered_otp = request.form.get("otp", "").strip()

        if otp_record.verified_at:
            return redirect(url_for("reset_password"))

        if otp_record.attempts >= OTP_MAX_ATTEMPTS:
            otp_record.used = True
            db.session.commit()
            session.pop("password_reset_otp_id", None)
            flash("Too many incorrect attempts. Request a new code.", "error")
            return redirect(url_for("forgot_password"))

        otp_record.attempts += 1
        is_valid = (
            len(entered_otp) == 6
            and entered_otp.isdigit()
            and check_password_hash(otp_record.otp_hash, entered_otp)
        )
        if not is_valid:
            db.session.commit()
            remaining = OTP_MAX_ATTEMPTS - otp_record.attempts
            flash(
                f"Incorrect code. You have {remaining} attempt(s) remaining.",
                "error",
            )
            return redirect(url_for("verify_otp"))

        otp_record.verified_at = utcnow()
        db.session.commit()
        flash("Email verified. You can now set a new password.", "success")
        return redirect(url_for("reset_password"))
    return render_template(
        "verify_otp.html",
        email=otp_record.user.username,
        expires_minutes=OTP_VALID_MINUTES,
    )
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    otp_record = get_active_reset_otp()
    if not otp_record or otp_record.used:
        session.pop("password_reset_otp_id", None)
        flash("Please verify your email before changing your password.", "error")
        return redirect(url_for("forgot_password"))

    now = utcnow()
    if (
        otp_record.expires_at < now
        or not otp_record.verified_at
        or otp_record.verified_at + timedelta(
            minutes=OTP_VERIFIED_RESET_WINDOW_MINUTES
        ) < now
    ):
        otp_record.used = True
        db.session.commit()
        session.pop("password_reset_otp_id", None)
        flash("Your verification session expired. Please request a new code.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        validate_csrf()
        new_password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(new_password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return render_template("reset_password.html"), 400

        if new_password != confirm_password:
            flash("The passwords do not match. Please try again.", "error")
            return render_template("reset_password.html"), 400

        user = db.session.get(User, otp_record.user_id)
        if not user:
            otp_record.used = True
            db.session.commit()
            session.pop("password_reset_otp_id", None)
            flash("Account not found. Please contact support.", "error")
            return redirect(url_for("login"))

        user.password = generate_password_hash(new_password)
        otp_record.used = True
        # Invalidate all other unused reset codes for this account.
        PasswordResetOTP.query.filter(
            PasswordResetOTP.user_id == user.id,
            PasswordResetOTP.id != otp_record.id,
            PasswordResetOTP.used.is_(False),
        ).update({PasswordResetOTP.used: True}, synchronize_session=False)
        db.session.commit()

        session.pop("password_reset_otp_id", None)
        flash("Password changed successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")
# ============================================================
# Quiz and leaderboard routes
# ============================================================
@app.route("/choose_category")
def choose_category():
    categories = [
        row[0]
        for row in db.session.query(Question.category).distinct().all()
    ]
    return render_template("choose_category.html", categories=categories)


# ---------------- Start Quiz with 90-second timer ----------------

@app.route("/start_quiz", methods=["POST"])
def start_quiz():

    if "user_id" not in session:
        return redirect(url_for("login"))

    selected_category = request.form.get("category", "")

    questions = Question.query.filter_by(
        category=selected_category
    ).order_by(Question.id.asc()).all()

    if not questions:
        flash("No questions available in this category.", "error")
        return redirect(url_for("choose_category"))

    # Store quiz start time and question IDs in the session
    session["quiz_started_at"] = time.time()
    session["quiz_category"] = selected_category
    session["quiz_question_ids"] = [
        question.id for question in questions
    ]

    return render_template(
        "quiz.html",
        questions=questions,
        category=selected_category,
        quiz_started_at=session["quiz_started_at"],
        quiz_time_limit=QUIZ_TIME_LIMIT_SECONDS
    )

@app.route("/submit_quiz", methods=["POST"])
def submit_quiz():
    if "user_id" not in session:
        return redirect(url_for("login"))

    validate_csrf()

    selected_category = request.form.get("category", "")

    started_at = session.pop("quiz_started_at", None)
    expected_category = session.pop("quiz_category", None)
    question_ids = session.pop("quiz_question_ids", [])

    # Verify the active quiz session
    if (
        started_at is None
        or expected_category != selected_category
        or not question_ids
    ):
        flash("Quiz session expired. Please start again.", "error")
        return redirect(url_for("choose_category"))

    elapsed_time = time.time() - float(started_at)

    timed_out = elapsed_time >= QUIZ_TIME_LIMIT_SECONDS

    # Allow 10 seconds for automatic submission/network delay.
    # Ignore answers submitted considerably after the deadline.
    ignore_answers = elapsed_time > (QUIZ_TIME_LIMIT_SECONDS + 10)

    questions = (
        Question.query
        .filter(
            Question.id.in_(question_ids),
            Question.category == selected_category
        )
        .order_by(Question.id.asc())
        .all()
    )

    if not questions:
        flash("Quiz questions could not be found.", "error")
        return redirect(url_for("choose_category"))

    score_value = 0
    answer_review = []

    for index, question in enumerate(questions, start=1):

        options = {
            "A": question.option_a,
            "B": question.option_b,
            "C": question.option_c,
            "D": question.option_d
        }

        selected_answer = request.form.get(
            f"q{question.id}", ""
        )

        if ignore_answers:
            selected_answer = ""

        correct_answer = question.correct_answer

        is_correct = (
            selected_answer == correct_answer
            and selected_answer != ""
        )

        if is_correct:
            score_value += 1

        answer_review.append({
            "number": index,
            "question": question.question_text,
            "selected_answer": (
                f"{selected_answer} - {options[selected_answer]}"
                if selected_answer in options
                else "Not answered"
            ),
            "correct_answer": (
                f"{correct_answer} - {options[correct_answer]}"
            ),
            "is_correct": is_correct
        })

    # Save the score
    new_score = Score(
        user_id=session["user_id"],
        score=score_value,
        total=len(questions),
        category=selected_category
    )

    db.session.add(new_score)
    db.session.commit()
    # Display results and correct answers
    return render_template(
        "results.html",
        score=score_value,
        total=len(questions),
        category=selected_category,
        answer_review=answer_review,
        timed_out=timed_out
    )
# ---------------- Admin helper ----------------

def is_admin_user():
    admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()

    return (
        bool(admin_email)
        and "user_id" in session
        and session.get("username", "").strip().lower() == admin_email
    )


# ---------------- Top 10 Leaderboard ----------------

@app.route("/leaderboard/<category>")
def leaderboard(category):

    all_scores = (
        Score.query
        .filter_by(category=category)
        .order_by(
            Score.score.desc(),
            Score.total.desc(),
            Score.id.asc()
        )
        .all()
    )

    # Display each player's highest score only.
    best_scores = {}

    for score in all_scores:
        if score.user_id not in best_scores:
            best_scores[score.user_id] = score

    scores = list(best_scores.values())[:10]

    return render_template(
        "leaderboard.html",
        scores=scores,
        category=category,
        is_admin=is_admin_user()
    )
# ---------------- Admin: Clear Category Leaderboard ----------------

@app.route(
    "/admin/leaderboard/clear/<category>",
    methods=["POST"]
)
def admin_clear_leaderboard(category):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_admin_user():
        abort(403)

    # Verify the CSRF token before deleting records.
    validate_csrf()

    deleted_count = (
        Score.query
        .filter_by(category=category)
        .delete(synchronize_session=False)
    )

    db.session.commit()

    flash(
        f"Successfully cleared {deleted_count} leaderboard records "
        f"for {category}.",
        "success"
    )

    return redirect(
        url_for("leaderboard", category=category)
    )


@app.route("/admin/leaderboard/clear-all", methods=["POST"])
def admin_clear_all_leaderboard():
    """Allow only the configured admin to clear every saved quiz score."""
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_admin_user():
        abort(403)

    validate_csrf()
    deleted_count = Score.query.delete(synchronize_session=False)
    db.session.commit()
    flash(f"Successfully cleared all {deleted_count} leaderboard records.", "success")
    return redirect(url_for("choose_category"))


# ============================================================
# Gmail SMTP test route (keeps the old route path)
# ============================================================
@app.route("/test_email_api")
def test_email_api():
    gmail_address = os.environ.get("GMAIL_ADDRESS", "").strip()
    if not gmail_address:
        return "GMAIL_ADDRESS is missing. Check PyCharm environment variables.", 500

    success = send_email(
        gmail_address,
        "Gmail SMTP test - Online Quiz System",
        "This is a test email sent using Gmail SMTP from your Flask application.",
    )
    if success:
        return (
            "Test email sent successfully using Gmail SMTP. "
            "Check your inbox and Spam folder."
        )
    return "Email failed. Check the PyCharm Run console for the Gmail SMTP error.", 500
# ============================================================
# Initial database questions (21 total, kept from your project)
# ============================================================
INITIAL_QUESTIONS = [
    # Science & Space
    ("Which planet is called the 'Blue Planet'?", "Earth", "Mars", "Neptune", "Venus", "A", "Science & Space"),
    ("What gas do humans need to breathe?", "Carbon Dioxide", "Oxygen", "Nitrogen", "Hydrogen", "B", "Science & Space"),
    ("Who proposed the theory of relativity?", "Isaac Newton", "Albert Einstein", "Galileo Galilei", "Nikola Tesla", "B", "Science & Space"),
    ("What is the chemical symbol for gold?", "Au", "Ag", "Fe", "Pb", "A", "Science & Space"),
    ("Which planet has the largest volcano in the solar system?", "Mars", "Earth", "Jupiter", "Venus", "A", "Science & Space"),
    ("What force keeps us on the ground?", "Magnetism", "Gravity", "Friction", "Pressure", "B", "Science & Space"),
    ("What is the speed of light in vacuum (approx)?", "300,000 km/s", "150,000 km/s", "1,000 km/s", "30,000 km/s", "A", "Science & Space"),

    # Sports & Games
    ("How many players are on a cricket team?", "9", "10", "11", "12", "C", "Sports & Games"),
    ("Which country won the FIFA World Cup in 2018?", "Brazil", "France", "Germany", "Argentina", "B", "Sports & Games"),
    ("What is the national sport of Japan?", "Sumo Wrestling", "Baseball", "Karate", "Judo", "A", "Sports & Games"),
    ("In chess, which piece can move in an 'L' shape?", "Knight", "Bishop", "Rook", "Queen", "A", "Sports & Games"),
    ("Who is known as the 'God of Cricket'?", "MS Dhoni", "Virat Kohli", "Sachin Tendulkar", "Kapil Dev", "C", "Sports & Games"),
    ("What color card in football means a player is sent off?", "Yellow", "Red", "Blue", "Green", "B", "Sports & Games"),
    ("Which sport uses a shuttlecock?", "Badminton", "Tennis", "Squash", "Table Tennis", "A", "Sports & Games"),

    # Movies & TV Shows
    ("Who directed the movie Inception?", "Christopher Nolan", "Steven Spielberg", "James Cameron", "Quentin Tarantino", "A", "Movies & TV Shows"),
    ("Which superhero is also called the 'Caped Crusader'?", "Superman", "Batman", "Spider-Man", "Iron Man", "B", "Movies & TV Shows"),
    ("Who played Jack in the movie Titanic?", "Leonardo DiCaprio", "Tom Cruise", "Brad Pitt", "Johnny Depp", "A", "Movies & TV Shows"),
    ("In Harry Potter, what house does Harry belong to?", "Slytherin", "Hufflepuff", "Ravenclaw", "Gryffindor", "D", "Movies & TV Shows"),
    ("Who voices Woody in Toy Story?", "Tom Hanks", "Tim Allen", "Robin Williams", "Chris Evans", "A", "Movies & TV Shows"),
    ("Which streaming service released Stranger Things?", "Netflix", "Amazon Prime", "Disney+", "HBO Max", "A", "Movies & TV Shows"),
    ("What is the name of the lion in The Lion King?", "Mufasa", "Scar", "Simba", "Nala", "C", "Movies & TV Shows"),
]


def initialize_database():
    with app.app_context():
        db.create_all()
        if not Question.query.first():
            for item in INITIAL_QUESTIONS:
                (
                    question_text,
                    option_a,
                    option_b,
                    option_c,
                    option_d,
                    answer,
                    category,
                ) = item
                db.session.add(
                    Question(
                        question_text=question_text,
                        option_a=option_a,
                        option_b=option_b,
                        option_c=option_c,
                        option_d=option_d,
                        correct_answer=answer,
                        category=category,
                    )
                )
            db.session.commit()


if __name__ == "__main__":
    initialize_database()
    app.run(debug=True, host="0.0.0.0", port=5000)
