# code (1).py
from reports import get_total_deposits, get_most_popular_game, get_new_users, get_user_activity
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import SQLAlchemyError
from forms import RegisterForm  # Import Flask-WTF Forms
from sqlalchemy import func
import os
import logging
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "your_secret_key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///betting.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
bcrypt = Bcrypt(app)  # Initialize Bcrypt

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Import models after db initialization
from models import User, Transaction, GameHistory, Settings

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            username = form.username.data
            password = form.password.data
            phone_number = form.phone_number.data #Changed to phone number
            referral_code = form.referral_code.data

            if User.query.filter_by(username=username).first():
                flash("Username already exists!", "danger")
                return render_template("register.html", form=form)
            if User.query.filter_by(phone_number=phone_number).first():
                flash("Phone number already exists!", "danger")
                return render_template("register.html", form=form)

            import uuid
            unique_ref_code = str(uuid.uuid4())[:8]
            # Hash the password using bcrypt
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(username=username, phone_number = phone_number, password_hash=hashed_password, referral_code=unique_ref_code)
            db.session.add(user)

            if referral_code:
                referrer = User.query.filter_by(referral_code=referral_code).first()
                if referrer:
                    # Store the referrer's ID in the new user's session for later
                    session['referrer_id'] = referrer.id

            db.session.commit()
            login_user(user)
            flash("Account created successfully!", "success")
            return redirect(url_for("dashboard"))
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error during registration: {str(e)}")
            flash("Database error occurred during registration.", "danger")
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            flash("An error occurred during registration.", "danger")

        return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        try:
            phone_number = request.form["phone_number"]
            password = request.form["password"]
            user = User.query.filter_by(phone_number=phone_number).first()

            if user and bcrypt.check_password_hash(user.password_hash, password):
                login_user(user)
                return redirect(url_for("dashboard"))

            flash("Invalid phone_number or password!", "danger")
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error during login: {str(e)}")
            flash("Database error occurred during login.", "danger")
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash("An error occurred during login.", "danger")

    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).limit(5).all()
    game_history = GameHistory.query.filter_by(user_id=current_user.id).order_by(GameHistory.timestamp.desc()).limit(5).all()
    return render_template("dashboard.html",
                         balance=current_user.balance,
                         transactions=transactions,
                         game_history=game_history)

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")

@app.route("/transactions")
@login_required
def transactions():
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).all()
    return render_template("transactions.html", transactions=transactions)

@app.route("/deposit", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def deposit():
    try:
        amount = Decimal(request.form["amount"]) # Make sure you're handling the amount as a decimal
        payment_method = request.form["payment_method"]

        if amount < 100:
            flash("Minimum deposit amount is 100 PKR.", "danger")
            return redirect(url_for("dashboard"))

        if payment_method not in ["easypaisa", "jazzcash"]:
            flash("Invalid payment method selected.", "danger")
            return redirect(url_for("dashboard"))

        payment_number = Settings.get_value(f'{payment_method}_number')
        if not payment_number:
            flash("Payment method currently unavailable.", "danger")
            return redirect(url_for("dashboard"))
        #Check referral bonus
        if 'referrer_id' in session:
            referrer = User.query.get(session['referrer_id'])
            if referrer:
                referrer.balance += Decimal('50.00')  # Award 50 PKR bonus
                transaction = Transaction(
                    user_id=referrer.id,
                    amount=Decimal('50.00'),
                    type="referral_bonus",
                    status="Approved"
                )
                db.session.add(transaction)
                flash(f"Referral bonus of 50 PKR credited to {referrer.username}!", "success")

            # Clear the session variable to prevent duplicate bonus awards
            session.pop('referrer_id', None)

        return render_template("payment_verification.html",
                             amount=amount,
                             payment_method=payment_method,
                             payment_number=payment_number)

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error during deposit: {str(e)}")
        flash("Database error occurred during deposit.", "danger")
        return redirect(url_for("dashboard"))
    except Exception as e:
        logger.error(f"Deposit error: {str(e)}")
        flash("An error occurred during deposit.", "danger")
        return redirect(url_for("dashboard"))

@app.route("/withdraw", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def withdraw():
    try:
        amount = float(request.form["amount"])
        if amount <= 0 or amount > current_user.balance:
            flash("Invalid withdrawal amount!", "danger")
            return redirect(url_for("dashboard"))

        transaction = Transaction(
            user_id=current_user.id,
            amount=amount,
            type="withdraw",
            status="Pending",
            timestamp=datetime.utcnow()
        )
        db.session.add(transaction)
        db.session.commit()

        flash("Withdrawal request submitted for approval!", "info")
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error during withdrawal: {str(e)}")
        flash("Database error occurred during withdrawal.", "danger")
    except Exception as e:
        logger.error(f"Withdrawal error: {str(e)}")
        flash("An error occurred during withdrawal.", "danger")

    return redirect(url_for("dashboard"))


@app.route("/admin-auth", methods=["POST"])
@limiter.limit("5 per minute")
def admin_auth():
    password = request.form.get("admin_password")

    # Fetch the stored admin password hash from the database
    stored_password_hash = Settings.get_value('admin_password')

    if stored_password_hash and bcrypt.check_password_hash(stored_password_hash, password):
        session['is_super_admin'] = True
        flash("Admin access granted!", "success")
        return redirect(url_for("admin"))
    else:
        flash("Invalid admin password!", "danger")
        return redirect(url_for("dashboard"))


@app.route("/admin")
def admin():
    if not session.get('is_super_admin'):
        flash("Unauthorized access!", "danger")
        return redirect(url_for("dashboard"))

    # Date range for reports (example)
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)  # Last 30 days

    # Get admin statistics
    total_users = User.query.count()
    total_deposits = get_total_deposits(start_date, end_date)
    total_withdrawals = Transaction.query.filter_by(type="withdraw", status="Approved").with_entities(db.func.sum(Transaction.amount)).scalar() or 0
    pending_transactions = Transaction.query.filter_by(status="Pending").all()
    phone_number = Settings.get_value('deposit_phone', '') # Added to get phone number from settings
    easypaisa_number = Settings.get_value('easypaisa_number', '')
    jazzcash_number = Settings.get_value('jazzcash_number', '')

    most_popular_game, popular_count = get_most_popular_game(start_date, end_date)
    new_users = get_new_users(start_date, end_date)
    user_activity = get_user_activity(start_date, end_date)

    return render_template("admin.html",
                         transactions=pending_transactions,
                         total_users=total_users,
                         total_deposits=total_deposits,
                         total_withdrawals=total_withdrawals,
                         phone_number=Settings.get_value('deposit_phone', ''),
                         easypaisa_number=Settings.get_value('easypaisa_number', ''),
                         jazzcash_number=Settings.get_value('jazzcash_number', ''),
                         most_popular_game=most_popular_game,
                         popular_count = popular_count,
                         new_users = new_users,
                         user_activity = user_activity,
                         settings=Settings)


@app.route("/admin/approve/<int:transaction_id>")
@login_required
def approve_transaction(transaction_id):
    if not session.get('is_super_admin'):
        flash("Unauthorized access!", "danger")
        return redirect(url_for("dashboard"))

    try:
        transaction = Transaction.query.get_or_404(transaction_id)
        if transaction.type == "withdraw":
            user = User.query.get(transaction.user_id)
            if user.balance >= transaction.amount:
                transaction.status = "Approved"
                user.balance -= transaction.amount
                db.session.commit()
                flash("Transaction approved successfully!", "success")
            else:
                flash("User has insufficient balance!", "danger")
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error during transaction approval: {str(e)}")
            flash("Database error occurred while processing the transaction.", "danger")
            return redirect(url_for("admin"))
        except Exception as e:
            logger.error(f"Transaction approval error: {str(e)}")
            flash("An error occurred while processing the transaction.", "danger")
            return redirect(url_for("admin"))

        return redirect(url_for("admin"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

@app.route("/admin/search")
def admin_search():
    if not session.get('is_super_admin'):
        flash("Unauthorized access!", "danger")
        return redirect(url_for("dashboard"))

    query = request.args.get('query', '').strip()
    user_profile = None  # Initialize user_profile to None
    search_results = []

    if query:
        # Search by User ID (if query is numeric and 8 characters long)
        if query.isdigit() and len(query) == 8:
            user = User.query.get(int(query))
            if user:
                user_profile = user  # Assign user object to user_profile

        # Search by username (case-insensitive) - if not a user ID
        if not user_profile:  # Only search by username if no user ID was found
            search_results = User.query.filter(User.username.ilike(f"%{query}%")).all()

        # Date range for reports (example)
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)  # Last 30 days

        # Get admin statistics
        total_users = User.query.count()
        total_deposits = get_total_deposits(start_date, end_date)
        total_withdrawals = Transaction.query.filter_by(type="withdraw", status="Approved").with_entities(db.func.sum(Transaction.amount)).scalar() or 0
        pending_transactions = Transaction.query.filter_by(status="Pending").all()

        return render_template("admin.html",
                             user_profile=user_profile,  # Pass user_profile to the template
                             search_results=search_results,
                             transactions=pending_transactions,
                             total_users=total_users,
                             total_deposits=total_deposits,
                             total_withdrawals=total_withdrawals,
                             phone_number=Settings.get_value('deposit_phone', ''),
                             easypaisa_number=Settings.get_value('easypaisa_number', ''),
                             jazzcash_number=Settings.get_value('jazzcash_number', ''),
                             settings=Settings)

@app.route("/admin/adjust-balance", methods=["POST"])
def admin_adjust_balance():
    if not session.get('is_super_admin'):
        flash("Unauthorized access!", "danger")
        return redirect(url_for("dashboard"))

    try:
        user_id = request.form.get('user_id', type=int)
        new_balance = request.form.get('new_balance', type=float)

        if not user_id or new_balance is None or new_balance < 0:
            flash("Invalid balance adjustment parameters!", "danger")
            return redirect(url_for("admin"))

        user = User.query.get_or_404(user_id)
        old_balance = User.query.filter_by(id=user_id).with_entities(func.sum(User.balance)).scalar() or 0
        user.balance = new_balance

        # Log the balance adjustment
        logger.info(f"Admin adjusted balance for user {user.username} (ID: {user.id}) from {old_balance} to {new_balance}")

        db.session.commit()
        flash(f"Successfully updated balance for user {user.username}!", "success")
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error during balance adjustment: {str(e)}")
        flash("Database error occurred while adjusting the balance.", "danger")
        return redirect(url_for("admin_search", query=request.args.get('query', '')))
    except Exception as e:
        logger.error(f"Balance adjustment error: {str(e)}")
        flash("An error occurred while adjusting the balance.", "danger")
        return redirect(url_for("admin_search", query=request.args.get('query', '')))

@app.route("/admin/add-funds", methods=["POST"])
def admin_add_funds():
    if not session.get('is_super_admin'):
        flash("Unauthorized access!", "danger")
        return redirect(url_for("dashboard"))

    try:
        user_id = request.form.get('user_id', type=int)
        amount = request.form.get('amount', type=float)

        if not user_id or not amount or amount <= 0:
            flash("Invalid amount specified!", "danger")
            return redirect(url_for("admin"))

        user = User.query.get_or_404(user_id)
        user.balance += amount

        # Log the transaction
        transaction = Transaction(
            user_id=user_id,
            amount=amount,
            type="deposit",
            status="Approved",
            timestamp=datetime.utcnow()
        )
        db.session.add(transaction)
        db.session.commit()

        logger.info(f"Admin added {amount} PKR to user {user.username} (ID: {user.id})")
        flash(f"Successfully added {amount} PKR to {user.username}'s account!", "success")
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error during adding funds: {str(e)}")
        flash("Database error occurred while adding funds.", "danger")
        return redirect(url_for("admin_search", query=request.args.get('query', '')))
    except Exception as e:
        logger.error(f"Add funds error: {str(e)}")
        flash("An error occurred while adding funds.", "danger")
        return redirect(url_for("admin_search", query=request.args.get('query', '')))

@app.route("/admin/remove-funds", methods=["POST"])
def admin_remove_funds():
    if not session.get('is_super_admin'):
        flash("Unauthorized access!", "danger")
        return redirect(url_for("dashboard"))

    try:
        user_id = request.form.get('user_id', type=int)
        amount = request.form.get('amount', type=float)

        if not user_id or not amount or amount <= 0:
            flash("Invalid amount specified!", "danger")
            return redirect(url_for("admin"))

        user = User.query.get_or_404(user_id)
        if user.balance < amount:
            flash("Insufficient balance!", "danger")
            return redirect(url_for("admin"))

        user.balance -= amount

        # Log the transaction
        transaction = Transaction(
            user_id=user_id,
            amount=amount,
            type="withdraw",
            status="Approved",
            timestamp=datetime.utcnow()
        )
        db.session.add(transaction)
        db.session.commit()

        logger.info(f"Admin removed {amount} PKR from user {user.username} (ID: {user.id})")
        flash(f"Successfully removed {amount} PKR from {user.username}'s account!", "success")
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error during removing funds: {str(e)}")
        flash("Database error occurred while removing funds.", "danger")
        return redirect(url_for("admin_search", query=request.args.get('query', '')))
    except Exception as e:
        logger.error(f"Remove funds error: {str(e)}")
        flash("An error occurred while removing funds.", "danger")
        return redirect(url_for("admin_search", query=request.args.get('query', '')))

@app.route("/admin/change-password", methods=["POST"])
def admin_change_password():
    if not session.get('is_super_admin'):
        flash("Unauthorized access!", "danger")
        return redirect(url_for("dashboard"))

    try:
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')

        # Fetch
