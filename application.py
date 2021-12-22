import os
import time

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    if not db.execute("SELECT * FROM users INNER JOIN transactions ON users.id = transactions.user_id WHERE user_id = ?", session.get("user_id")):
        rows = db.execute("SELECT * FROM users WHERE id = ?", session.get("user_id"))

        cash = rows[0]["cash"]
        total = cash

        return render_template("index.html", rows=rows,cash=usd(cash),total=usd(total))

    rows = db.execute("SELECT symbol, SUM(shares), cash FROM transactions INNER JOIN users ON users.id = transactions.user_id WHERE user_id = ? GROUP BY symbol", session.get("user_id"))

    total_grand = 0
    cash = rows[0]["cash"]

    for row in rows:
        if row["SUM(shares)"] > 0:
            quote = lookup(row["symbol"])
            row["name"] = quote["name"]
            row["price_actual"] = usd(quote["price"])
            total_holding = quote["price"] * row["SUM(shares)"]
            row["total_holding"] = usd(total_holding)
            total_grand += total_holding

    total_grand += cash

    return render_template("index.html", rows=rows, cash=usd(cash), total_grand=usd(total_grand))

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))
        shares = int(request.form.get("shares"))
        if not request.form.get("symbol"):
            return apology("missing symbol", 400)
        if not quote:
            return apology("symbol doesn't exist", 400)
        if shares < 1:
            return apology("shares must be positive integer", 400)

        cash = db.execute("SELECT cash FROM users WHERE id = ?", session.get("user_id"))


        if lookup(request.form.get("symbol"))['price'] * shares > cash[0]["cash"]:
            return apology("can't afford", 400)

        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price, transacted) VALUES (:user_id, :symbol, :shares, :price, :transacted)",
            user_id=session["user_id"],
            symbol=request.form.get("symbol").upper(),
            shares=int(request.form.get("shares")),
            price=usd(lookup(request.form.get("symbol"))["price"]),
            transacted=time.strftime('%Y-%m-%d %H:%M:%S'))

        db.execute("UPDATE users SET cash=? WHERE id=?", cash[0]["cash"] - shares * lookup(request.form.get("symbol"))["price"],
                   session["user_id"])

        return redirect("/")
    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Query database
    rows = db.execute(
        "SELECT symbol, shares, price, transacted, cash FROM transactions INNER JOIN users ON users.id = transactions.user_id WHERE user_id = :user_id",
        user_id=session["user_id"])

    return render_template("history.html",
                           rows=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        quot = lookup(request.form.get("symbol"))
        if not request.form.get("symbol"):
            return apology("missing symbol", 400)
        if not quot:
            return apology("invalid symbol", 400)
        return render_template("quoted.html", message=lookup(request.form.get("symbol")))
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Ensure username was submitted
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("must provide username", 400)
        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)
        # If user already exists
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) == 1:
            return apology("username already exist", 400)

        # if passwords match insert to db and redirect to login page
        if password == confirmation:
            pass_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, pass_hash)
            return redirect("/login")
        else:
            return apology("don't match password")
    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    rows = db.execute("SELECT DISTINCT symbol FROM transactions WHERE user_id = ?", session.get("user_id"))

    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("missing symbol", 400)
        if int(request.form.get("shares")) < 0:
            return apology("missing shares", 400)
        rows1 = db.execute("SELECT SUM(shares) FROM transactions WHERE user_id = ? AND symbol = ?", session.get("user_id"), request.form.get("symbol"))
        if int(request.form.get("shares")) > rows1[0]["SUM(shares)"]:
            return apology("too many shares", 400)

        quote = lookup(request.form.get("symbol"))
        income = quote["price"] * int(request.form.get("shares"))

        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price, transacted) VALUES (:user_id, :symbol, :shares, :price, :transacted)",
            user_id=session["user_id"],
            symbol=request.form.get("symbol").upper(),
            shares="-"+request.form.get("shares"),
            price=usd(quote["price"]),
            transacted=time.strftime('%Y-%m-%d %H:%M:%S'))


        rows = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=session["user_id"])

        session["cash"] = rows[0]["cash"]

        cash = session["cash"] + income

        db.execute("UPDATE users SET cash=? WHERE id=?", cash, session["user_id"])
        return redirect("/")


    return render_template("sell.html",rows=rows)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
