from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from mysql.connector import Error
import bcrypt
import os
from dotenv import load_dotenv
from flask_session import Session
from datetime import datetime
import uuid

load_dotenv()

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY")
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Database connection
def get_env():
    ip = os.environ.get("MYSQL_IP")
    username_db = os.environ.get("MYSQL_USER")
    password_db = os.environ.get("MYSQL_PASSWORD")
    db_name = os.environ.get("MYSQL_DB")
    return ip, username_db, password_db, db_name


def create_connection(host_name, user_name, user_password, db_name):
    try:
        connection = mysql.connector.connect(
            host=host_name, user=user_name, passwd=user_password, database=db_name
        )
        print("Connection to MySQL DB successful")
        return connection
    except Error as e:
        print(f"The error '{e}' occurred")
        return None


# Helper function for executing queries
def execute_query(connection, query, fetch=False):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        if fetch:
            result = cursor.fetchall()
            return result
        connection.commit()
        print("Query executed successfully")
    except Error as e:
        print(f"The error '{e}' occurred")
    finally:
        cursor.close()


# Password hashing and verification
def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(
        provided_password.encode("utf-8"), stored_password.encode("utf-8")
    )


# Home route
@app.route("/")
def home():
    if "user_name" in session:
        return redirect(url_for("user_page"))
    return render_template("home.html")


# Register route
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        connection = create_connection(*get_env())
        user_name = request.form["user_name"]
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        # Check if user exists
        if user_exists(connection, user_name):
            log_request(connection, None, "Failed registration: Username exists")
            return render_template(
                "register.html",
                message="Username already exists. Please choose another one.",
            )

        # Check if email exists
        if email_exists(connection, email):
            log_request(connection, None, "Failed registration: Email exists")
            return render_template(
                "register.html",
                message="Email already exists. Please use another one, or log in to existing account",
            )

        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        insert_query = f"""
            INSERT INTO users (userName, name, email, hashedPassword)
            VALUES ('{user_name}', '{name}', '{email}', '{hashed_password.decode("utf-8")}')
        """
        execute_query(connection, insert_query)

        select_user_id_query = f"SELECT id FROM users WHERE userName = '{user_name}';"
        new_user_id = execute_query(connection, select_user_id_query, fetch=True)
        user_id = new_user_id[0][0] if new_user_id else None

        log_request(connection, user_id, "User Registered")
        return redirect(
            url_for("login", message="User registered successfully. Please log in.")
        )

    return render_template("register.html")


# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        connection = create_connection(*get_env())
        user_name = request.form["user_name"]
        password = request.form["password"]

        select_password_and_user_id_query = (
            f"SELECT id, hashedPassword FROM users WHERE userName = '{user_name}';"
        )
        user = execute_query(connection, select_password_and_user_id_query, fetch=True)

        if user and verify_password(user[0][1], password):
            session["user_id"] = user[0][0]
            log_request(connection, session["user_id"], "login")
            return redirect(
                url_for("user_page", message="Login successful!", user_name=user_name)
            )
        else:
            log_request(connection, None, "login Failed")
            return render_template("login.html", message="Invalid username or password")

    log_request(create_connection(*get_env()), None, "Visted login page")
    return render_template("login.html")


# User page route
@app.route("/user")
def user_page():
    connection = create_connection(*get_env())
    if "user_id" in session:
        log_request(connection, session["user_id"], "Visited user page")
        return render_template("user.html", user_name=session["user_id"])

    log_request(connection, None, "Attempted to visit user page without logging in")
    return redirect(url_for("login"))


# Logout route
@app.route("/logout")
def logout():
    session.pop("user_name", None)
    return redirect(url_for("home", message="Logged out successfully"))


def user_exists(connection, user_name):
    find_user_query = f"SELECT * FROM users WHERE userName = '{user_name}';"
    result = execute_query(connection, find_user_query, fetch=True)
    return len(result) > 0


def email_exists(connection, email):
    find_email_query = f"SELECT * FROM users WHERE email = '{email}';"
    result = execute_query(connection, find_email_query, fetch=True)
    return len(result) > 0


def log_request(connection, user_id, action):
    ip_address = request.remote_addr
    timestamp = datetime.now()
    request_id = str(uuid.uuid4())

    log_query = f"""
    INSERT INTO requestlog (id, userId, ipAddress, action, timestamp)
    VALUES ('{request_id}', {user_id if user_id else 'NULL'}, '{ip_address}', '{action}', '{timestamp}')
    """

    execute_query(connection, log_query)


# Run the app
if __name__ == "__main__":
    app.run(debug=True)
