from flask import Flask, session, redirect, g, request
import sqlite3
import requests
import bcrypt
import json

import hashlib

app = Flask(__name__)
app.secret_key = "test-key-secret"
DATABASE = 'lab.db'

''' Database Connection Setup'''
def get_db():
    if 'db'not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(error):
    db = g.pop('db', None)
    if db:
        db.close()


'''#### Login (A01 + A03) ####'''
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        try:
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            user = db.execute(query).fetchone()

            if user:
                session["user"] = user["username"]
                session["role"] = user["role"]
                if user["role"] == "admin":
                    return redirect("/admin")
                else:
                    return redirect("/dashboard")
            else:
                return "Invalid credentials", 401
        except Exception as e:
            return f"Error: {e}", 500

    return '''
        <form method="post">
            <h2>Login</h2>
            Username: <input name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit">
        </form>
    '''

''' A01'''

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return f"<h2>Welcome to {session['user']}'s dashboard</h2>"

@app.route("/admin")
def admin_dashboard():
    role = request.args.get("role")
    if role == "admin":
        return "Welcome, admin!"
    return "Access denied", 403

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

''' AO2'''
@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    with open("users.json", "a") as f:
        f.write(json.dumps({"user": username, "pass": password}) + "\n")
    return "User registered."

'''#### A03 ####'''
@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    results = db.execute(f"SELECT * FROM users WHERE username LIKE '%{q}%'").fetchall()
    return "<br>".join([f"{row['username']} ({row['role']})" for row in results])

@app.route("/")
def home():
    return """
    <h1> VulnHunter OWASP Lab</h1>
    <u1>
        <li><a href="/login"> Login</a></li>
        <li>
            <form action="/register" method="post" style="display:inline;">
                <input type = "hidden" name="username" value="user1">
                <input type = "hidden" name="password" value="1234">
                <input type = "submit" value="Register">
            </form>
        </li>
    </u1>
"""

'''#### A04 ####'''
@app.route("/reset", methods=["GET", "POST"])
def reset_any_password():
    if request.method == "POST":
        username = request.form["username"]
        new_pw = request.form["password"]

        db = get_db()
        try:
            db.execute(f"UPDATE users SET password = '{new_pw}' WHERE username = '{username}'")
            db.commit()
            return f"Password for '{username}' reset successfully!"
        except Exception as e:
            return f"Error: {e}", 500

    return '''
        <form method="post">
            <h2>Reset Password</h2>
            Username: <input name="username"><br>
            New Password: <input type="password" name="password"><br>
            <input type="submit" value="Reset Password">
        </form>
    '''

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)