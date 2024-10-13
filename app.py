import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from functions import login_required, password_required
from werkzeug.security import check_password_hash, generate_password_hash
from flask_socketio import SocketIO, send
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

app.config["SESSION_PERMANENT"] = False
app.config["SECRET"] = "secret!123"
app.config["SESSION_TYPE"] = "filesystem"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///information.db'
Session(app)

socketio = SocketIO(app, cors_allowed_origins="*")

db = SQL("sqlite:///information.db")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/nyheter")
def nyheter():
    return render_template("news_home.html")


@app.route("/nyheter/grekland")
def grekland():
    return render_template("grekland.html")


@app.route("/nyheter/futsalturnering")
def futsalturnering():
    return render_template("futsal.html")


@app.route("/nyheter/korvätartävling")
def korvätartävling():
    return render_template("korvätartävling.html")


@app.route("/chat")
@login_required
def chat():
    messages = db.execute("SELECT * FROM messages")
    name = db.execute("SELECT username FROM users WHERE id=?;", session["user_id"])[0]["username"]
    return render_template("chat.html", name=name, messages=messages)

@app.route('/send_message', methods=['POST'])
def send_message():
    name = request.json['name']
    message_text = request.json['message']

    db.execute("INSERT INTO messages (username, message, time) VALUES (?, ?, CURRENT_TIMESTAMP)", name, message_text)

    return jsonify({"status": "Message sent!"})

@socketio.on("message")
def handle_message(message):
    print("Recieved message: " + message)
    if message != "User connected!":
        send(message, broadcast=True)


@app.route("/skoldokument")
@password_required
def skoldokument():
    return render_template("skoldokument.html")


@app.route("/om-oss")
def om_oss():
    return render_template("om_oss.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        session.pop('user_id', None)

        if not request.form.get("username"):
            flash("Användarnamn saknas")
            return render_template("login.html")

        elif not request.form.get("password"):
            flash("Lösenord saknas")
            return render_template("login.html")

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
            )

        if len(rows) != 1:
            flash("Felaktigt änvändarnamn")
            return render_template("login.html")


        elif not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("Felaktigt lösenord")
            return render_template("login.html")

        session["user_id"] = rows[0]["id"]

        messages = db.execute("SELECT * FROM messages")
        name = db.execute("SELECT username FROM users WHERE id=?;", session["user_id"])[0]["username"]
        return render_template("chat.html", name=name, messages=messages)

    else:
        return render_template("login.html")

@app.route("/logout")
def logout():

    session.pop('user_id', None)

    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        session.pop('user_id', None)

        if not request.form.get("username"):
            flash("Användarnamn saknas")
            return render_template("register.html")

        elif not request.form.get("password"):
            flash("Lösenord saknas")
            return render_template("register.html")

        elif not request.form.get("confirmation"):
            flash("Lösenord saknas")
            return render_template("register.html")

        elif request.form.get("password") != request.form.get("confirmation"):
            flash("Lösenorden överensstämmer inte")
            return render_template("register.html")

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        if len(rows) != 0:
            flash("Ogiltigt användarnamn")
            return render_template("register.html")

        username = request.form.get("username")
        hash = generate_password_hash(request.form.get("password"))

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)

        flash("Konto registrerat")
        return render_template("login.html")

    else:
        return render_template("register.html")



@app.route("/password", methods=["GET", "POST"])
def password():

    if request.method == "POST":

        if not request.form.get("password"):
            flash('Lösenord kan inte vara tomt!')
            return render_template("password.html")

        if request.form.get("password").strip() != "1177":
            flash('Felaktigt lösenord!')
            return render_template("password.html")

        session["password"] = True

        return redirect("/skoldokument")

    else:
        return render_template("password.html")




if __name__ == "__main__":
    socketio.run(app, host="192.168.50.105")
    app.run(debug=False, host="0.0.0.0")
