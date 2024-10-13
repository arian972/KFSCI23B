from functools import wraps
from flask import redirect, render_template, session
from flask_socketio import SocketIO, send

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


def password_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("password") != True:
            return redirect("/password")
        return f(*args, **kwargs)

    return decorated_function

