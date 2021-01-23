import functools

from flask import Blueprint,  flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/')

@bp.route('/')
def index():
    return render_template('login.html') 

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        db = get_db()
        error = None

        if not username:
            error = "Username is required"
        elif not password:
            error = "Password is required"
        elif not email:
            error = "Email is required"
        elif db.execute(
            'SELECT id FROM user WHERE username = ?', (username,) 
        ).fetchone() is not None:
            error = f'User {username} is already registered.'

        if error is None:
            db.execute(
                'INSERT INTO user (username, password, email) VALUES (?, ?, ?)',
                (username, generate_password_hash(password), email)
            )
            db.commit()
            return redirect(url_for('auth.index'))
        
        flash(error)
        return redirect(url_for('auth.index'))
    elif request.method == "GET":
        return render_template('register.html')
    
@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,) 
        ).fetchone()

        if user is None:
            error = 'Username not found'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('auth.login_message'))

        flash(error)
        return redirect(url_for('auth.index'))
    elif request.method == "GET":
        return render_template('login.html')

@bp.route('/login_message')
def login_message():
    user_id = session.get('user_id')
    username = session.get('username')
    # Abort if the user is not logged in
    if user_id is None:
        abort(401)
        return render_template('login.html')
    else:
        user = {
            'id': user_id,
            'username': username,
        }
        return render_template('login_ms.html', user=user)
    
@bp.route('/logout')    
def logout():
    session.clear()
    return redirect(url_for('auth.index'))
