from flask import render_template, request, session, redirect, url_for, flash
from functools import wraps
from ..auth_manager import check_credentials
from . import bp_auth

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@bp_auth.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        success, message = check_credentials(username, password)
        
        if success:
            session['logged_in'] = True
            session['username'] = username
            session.modified = True
            return redirect(url_for('dashboard.index'))
        else:
            error = message if message else 'Invalid Credentials.'

    return render_template('login.html', error=error)

@bp_auth.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('dashboard.index'))
