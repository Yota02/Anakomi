from functools import wraps
from flask import session, flash, redirect, url_for

def login_required(f):
    """Décorateur pour vérifier l'authentification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Veuillez vous connecter pour accéder à cette page.')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function
