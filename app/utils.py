from flask import session, current_app
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from app.models import User

def get_current_user():
    """Récupérer l'utilisateur actuel"""
    if 'user_id' in session:
        return User.get(session['user_id'])
    return None

def _get_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

import secrets
import time

def generate_reset_code():
    """Génère un code numérique à 6 chiffres."""
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])

def generate_reset_token(user_id):
    s = _get_serializer()
    return s.dumps({'user_id': user_id})

def verify_reset_token(token, max_age=3600):
    s = _get_serializer()
    try:
        data = s.loads(token, max_age=max_age)
        return data.get('user_id')
    except (SignatureExpired, BadSignature):
        return None
