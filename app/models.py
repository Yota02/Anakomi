from app.database import fetch_one, resolve_user_table
import logging

logger = logging.getLogger(__name__)

_user_table_cache = None

def get_user_table_info():
    global _user_table_cache
    if _user_table_cache is None:
        try:
            _user_table_cache = resolve_user_table()
        except Exception:
            # En cas d'erreur de connexion pendant la détection, fallback sûr
            _user_table_cache = {'table': 'user', 'password_col': 'password_hash'}
    return _user_table_cache

class User:
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email
    
    @staticmethod
    def get(user_id):
        """Récupérer un utilisateur par son ID"""
        try:
            info = get_user_table_info()
            tbl = info['table']
            user_data = fetch_one(f"SELECT id, username, email FROM {tbl} WHERE id = %s", (user_id,))
            if user_data:
                return User(user_data['id'], user_data['username'], user_data['email'])
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'utilisateur {user_id}: {e}")
        return None
    
    @staticmethod
    def get_by_username(username):
        """Récupérer un utilisateur par son nom d'utilisateur."""
        try:
            info = get_user_table_info()
            tbl = info['table']
            pwdcol = info['password_col']
            return fetch_one(f"SELECT *, {pwdcol} AS password_hash FROM {tbl} WHERE username = %s", (username,))
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'utilisateur {username}: {e}")
            return None
