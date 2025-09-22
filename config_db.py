import pymysql
from contextlib import contextmanager
from dotenv import load_dotenv
import os

dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path)

# Configuration de la base de données (gestion du port et extraction du charset si collation fournie)
_db_port = os.getenv('DB_PORT', '3316')
try:
     _db_port = int(_db_port)
except ValueError:
    _db_port = 3316

_raw_charset = os.getenv('DB_CHARSET', 'utf8mb4_unicode_ci')
_charset = _raw_charset.split('_')[0]


DB_CONFIG = {
            'host': os.getenv('DB_HOST'),
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASSWORD'),
            'database': os.getenv('DB_DATABASE'),
            'charset': _charset,
            'port': _db_port
        }

# Masquer le mot de passe dans les logs
_masked = DB_CONFIG.copy()
if _masked.get('password'):
    _masked['password'] = '***REDACTED***'


# --- Ajout : diagnostics pour erreurs MySQL ---
def parse_mysql_error(exc):
    """Retourne (code, message, conseil_court)."""
    code = None
    msg = str(exc)
    try:
        # pymysql lance souvent OperationalError/InterfaceError avec (code, msg)
        if hasattr(exc, 'args') and exc.args:
            code = exc.args[0]
    except Exception:
        code = None

    advice = "Vérifiez la configuration dans le fichier .env et que le serveur MySQL est joignable."
    if code == 1045:
        advice = "Accès refusé : identifiants invalides ou hôte non autorisé. Vérifiez DB_USER/DB_PASSWORD/DB_HOST et que l'utilisateur a des droits depuis votre IP (GRANT ALL PRIVILEGES ON ... TO 'user'@'host')."
    elif code in (2003,):
        advice = "Impossible de joindre le serveur MySQL (réseau / port). Vérifiez que MySQL écoute et que DB_HOST/DB_PORT sont corrects, firewall ou connexion distante autorisée."
    elif code in (2005,):
        advice = "Hôte MySQL introuvable. Vérifiez DB_HOST (résolution DNS) et la connectivité réseau."
    elif code == 1049:
        advice = "Base de données introuvable. Vérifiez DB_DATABASE ou créez la base avant d'essayer de vous connecter."
    return code, msg, advice

def test_connection(timeout=5):
    """Teste rapidement la connexion en renvoyant un dict {ok, code, msg, advice}."""
    try:
        conn = pymysql.connect(
            host=DB_CONFIG.get('host'),
            user=DB_CONFIG.get('user'),
            password=DB_CONFIG.get('password'),
            database=DB_CONFIG.get('database'),
            charset=DB_CONFIG.get('charset'),
            port=DB_CONFIG.get('port'),
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=timeout
        )
        conn.close()
        return {'ok': True}
    except Exception as e:
        code, msg, advice = parse_mysql_error(e)
        return {'ok': False, 'code': code, 'msg': msg, 'advice': advice}

def print_connection_advice(result):
    """Affiche un message concis et masqué au besoin."""
    masked = DB_CONFIG.copy()
    if masked.get('password'):
        masked['password'] = '***REDACTED***'
    print(f"❌ Erreur de connexion MySQL (config: {masked}): {result.get('msg')}")
    print(f"Conseil: {result.get('advice')}")

# Ajout : gestionnaire de connexion réutilisable et helpers
@contextmanager
def get_connection():
    """
    Fournit une connexion pymysql basée sur DB_CONFIG.
    Usage:
        with get_connection() as conn:
            ...
    """
    try:
        conn = pymysql.connect(
            host=DB_CONFIG.get('host'),
            user=DB_CONFIG.get('user'),
            password=DB_CONFIG.get('password'),
            database=DB_CONFIG.get('database'),
            charset=DB_CONFIG.get('charset'),
            port=DB_CONFIG.get('port'),
            cursorclass=pymysql.cursors.DictCursor
        )
    except Exception as e:
        # Diagnostic utile sans révéler le mot de passe
        test = test_connection()
        if not test.get('ok'):
            print_connection_advice(test)
            raise RuntimeError(f"Erreur de connexion MySQL: {test.get('msg')} - {test.get('advice')}") from e
        masked = DB_CONFIG.copy()
        if masked.get('password'):
            masked['password'] = '***REDACTED***'
        raise RuntimeError(f"Erreur de connexion MySQL (config: {masked}): {e}") from e

    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass

def fetch_one(query, params=None):
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(query, params or ())
            return cursor.fetchone()

def fetch_all(query, params=None):
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(query, params or ())
            return cursor.fetchall()

def execute_query(query, params=None, commit=True):
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(query, params or ())
        if commit:
            conn.commit()

def create_database():
    """
    Script pour créer la base de données MySQL 'rate_my_anime'
    Lancez ce script avant de démarrer l'application Flask
    """
    # Vérifier d'abord la connectivité et afficher un conseil si échec
    test = test_connection()
    if not test.get('ok'):
        print_connection_advice(test)
        
        print("Abandon de la création automatique de la base de données tant que la connexion échoue.")
        return

    try:
        connection = pymysql.connect(**DB_CONFIG)
        cursor = connection.cursor()
        
        # Créer la base de données si elle n'existe pas
        cursor.execute("CREATE DATABASE IF NOT EXISTS michauxa CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        print("✅ Base de données 'michauxa' créée ou vérifiée avec succès !")

        # Afficher les bases de données existantes
        cursor.execute("SHOW DATABASES")
        databases = cursor.fetchall()
        print("📋 Bases de données disponibles:")
        for db in databases:
            print(f"  - {db[0]}")
        
        cursor.close()
        connection.close()
        
    except Exception as e:
        # Utiliser le diagnostic pour afficher un message utile
        code, msg, advice = parse_mysql_error(e)
        masked = DB_CONFIG.copy()
        if masked.get('password'):
            masked['password'] = '***REDACTED***'
        print(f"❌ Erreur lors de la création de la base de données (config: {masked}): {msg}")
        print(f"Conseil: {advice}")
        print("Vérifiez que MySQL est démarré et que les identifiants sont corrects.")

def ensure_tables():
    """Crée les tables 'anime' et 'review' si elles n'existent pas (opération sûre)."""
    anime_sql = """
    CREATE TABLE IF NOT EXISTS anime (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        genre VARCHAR(100),
        year INT,
        cover_url VARCHAR(500),
        added_by INT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    review_sql = """
    CREATE TABLE IF NOT EXISTS review (
        id INT AUTO_INCREMENT PRIMARY KEY,
        anime_id INT,
        user_id INT,
        rating INT CHECK (rating >= 1 AND rating <= 10),
        comment TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (anime_id) REFERENCES anime(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    user_sql = """
    CREATE TABLE IF NOT EXISTS user (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        email VARCHAR(100) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(anime_sql)
                cursor.execute(review_sql)
                cursor.execute(user_sql)
            conn.commit()
    except Exception as e:
        # Ne pas planter l'application : on loggue pour l'admin et on continue.
        print(f"⚠️  Échec création/verification des tables : {e}")

def resolve_user_table():
    """
    Détecte la table utilisateur ('user' ou 'users') et la colonne mot de passe ('password_hash' ou 'password').
    Retourne dict: {'table': <table_name>, 'password_col': <column_name>}
    """
    # vérifier la présence des tables possibles
    rows = fetch_all(
        "SELECT TABLE_NAME FROM information_schema.tables WHERE table_schema=%s AND TABLE_NAME IN ('user','users')",
        (DB_CONFIG.get('database'),)
    )
    if rows:
        # fetch_all renvoie des dicts grâce au DictCursor
        table = rows[0].get('TABLE_NAME') if isinstance(rows[0], dict) else rows[0][0]
    else:
        table = 'user'

    # vérifier quelle colonne de mot de passe existe
    cols = fetch_all(
        "SELECT COLUMN_NAME FROM information_schema.columns WHERE table_schema=%s AND table_name=%s AND COLUMN_NAME IN ('password_hash','password')",
        (DB_CONFIG.get('database'), table)
    )
    if cols:
        password_col = cols[0].get('COLUMN_NAME') if isinstance(cols[0], dict) else cols[0][0]
    else:
        # fallback sûr
        password_col = 'password_hash'

    return {'table': table, 'password_col': password_col}

if __name__ == "__main__":
    create_database()
    ensure_tables()
