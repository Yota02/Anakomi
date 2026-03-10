import pymysql
from contextlib import contextmanager
from dotenv import load_dotenv
import os
import logging

logger = logging.getLogger(__name__)

# Charger les variables d'environnement (chercher à la racine)
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
dotenv_path = os.path.join(base_dir, '.env')
load_dotenv(dotenv_path)

# Configuration de la base de données
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
    'port': _db_port,
    'cursorclass': pymysql.cursors.DictCursor
}

@contextmanager
def get_connection():
    """Fournit une connexion pymysql basée sur DB_CONFIG."""
    try:
        conn = pymysql.connect(**DB_CONFIG)
    except Exception as e:
        logger.error(f"Erreur de connexion MySQL: {e}")
        raise RuntimeError(f"Erreur de connexion MySQL") from e

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
            last_id = cursor.lastrowid
        if commit:
            conn.commit()
        return last_id

def resolve_user_table():
    """Détecte la table utilisateur ('user' ou 'users') et la colonne mot de passe."""
    try:
        rows = fetch_all(
            "SELECT TABLE_NAME FROM information_schema.tables WHERE table_schema=%s AND TABLE_NAME IN ('user','users')",
            (DB_CONFIG.get('database'),)
        )
        if rows:
            table = rows[0].get('TABLE_NAME')
        else:
            table = 'user'

        cols = fetch_all(
            "SELECT COLUMN_NAME FROM information_schema.columns WHERE table_schema=%s AND table_name=%s AND COLUMN_NAME IN ('password_hash','password')",
            (DB_CONFIG.get('database'), table)
        )
        if cols:
            password_col = cols[0].get('COLUMN_NAME')
        else:
            password_col = 'password_hash'

        return {'table': table, 'password_col': password_col}
    except Exception:
        return {'table': 'user', 'password_col': 'password_hash'}

def ensure_tables():
    """Crée les tables nécessaires si elles manquent (opération sûre)."""
    user_sql = """
    CREATE TABLE IF NOT EXISTS user (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        email VARCHAR(100) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
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
        parent_id INT DEFAULT NULL,
        date_created DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (anime_id) REFERENCES anime(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
        FOREIGN KEY (parent_id) REFERENCES review(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    top10_sql = """
    CREATE TABLE IF NOT EXISTS user_top10 (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        anime_id INT NOT NULL,
        rank_position TINYINT NOT NULL,
        is_public BOOLEAN DEFAULT TRUE,
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
        FOREIGN KEY (anime_id) REFERENCES anime(id) ON DELETE CASCADE,
        UNIQUE KEY unique_user_position (user_id, rank_position)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    videogame_sql = """
    CREATE TABLE IF NOT EXISTS videogame (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        genre VARCHAR(100),
        year INT,
        platform VARCHAR(100),
        cover_url VARCHAR(500),
        added_by INT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    videogame_review_sql = """
    CREATE TABLE IF NOT EXISTS videogame_review (
        id INT AUTO_INCREMENT PRIMARY KEY,
        videogame_id INT,
        user_id INT,
        rating INT CHECK (rating >= 1 AND rating <= 10),
        comment TEXT,
        parent_id INT DEFAULT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (videogame_id) REFERENCES videogame(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
        FOREIGN KEY (parent_id) REFERENCES videogame_review(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    videogame_top10_sql = """
    CREATE TABLE IF NOT EXISTS user_videogame_top10 (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        videogame_id INT NOT NULL,
        rank_position TINYINT NOT NULL,
        is_public BOOLEAN DEFAULT TRUE,
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
        FOREIGN KEY (videogame_id) REFERENCES videogame(id) ON DELETE CASCADE,
        UNIQUE KEY unique_user_vg_position (user_id, rank_position)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    waifu_sql = """
    CREATE TABLE IF NOT EXISTS waifu (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        anime_id INT NULL,
        videogame_id INT NULL,
        description TEXT,
        image_url VARCHAR(500),
        added_by INT,
        gender VARCHAR(10),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (anime_id) REFERENCES anime(id) ON DELETE CASCADE,
        FOREIGN KEY (videogame_id) REFERENCES videogame(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    waifu_review_sql = """
    CREATE TABLE IF NOT EXISTS waifu_review (
        id INT AUTO_INCREMENT PRIMARY KEY,
        waifu_id INT,
        user_id INT,
        rating INT CHECK (rating >= 1 AND rating <= 5),
        comment TEXT,
        parent_id INT DEFAULT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (waifu_id) REFERENCES waifu(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
        FOREIGN KEY (parent_id) REFERENCES waifu_review(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    waifu_top5_sql = """
    CREATE TABLE IF NOT EXISTS user_waifu_top5 (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        waifu_id INT NOT NULL,
        rank_position TINYINT NOT NULL,
        is_public BOOLEAN DEFAULT TRUE,
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
        FOREIGN KEY (waifu_id) REFERENCES waifu(id) ON DELETE CASCADE,
        UNIQUE KEY unique_user_waifu_position (user_id, rank_position)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    poll_sql = """
    CREATE TABLE IF NOT EXISTS poll (
        id INT AUTO_INCREMENT PRIMARY KEY,
        question VARCHAR(255) NOT NULL,
        created_by INT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES user(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    poll_option_sql = """
    CREATE TABLE IF NOT EXISTS poll_option (
        id INT AUTO_INCREMENT PRIMARY KEY,
        poll_id INT NOT NULL,
        option_text VARCHAR(255) NOT NULL,
        FOREIGN KEY (poll_id) REFERENCES poll(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    poll_vote_sql = """
    CREATE TABLE IF NOT EXISTS poll_vote (
        id INT AUTO_INCREMENT PRIMARY KEY,
        poll_id INT NOT NULL,
        option_id INT NOT NULL,
        user_id INT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (poll_id) REFERENCES poll(id) ON DELETE CASCADE,
        FOREIGN KEY (option_id) REFERENCES poll_option(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
        UNIQUE KEY unique_user_poll (user_id, poll_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    comparison_vote_sql = """
    CREATE TABLE IF NOT EXISTS comparison_vote (
        id INT AUTO_INCREMENT PRIMARY KEY,
        item_type ENUM('anime', 'videogame') NOT NULL,
        winner_id INT NOT NULL,
        loser_id INT NOT NULL,
        user_id INT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    tournament_sql = """
    CREATE TABLE IF NOT EXISTS tournament (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        item_type ENUM('anime', 'videogame', 'waifu') NOT NULL,
        tournament_type ENUM('bracket', 'poule') DEFAULT 'bracket',
        share_code VARCHAR(10) UNIQUE NOT NULL,
        created_by INT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES user(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    tournament_participant_sql = """
    CREATE TABLE IF NOT EXISTS tournament_participant (
        id INT AUTO_INCREMENT PRIMARY KEY,
        tournament_id INT NOT NULL,
        item_id INT NOT NULL,
        initial_position TINYINT NOT NULL,
        group_id CHAR(1) DEFAULT NULL, -- A, B, C, D...
        FOREIGN KEY (tournament_id) REFERENCES tournament(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    tournament_match_sql = """
    CREATE TABLE IF NOT EXISTS tournament_match (
        id INT AUTO_INCREMENT PRIMARY KEY,
        tournament_id INT NOT NULL,
        round_number TINYINT NOT NULL,
        match_number TINYINT NOT NULL,
        participant1_id INT, -- Refers to tournament_participant.id
        participant2_id INT, -- Refers to tournament_participant.id
        winner_id INT,      -- Refers to tournament_participant.id
        FOREIGN KEY (tournament_id) REFERENCES tournament(id) ON DELETE CASCADE,
        FOREIGN KEY (participant1_id) REFERENCES tournament_participant(id) ON DELETE SET NULL,
        FOREIGN KEY (participant2_id) REFERENCES tournament_participant(id) ON DELETE SET NULL,
        FOREIGN KEY (winner_id) REFERENCES tournament_participant(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    tournament_vote_sql = """
    CREATE TABLE IF NOT EXISTS tournament_vote (
        id INT AUTO_INCREMENT PRIMARY KEY,
        match_id INT NOT NULL,
        participant_id INT NOT NULL,
        session_id VARCHAR(100) NOT NULL,
        user_id INT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (match_id) REFERENCES tournament_match(id) ON DELETE CASCADE,
        FOREIGN KEY (participant_id) REFERENCES tournament_participant(id) ON DELETE CASCADE,
        UNIQUE KEY unique_session_match (session_id, match_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    battle_royale_sql = """
    CREATE TABLE IF NOT EXISTS battle_royale (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        status ENUM('active', 'finished') DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    battle_participant_sql = """
    CREATE TABLE IF NOT EXISTS battle_participant (
        id INT AUTO_INCREMENT PRIMARY KEY,
        battle_id INT NOT NULL,
        waifu_id INT NOT NULL,
        votes INT DEFAULT 0,
        FOREIGN KEY (battle_id) REFERENCES battle_royale(id) ON DELETE CASCADE,
        FOREIGN KEY (waifu_id) REFERENCES waifu(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """

    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(user_sql)
                cursor.execute(anime_sql)
                cursor.execute(review_sql)
                cursor.execute(top10_sql)
                cursor.execute(videogame_sql)
                cursor.execute(videogame_review_sql)
                cursor.execute(videogame_top10_sql)
                cursor.execute(waifu_sql)
                cursor.execute(waifu_review_sql)
                cursor.execute(waifu_top5_sql)
                cursor.execute(poll_sql)
                cursor.execute(poll_option_sql)
                cursor.execute(poll_vote_sql)
                cursor.execute(comparison_vote_sql)
                cursor.execute(tournament_sql)
                cursor.execute(tournament_participant_sql)
                cursor.execute(tournament_match_sql)
                cursor.execute(tournament_vote_sql)
                cursor.execute(battle_royale_sql)
                cursor.execute(battle_participant_sql)
                
                cursor.execute("""
                    SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
                    WHERE TABLE_NAME = 'review' AND COLUMN_NAME = 'id'
                """)
                if not cursor.fetchone():
                    cursor.execute("ALTER TABLE review ADD COLUMN id INT AUTO_INCREMENT PRIMARY KEY FIRST")
                
                cursor.execute("""
                    SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
                    WHERE TABLE_NAME = 'videogame_review' AND COLUMN_NAME = 'id'
                """)
                if not cursor.fetchone():
                    cursor.execute("ALTER TABLE videogame_review ADD COLUMN id INT AUTO_INCREMENT PRIMARY KEY FIRST")
                
                cursor.execute("""
                    SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
                    WHERE TABLE_NAME = 'waifu_review' AND COLUMN_NAME = 'id'
                """)
                if not cursor.fetchone():
                    cursor.execute("ALTER TABLE waifu_review ADD COLUMN id INT AUTO_INCREMENT PRIMARY KEY FIRST")
                
            conn.commit()
    except Exception as e:
        logger.warning(f"⚠️  Échec création/verification des tables : {e}")
