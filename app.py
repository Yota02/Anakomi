from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import logging
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import smtplib
from email.message import EmailMessage

from config_db import execute_query, fetch_all, fetch_one, get_connection, resolve_user_table

app = Flask(__name__)
# Charger la clé secrète depuis l'environnement (config_db.py a déjà chargé .env)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'change_me_in_production'

# Sécurité des cookies pour la prod (modifiable via variables d'environnement)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
# Par défaut on active Secure en production (peut être désactivé localement)
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', '1') == '1'
# Durée de session par défaut
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=int(os.getenv('SESSION_LIFETIME_DAYS', '7')))

# Logging minimal pour prod
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Résolution paresseuse de la table/colonne utilisateur (cache)
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

# Classe User simple pour gérer l'authentification
class User:
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email
    
    @staticmethod
    def get(user_id):
        """Récupérer un utilisateur par son ID"""
        info = get_user_table_info()
        tbl = info['table']
        user_data = fetch_one(f"SELECT id, username, email FROM {tbl} WHERE id = %s", (user_id,))
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['email'])
        return None
    
    @staticmethod
    def get_by_username(username):
        """Récupérer un utilisateur par son nom d'utilisateur.
           Selectionne aussi la colonne de mot de passe sous l'alias password_hash pour compatibilité."""
        info = get_user_table_info()
        tbl = info['table']
        pwdcol = info['password_col']
        return fetch_one(f"SELECT *, {pwdcol} AS password_hash FROM {tbl} WHERE username = %s", (username,))

# Fonctions d'aide pour l'authentification
def login_required(f):
    """Décorateur pour vérifier l'authentification"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Veuillez vous connecter pour accéder à cette page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Récupérer l'utilisateur actuel"""
    if 'user_id' in session:
        return User.get(session['user_id'])
    return None

# Context processor pour fournir l'utilisateur courant (déjà présent) et l'année actuelle
@app.context_processor
def inject_globals():
    return dict(current_user=get_current_user(), current_year=datetime.utcnow().year)

# --- Ajout : création sûre des tables nécessaires si elles manquent ---
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
        rating TINYINT NOT NULL,
        comment TEXT,
        user_id INT,
        anime_id INT,
        date_created DATETIME DEFAULT CURRENT_TIMESTAMP,
        -- On évite la contrainte foreign key sur user_id pour rester compatible si la table utilisateur diffère
        FOREIGN KEY (anime_id) REFERENCES anime(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    user_sql = """
    CREATE TABLE IF NOT EXISTS user (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(80) UNIQUE NOT NULL,
            email VARCHAR(120) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
     """
    user_top10_sql = """
    CREATE TABLE IF NOT EXISTS user_top10 (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        anime_id INT NOT NULL,
        rank_position INT NOT NULL,
        is_public TINYINT(1) DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
        FOREIGN KEY (anime_id) REFERENCES anime(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    waifu_sql = """
    CREATE TABLE IF NOT EXISTS waifu (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        anime_id INT NOT NULL,
        description TEXT,
        image_url VARCHAR(500),
        added_by INT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (anime_id) REFERENCES anime(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    user_waifu_top5_sql = """
    CREATE TABLE IF NOT EXISTS user_waifu_top5 (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        waifu_id INT NOT NULL,
        rank_position INT NOT NULL,
        is_public TINYINT(1) DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
        FOREIGN KEY (waifu_id) REFERENCES waifu(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(anime_sql)
                cursor.execute(review_sql)
                cursor.execute(user_sql)
                cursor.execute(user_top10_sql)
                cursor.execute(waifu_sql)
                cursor.execute(user_waifu_top5_sql)
            conn.commit()
    except Exception as e:
        # Ne pas planter l'application : on loggue pour l'admin et on continue.
        print(f"⚠️  Échec création/verification des tables : {e}")

# Serializer pour tokens de reset (utilise SECRET_KEY de app.config)
def _get_serializer():
    return URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_reset_token(user_id):
    s = _get_serializer()
    return s.dumps({'user_id': user_id})

def verify_reset_token(token, max_age=3600):
    s = _get_serializer()
    try:
        data = s.loads(token, max_age=max_age)
        return data.get('user_id')
    except SignatureExpired:
        return None
    except BadSignature:
        return None

def send_reset_email(to_email, token, username):
    """
    Envoie l'email de reset si la configuration SMTP est présente.
    Variables d'environnement supportées:
      SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, MAIL_FROM
    Si non configuré, on logge et on renvoie le lien (utile pour dev local).
    """
    host = os.getenv('SMTP_HOST')
    port = int(os.getenv('SMTP_PORT', '587')) if os.getenv('SMTP_PORT') else None
    user = os.getenv('SMTP_USER')
    password = os.getenv('SMTP_PASSWORD')
    mail_from = os.getenv('MAIL_FROM', 'no-reply@anakomi.local')

    reset_url = url_for('reset_password', token=token, _external=True)
    subject = "Réinitialisation de votre mot de passe - Anakomi"
    body = f"Bonjour {username},\n\nPour réinitialiser votre mot de passe, cliquez sur le lien suivant (valide 1h) :\n\n{reset_url}\n\nSi vous n'avez pas demandé ce reset, ignorez ce message.\n\n— L'équipe Anakomi"

    if host and user and password and port:
        try:
            msg = EmailMessage()
            msg['Subject'] = subject
            msg['From'] = mail_from
            msg['To'] = to_email
            msg.set_content(body)

            with smtplib.SMTP(host, port, timeout=10) as smtp:
                smtp.starttls()
                smtp.login(user, password)
                smtp.send_message(msg)
            logger.info("Email de réinitialisation envoyé à %s", to_email)
            return True
        except Exception as e:
            logger.error("Échec envoi email reset: %s", e)
            # fallback to console
    # Si pas de SMTP ou erreur -> log + flash le lien (pratique pour dev)
    logger.info("Lien de réinitialisation (dev/console) pour %s : %s", to_email, reset_url)
    return False

# Routes
@app.route('/')
def index():
    q = (request.args.get('q') or '').strip()
    sort = request.args.get('sort', 'recent')  # nouveau paramètre de tri

    # Liste blanche des tris autorisés pour éviter l'injection SQL
    _allowed_sorts = {
        'recent': 'a.created_at DESC, a.id DESC',
        'title_asc': 'LOWER(a.title) ASC, a.id DESC',
        'title_desc': 'LOWER(a.title) DESC, a.id DESC',
        'rating_desc': 'AVG(r.rating) DESC, a.id DESC'
    }
    order_clause = _allowed_sorts.get(sort, _allowed_sorts['recent'])

    try:
        if q:
            # recherche insensible à la casse sur titre et description (paramétrée)
            pattern = f"%{q}%"
            animes = fetch_all(
                f"""
                SELECT a.*, 
                       COALESCE(ROUND(AVG(r.rating),1), 0) AS avg_rating,
                       COUNT(r.id) AS review_count
                FROM anime a
                LEFT JOIN review r ON a.id = r.anime_id
                WHERE LOWER(a.title) LIKE %s OR LOWER(a.description) LIKE %s
                GROUP BY a.id
                ORDER BY {order_clause}
                """,
                (pattern.lower(), pattern.lower())
            )
        else:
            animes = fetch_all(
                f"""
                SELECT a.*, 
                       COALESCE(ROUND(AVG(r.rating),1), 0) AS avg_rating,
                       COUNT(r.id) AS review_count
                FROM anime a
                LEFT JOIN review r ON a.id = r.anime_id
                GROUP BY a.id
                ORDER BY {order_clause}
                """
            )
    except Exception as e:
        # Si la table anime manque, tenter une création automatique puis retenter
        msg = str(e).lower()
        if ('doesn' in msg and 'exist' in msg) or '1146' in msg or ('anime' in msg and 'doesn' in msg):
            flash("La table 'anime' est manquante. Tentative de création automatique...")
            ensure_tables()
            try:
                if q:
                    pattern = f"%{q}%"
                    animes = fetch_all(
                        f"""
                        SELECT a.*, 
                               COALESCE(ROUND(AVG(r.rating),1), 0) AS avg_rating,
                               COUNT(r.id) AS review_count
                        FROM anime a
                        LEFT JOIN review r ON a.id = r.anime_id
                        WHERE LOWER(a.title) LIKE %s OR LOWER(a.description) LIKE %s
                        GROUP BY a.id
                        ORDER BY {order_clause}
                        """,
                        (pattern.lower(), pattern.lower())
                    )
                else:
                    animes = fetch_all(
                        f"""
                        SELECT a.*, 
                               COALESCE(ROUND(AVG(r.rating),1), 0) AS avg_rating,
                               COUNT(r.id) AS review_count
                        FROM anime a
                        LEFT JOIN review r ON a.id = r.anime_id
                        GROUP BY a.id
                        ORDER BY {order_clause}
                        """
                    )
            except Exception as e2:
                flash("Impossible de récupérer les animes après tentative de création : vérifier la base de données.")
                print(f"Erreur après tentative de création des tables: {e2}")
                animes = []
        else:
            # Pour toute autre erreur, on loggue et retourne une liste vide pour éviter un crash visible.
            print(f"Erreur lors de la lecture des animes: {e}")
            flash("Erreur lors de la lecture des animes. Voir la console pour plus de détails.")
            animes = []
    return render_template('index.html', animes=animes, sort=sort)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        info = get_user_table_info()
        tbl = info['table']
        pwdcol = info['password_col']
        
        # Vérifier si l'utilisateur existe déjà
        if fetch_one(f"SELECT id FROM {tbl} WHERE username = %s", (username,)):
            flash('Nom d\'utilisateur déjà existant')
            return redirect(url_for('register'))
        
        if fetch_one(f"SELECT id FROM {tbl} WHERE email = %s", (email,)):
            flash('Email déjà utilisé')
            return redirect(url_for('register'))
        
        # Créer l'utilisateur : insérer dans la colonne détectée pour le mot de passe
        password_hash = generate_password_hash(password)
        execute_query(
            f"INSERT INTO {tbl} (username, email, {pwdcol}) VALUES (%s, %s, %s)",
            (username, email, password_hash)
        )
        
        flash('Inscription réussie')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        info = get_user_table_info()
        tbl = info['table']
        pwdcol = info['password_col']

        # Récupérer l'utilisateur et normaliser le champ mot de passe sous 'password_hash'
        user = fetch_one(f"SELECT *, {pwdcol} AS password_hash FROM {tbl} WHERE username = %s", (username,))
        
        if user and check_password_hash(user.get('password_hash', ''), password):
            session['user_id'] = user['id']
            flash('Connexion réussie')
            return redirect(url_for('index'))
        else:
            flash('Identifiants incorrects')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    flash('Déconnexion réussie')
    return redirect(url_for('index'))

@app.route('/add_anime', methods=['GET', 'POST'])
@login_required
def add_anime():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        genre = request.form['genre']
        year = request.form['year']
        cover_url = request.form.get('cover_url', '')
        
        execute_query(
            "INSERT INTO anime (title, description, genre, year, cover_url, added_by) VALUES (%s, %s, %s, %s, %s, %s)",
            (title, description, genre, int(year), cover_url, session['user_id'])
        )
        
        flash('Anime ajouté avec succès')
        return redirect(url_for('index'))
    
    return render_template('add_anime.html')

@app.route('/anime/<int:id>')
def anime_detail(id):
    anime = fetch_one("SELECT * FROM anime WHERE id = %s", (id,))
    if not anime:
        flash('Anime non trouvé')
        return redirect(url_for('index'))
    
    info = get_user_table_info()
    user_tbl = info['table']
    # Récupérer les avis avec les noms d'utilisateur (utilise la table utilisateur détectée)
    reviews = fetch_all(f"""
        SELECT r.*, u.username 
        FROM review r 
        JOIN {user_tbl} u ON r.user_id = u.id 
        WHERE r.anime_id = %s 
        ORDER BY r.date_created DESC
    """, (id,))
    
    # Calculer la moyenne des notes
    avg_rating = 0
    if reviews:
        avg_rating = sum(review['rating'] for review in reviews) / len(reviews)
    
    return render_template('anime_detail.html', anime=anime, reviews=reviews, avg_rating=round(avg_rating, 1))

@app.route('/add_review/<int:anime_id>', methods=['POST'])
@login_required
def add_review(anime_id):
    rating = int(request.form['rating'])
    comment = request.form['comment']
    
    # Vérifier si l'utilisateur a déjà noté cet anime
    existing_review = fetch_one(
        "SELECT id FROM review WHERE user_id = %s AND anime_id = %s",
        (session['user_id'], anime_id)
    )
    
    if existing_review:
        # Mettre à jour l'avis existant
        execute_query(
            "UPDATE review SET rating = %s, comment = %s, date_created = NOW() WHERE user_id = %s AND anime_id = %s",
            (rating, comment, session['user_id'], anime_id)
        )
        flash('Avis modifié avec succès')
    else:
        # Créer un nouvel avis
        execute_query(
            "INSERT INTO review (rating, comment, user_id, anime_id) VALUES (%s, %s, %s, %s)",
            (rating, comment, session['user_id'], anime_id)
        )
        flash('Avis ajouté avec succès')
    
    return redirect(url_for('anime_detail', id=anime_id))

@app.route('/edit_anime/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_anime(id):
    anime = fetch_one("SELECT * FROM anime WHERE id = %s", (id,))
    if not anime:
        flash('Anime non trouvé')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        genre = request.form['genre']
        year = request.form['year']
        cover_url = request.form.get('cover_url', '')
        
        execute_query(
            "UPDATE anime SET title = %s, description = %s, genre = %s, year = %s, cover_url = %s WHERE id = %s",
            (title, description, genre, int(year), cover_url, id)
        )
        
        flash('Anime modifié avec succès')
        return redirect(url_for('anime_detail', id=id))
    
    return render_template('edit_anime.html', anime=anime)

# Route: demande de réinitialisation
@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash("Veuillez fournir votre adresse email.")
            return redirect(url_for('reset_password_request'))

        # Détecter la table utilisateur et chercher par email
        info = get_user_table_info()
        tbl = info['table']
        user = fetch_one(f"SELECT id, username, email FROM {tbl} WHERE email = %s", (email,))
        if user:
            token = generate_reset_token(user['id'])
            sent = send_reset_email(user['email'], token, user.get('username') or '')
            flash("Si un compte existe pour cet email, un lien de réinitialisation a été envoyé.")
            # Ne pas révéler l'existence du compte : message générique
            if not sent:
                # pour dev on affiche aussi le lien (console/log) ; inutile d'ajouter ici
                pass
        else:
            # Même message pour éviter de divulguer l'existence de l'email
            flash("Si un compte existe pour cet email, un lien de réinitialisation a été envoyé.")
        return redirect(url_for('login'))
    return render_template('password_reset_request.html')

# Route: formulaire de nouveau mot de passe
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user_id = verify_reset_token(token)
    if not user_id:
        flash("Le lien de réinitialisation est invalide ou expiré.")
        return redirect(url_for('reset_password_request'))

    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        password2 = request.form.get('password2', '').strip()
        if not password or password != password2:
            flash("Les mots de passe doivent être identiques et non vides.")
            return redirect(url_for('reset_password', token=token))

        password_hash = generate_password_hash(password)
        info = get_user_table_info()
        tbl = info['table']
        pwdcol = info['password_col']
        # Mettre à jour la colonne détectée (compatible password / password_hash)
        execute_query(f"UPDATE {tbl} SET {pwdcol} = %s WHERE id = %s", (password_hash, user_id))
        flash("Mot de passe réinitialisé avec succès. Vous pouvez maintenant vous connecter.")
        return redirect(url_for('login'))

    return render_template('password_reset.html', token=token)

@app.route('/top10/users')
def top10_users():
    """Liste des utilisateurs ayant un top 10 public"""
    info = get_user_table_info()
    user_tbl = info['table']
    
    users_with_top10 = fetch_all(f"""
        SELECT DISTINCT u.id, u.username, COUNT(t.id) as anime_count
        FROM {user_tbl} u
        JOIN user_top10 t ON u.id = t.user_id
        WHERE t.is_public = 1
        GROUP BY u.id, u.username
        ORDER BY u.username
    """)
    
    return render_template('top10_users.html', users=users_with_top10)

@app.route('/top10/user/<int:user_id>')
def view_user_top10(user_id):
    """Voir le top 10 d'un utilisateur"""
    info = get_user_table_info()
    user_tbl = info['table']
    
    # Récupérer l'utilisateur
    user = fetch_one(f"SELECT id, username FROM {user_tbl} WHERE id = %s", (user_id,))
    if not user:
        flash("Utilisateur non trouvé")
        return redirect(url_for('index'))
    
    # Vérifier si c'est le propriétaire ou si le top10 est public
    current_user_obj = get_current_user()
    is_owner = current_user_obj and current_user_obj.id == user_id
    
    if not is_owner:
        # Vérifier qu'il y a au moins un anime public
        public_check = fetch_one(
            "SELECT id FROM user_top10 WHERE user_id = %s AND is_public = 1 LIMIT 1",
            (user_id,)
        )
        if not public_check:
            flash("Ce top 10 est privé")
            return redirect(url_for('top10_users'))
    
    # Récupérer le top 10 (public seulement si pas propriétaire)
    where_clause = "" if is_owner else "AND t.is_public = 1"
    
    top10 = fetch_all(f"""
        SELECT t.rank_position, t.is_public, a.id, a.title, a.cover_url, a.genre, a.year,
               COALESCE(ROUND(AVG(r.rating),1), 0) AS avg_rating
        FROM user_top10 t
        JOIN anime a ON t.anime_id = a.id
        LEFT JOIN review r ON a.id = r.anime_id
        WHERE t.user_id = %s {where_clause}
        GROUP BY t.rank_position, t.is_public, a.id, a.title, a.cover_url, a.genre, a.year
        ORDER BY t.rank_position
    """, (user_id,))
    
    return render_template('view_top10.html', user=user, top10=top10, is_owner=is_owner)

@app.route('/my-top10')
@login_required
def my_top10():
    """Gérer son propre top 10"""
    user_id = session['user_id']
    
    # Récupérer le top 10 actuel
    top10 = fetch_all("""
        SELECT t.rank_position, t.is_public, a.id, a.title, a.cover_url
        FROM user_top10 t
        JOIN anime a ON t.anime_id = a.id
        WHERE t.user_id = %s
        ORDER BY t.rank_position
    """, (user_id,))
    
    # Récupérer tous les animes pour la sélection
    all_animes = fetch_all("SELECT id, title FROM anime ORDER BY title")
    
    return render_template('manage_top10.html', top10=top10, all_animes=all_animes)

@app.route('/my-top10/update', methods=['POST'])
@login_required
def update_top10():
    """Mettre à jour son top 10"""
    user_id = session['user_id']
    
    # Supprimer l'ancien top 10
    execute_query("DELETE FROM user_top10 WHERE user_id = %s", (user_id,))
    
    # Récupérer la visibilité globale
    is_public = 1 if request.form.get('is_public') == 'on' else 0
    
    # Ajouter les nouveaux animes
    for i in range(1, 11):
        anime_id = request.form.get(f'anime_{i}')
        if anime_id and anime_id.isdigit():
            execute_query(
                "INSERT INTO user_top10 (user_id, anime_id, rank_position, is_public) VALUES (%s, %s, %s, %s)",
                (user_id, int(anime_id), i, is_public)
            )
    
    flash("Votre top 10 a été mis à jour avec succès")
    return redirect(url_for('my_top10'))

@app.route('/waifus')
def waifus_list():
    """Liste de toutes les waifus"""
    waifus = fetch_all("""
        SELECT w.*, a.title as anime_title
        FROM waifu w
        JOIN anime a ON w.anime_id = a.id
        ORDER BY w.name
    """)
    
    return render_template('waifus_list.html', waifus=waifus)

@app.route('/add_waifu', methods=['GET', 'POST'])
@login_required
def add_waifu():
    """Ajouter une nouvelle waifu"""
    if request.method == 'POST':
        name = request.form['name']
        anime_id = request.form['anime_id']
        description = request.form.get('description', '')
        image_url = request.form.get('image_url', '')
        
        execute_query(
            "INSERT INTO waifu (name, anime_id, description, image_url, added_by) VALUES (%s, %s, %s, %s, %s)",
            (name, anime_id, description, image_url, session['user_id'])
        )
        
        flash('Waifu ajoutée avec succès')
        return redirect(url_for('waifus_list'))
    
    # Récupérer tous les animes pour la sélection
    animes = fetch_all("SELECT id, title FROM anime ORDER BY title")
    return render_template('add_waifu.html', animes=animes)

@app.route('/waifu/<int:id>')
def waifu_detail(id):
    """Détail d'une waifu"""
    waifu = fetch_one("""
        SELECT w.*, a.title as anime_title, a.id as anime_id
        FROM waifu w
        JOIN anime a ON w.anime_id = a.id
        WHERE w.id = %s
    """, (id,))
    
    if not waifu:
        flash('Waifu non trouvée')
        return redirect(url_for('waifus_list'))
    
    return render_template('waifu_detail.html', waifu=waifu)

@app.route('/waifu-top5/users')
def waifu_top5_users():
    """Liste des utilisateurs ayant un top 5 waifu public"""
    info = get_user_table_info()
    user_tbl = info['table']
    
    users_with_top5 = fetch_all(f"""
        SELECT DISTINCT u.id, u.username, COUNT(t.id) as waifu_count
        FROM {user_tbl} u
        JOIN user_waifu_top5 t ON u.id = t.user_id
        WHERE t.is_public = 1
        GROUP BY u.id, u.username
        ORDER BY u.username
    """)
    
    return render_template('waifu_top5_users.html', users=users_with_top5)

@app.route('/waifu-top5/user/<int:user_id>')
def view_user_waifu_top5(user_id):
    """Voir le top 5 waifu d'un utilisateur"""
    info = get_user_table_info()
    user_tbl = info['table']
    
    # Récupérer l'utilisateur
    user = fetch_one(f"SELECT id, username FROM {user_tbl} WHERE id = %s", (user_id,))
    if not user:
        flash("Utilisateur non trouvé")
        return redirect(url_for('index'))
    
    # Vérifier si c'est le propriétaire ou si le top5 est public
    current_user_obj = get_current_user()
    is_owner = current_user_obj and current_user_obj.id == user_id
    
    if not is_owner:
        # Vérifier qu'il y a au moins une waifu publique
        public_check = fetch_one(
            "SELECT id FROM user_waifu_top5 WHERE user_id = %s AND is_public = 1 LIMIT 1",
            (user_id,)
        )
        if not public_check:
            flash("Ce top 5 waifu est privé")
            return redirect(url_for('waifu_top5_users'))
    
    # Récupérer le top 5 waifu (public seulement si pas propriétaire)
    where_clause = "" if is_owner else "AND t.is_public = 1"
    
    top5 = fetch_all(f"""
        SELECT t.rank_position, t.is_public, w.id, w.name, w.image_url, w.description,
               a.title as anime_title, a.id as anime_id
        FROM user_waifu_top5 t
        JOIN waifu w ON t.waifu_id = w.id
        JOIN anime a ON w.anime_id = a.id
        WHERE t.user_id = %s {where_clause}
        ORDER BY t.rank_position
    """, (user_id,))
    
    return render_template('view_waifu_top5.html', user=user, top5=top5, is_owner=is_owner)

@app.route('/my-waifu-top5')
@login_required
def my_waifu_top5():
    """Gérer son propre top 5 waifu"""
    user_id = session['user_id']
    
    # Récupérer le top 5 actuel
    top5 = fetch_all("""
        SELECT t.rank_position, t.is_public, w.id, w.name, w.image_url,
               a.title as anime_title
        FROM user_waifu_top5 t
        JOIN waifu w ON t.waifu_id = w.id
        JOIN anime a ON w.anime_id = a.id
        WHERE t.user_id = %s
        ORDER BY t.rank_position
    """, (user_id,))
    
    # Récupérer toutes les waifus pour la sélection
    all_waifus = fetch_all("""
        SELECT w.id, w.name, a.title as anime_title
        FROM waifu w
        JOIN anime a ON w.anime_id = a.id
        ORDER BY w.name
    """)
    
    return render_template('manage_waifu_top5.html', top5=top5, all_waifus=all_waifus)

@app.route('/my-waifu-top5/update', methods=['POST'])
@login_required
def update_waifu_top5():
    """Mettre à jour son top 5 waifu"""
    user_id = session['user_id']
    
    # Supprimer l'ancien top 5
    execute_query("DELETE FROM user_waifu_top5 WHERE user_id = %s", (user_id,))
    
    # Récupérer la visibilité globale
    is_public = 1 if request.form.get('is_public') == 'on' else 0
    
    # Ajouter les nouvelles waifus
    for i in range(1, 6):
        waifu_id = request.form.get(f'waifu_{i}')
        if waifu_id and waifu_id.isdigit():
            execute_query(
                "INSERT INTO user_waifu_top5 (user_id, waifu_id, rank_position, is_public) VALUES (%s, %s, %s, %s)",
                (user_id, int(waifu_id), i, is_public)
            )
    
    flash("Votre top 5 waifu a été mis à jour avec succès")
    return redirect(url_for('my_waifu_top5'))

if __name__ == '__main__':
    # Hôte/port et mode debug contrôlés par des variables d'environnement
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', '5000'))
    debug = os.getenv('FLASK_DEBUG', '0') == '1'

    try:
        # Tester la connexion à la base de données avant démarrage
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
    except Exception as e:
        logger.error("❌ Erreur de connexion à MySQL: %s", e)
        logger.error("Vérifiez que MySQL est démarré et que les paramètres de connexion sont corrects.")
        exit(1)

    # Assurer la présence des tables requises
    ensure_tables()

    # Démarrer l'app (pour dev local). En production, utilisez gunicorn: e.g.
    # gunicorn -w 4 -b 0.0.0.0:8000 "app:app"
    app.run(host=host, port=port, debug=debug)
