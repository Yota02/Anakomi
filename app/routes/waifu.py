from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.database import fetch_one, fetch_all, execute_query
from app.models import get_user_table_info
from app.utils import get_current_user
from app.decorators import login_required

waifu_bp = Blueprint('waifu', __name__)

@waifu_bp.route('/waifus')
def waifus_list():
    q = (request.args.get('q') or '').strip()
    sort = request.args.get('sort') or 'name_asc'
    gender_filter = request.args.get('gender')
    category_filter = request.args.get('category')

    _allowed_sorts = {
        'name_asc': 'LOWER(w.name) ASC, w.id DESC',
        'name_desc': 'LOWER(w.name) DESC, w.id DESC',
        'rating_desc': 'AVG(r.rating) DESC, w.id DESC',
        'rating_asc': 'AVG(r.rating) ASC, w.id DESC',
        'reviews_desc': 'COUNT(r.id) DESC, w.id DESC',
        'reviews_asc': 'COUNT(r.id) ASC, w.id DESC'
    }
    order_clause = _allowed_sorts.get(sort, _allowed_sorts['name_asc'])

    where_conditions = []
    params = []
    if q:
        pattern = f"%{q}%"
        where_conditions.append("(LOWER(w.name) LIKE %s OR LOWER(w.description) LIKE %s OR LOWER(a.title) LIKE %s OR LOWER(v.title) LIKE %s)")
        params.extend([pattern.lower(), pattern.lower(), pattern.lower(), pattern.lower()])
    if gender_filter in ['girl', 'boy']:
        where_conditions.append("w.gender = %s")
        params.append(gender_filter)
    if category_filter in ['anime', 'videogame']:
        if category_filter == 'anime':
            where_conditions.append("w.anime_id IS NOT NULL")
        else:
            where_conditions.append("w.videogame_id IS NOT NULL")
    where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"

    try:
        waifus = fetch_all(
            f"""
            SELECT w.*,
                   a.title as anime_title,
                   v.title as videogame_title,
                   CASE 
                       WHEN w.anime_id IS NOT NULL THEN 'anime'
                       WHEN w.videogame_id IS NOT NULL THEN 'videogame'
                   END as source_type,
                   COALESCE(ROUND(AVG(r.rating),1), 0) AS avg_rating,
                   COUNT(r.id) AS review_count
            FROM waifu w
            LEFT JOIN anime a ON w.anime_id = a.id
            LEFT JOIN videogame v ON w.videogame_id = v.id
            LEFT JOIN waifu_review r ON w.id = r.waifu_id
            WHERE {where_clause}
            GROUP BY w.id
            ORDER BY {order_clause}
            """,
            params
        )
    except Exception:
        flash("Erreur lors de la lecture des waifus.")
        waifus = []

    return render_template('waifus_list.html', waifus=waifus, sort=sort, gender_filter=gender_filter, category_filter=category_filter)

@waifu_bp.route('/add_waifu', methods=['GET', 'POST'])
@login_required
def add_waifu():
    if request.method == 'POST':
        name = request.form['name']
        source_type = request.form['source_type']
        source_id = request.form['source_id']
        description = request.form.get('description', '')
        image_url = request.form.get('image_url', '')
        gender = request.form['gender']
        
        if source_type == 'anime' and source_id:
            anime_id = int(source_id)
            videogame_id = None
        elif source_type == 'videogame' and source_id:
            anime_id = None
            videogame_id = int(source_id)
        else:
            flash('Veuillez sélectionner une source valide pour la waifu')
            animes = fetch_all("SELECT id, title FROM anime ORDER BY title")
            videogames = fetch_all("SELECT id, title FROM videogame ORDER BY title")
            return render_template('add_waifu.html', animes=animes, videogames=videogames)
        
        execute_query(
            "INSERT INTO waifu (name, anime_id, videogame_id, description, image_url, added_by, gender) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (name, anime_id, videogame_id, description, image_url, session['user_id'], gender)
        )
        
        flash('Waifu ajoutée avec succès')
        return redirect(url_for('waifu.waifus_list'))
    
    animes = fetch_all("SELECT id, title FROM anime ORDER BY title")
    videogames = fetch_all("SELECT id, title FROM videogame ORDER BY title")
    return render_template('add_waifu.html', animes=animes, videogames=videogames)

@waifu_bp.route('/waifu/<int:id>')
def waifu_detail(id):
    waifu = fetch_one("""
        SELECT w.*, 
               a.title as anime_title, a.id as anime_id,
               v.title as videogame_title, v.id as videogame_id,
               CASE 
                   WHEN w.anime_id IS NOT NULL THEN 'anime'
                   WHEN w.videogame_id IS NOT NULL THEN 'videogame'
               END as source_type
        FROM waifu w
        LEFT JOIN anime a ON w.anime_id = a.id
        LEFT JOIN videogame v ON w.videogame_id = v.id
        WHERE w.id = %s
    """, (id,))
    
    if not waifu:
        flash('Waifu non trouvée')
        return redirect(url_for('waifu.waifus_list'))
    
    info = get_user_table_info()
    user_tbl = info['table']
    reviews = fetch_all(f"""
        SELECT r.*, u.username 
        FROM waifu_review r 
        JOIN {user_tbl} u ON r.user_id = u.id 
        WHERE r.waifu_id = %s 
        ORDER BY r.created_at DESC
    """, (id,))
    
    avg_rating = 0
    if reviews:
        avg_rating = sum(review['rating'] for review in reviews) / len(reviews)
    
    return render_template('waifu_detail.html', waifu=waifu, reviews=reviews, avg_rating=round(avg_rating, 1))

@waifu_bp.route('/add_waifu_review/<int:waifu_id>', methods=['POST'])
@login_required
def add_waifu_review(waifu_id):
    rating = request.form.get('rating')
    comment = request.form['comment']
    parent_id = request.form.get('parent_id')
    
    if parent_id:
        execute_query(
            "INSERT INTO waifu_review (rating, comment, user_id, waifu_id, parent_id) VALUES (%s, %s, %s, %s, %s)",
            (rating, comment, session['user_id'], waifu_id, parent_id)
        )
        flash('Réponse ajoutée avec succès')
    else:
        existing_review = fetch_one(
            "SELECT id FROM waifu_review WHERE user_id = %s AND waifu_id = %s AND parent_id IS NULL",
            (session['user_id'], waifu_id)
        )
        
        if existing_review:
            execute_query(
                "UPDATE waifu_review SET rating = %s, comment = %s, created_at = NOW() WHERE id = %s",
                (rating, comment, existing_review['id'])
            )
            flash('Avis modifié avec succès')
        else:
            execute_query(
                "INSERT INTO waifu_review (rating, comment, user_id, waifu_id) VALUES (%s, %s, %s, %s)",
                (rating, comment, session['user_id'], waifu_id)
            )
            flash('Avis ajouté avec succès')
    
    # Automatiquement mettre à jour la rareté basée sur la nouvelle moyenne
    update_waifu_rarity(waifu_id)
    
    return redirect(url_for('waifu.waifu_detail', id=waifu_id))

def update_waifu_rarity(waifu_id):
    stats = fetch_one("""
        SELECT COALESCE(AVG(rating), 0) as avg_rating, COUNT(id) as count 
        FROM waifu_review 
        WHERE waifu_id = %s AND parent_id IS NULL
    """, (waifu_id,))
    
    if stats and stats['count'] > 0:
        avg = stats['avg_rating']
        new_rarity = 'Commune'
        if avg >= 4.5:
            new_rarity = 'Légendaire'
        elif avg >= 4.0:
            new_rarity = 'Épique'
        elif avg >= 3.0:
            new_rarity = 'Rare'
        
        execute_query("UPDATE waifu SET rarity = %s WHERE id = %s", (new_rarity, waifu_id))

@waifu_bp.route('/my-waifu-top5')
@login_required
def my_waifu_top5():
    user_id = session['user_id']
    
    top5 = fetch_all("""
        SELECT t.rank_position, t.is_public, w.id, w.name, w.image_url, w.description,
               a.title as anime_title, a.id as anime_id,
               v.title as videogame_title, v.id as videogame_id,
               CASE 
                   WHEN w.anime_id IS NOT NULL THEN 'anime'
                   WHEN w.videogame_id IS NOT NULL THEN 'videogame'
               END as source_type
        FROM user_waifu_top5 t
        JOIN waifu w ON t.waifu_id = w.id
        LEFT JOIN anime a ON w.anime_id = a.id
        LEFT JOIN videogame v ON w.videogame_id = v.id
        WHERE t.user_id = %s
        ORDER BY t.rank_position
    """, (user_id,))
    
    all_waifus = fetch_all("""
        SELECT w.id, w.name, 
               a.title as anime_title,
               v.title as videogame_title,
               CASE 
                   WHEN w.anime_id IS NOT NULL THEN a.title
                   WHEN w.videogame_id IS NOT NULL THEN v.title
               END as source_title
        FROM waifu w
        LEFT JOIN anime a ON w.anime_id = a.id
        LEFT JOIN videogame v ON w.videogame_id = v.id
        ORDER BY w.name
    """)
    
    return render_template('manage_waifu_top5.html', top5=top5, all_waifus=all_waifus)

@waifu_bp.route('/my-waifu-top5/update', methods=['POST'])
@login_required
def update_waifu_top5():
    user_id = session['user_id']
    execute_query("DELETE FROM user_waifu_top5 WHERE user_id = %s", (user_id,))
    is_public = 1 if request.form.get('is_public') == 'on' else 0
    
    for i in range(1, 11):
        waifu_id = request.form.get(f'waifu_{i}')
        if waifu_id and waifu_id.isdigit():
            execute_query(
                "INSERT INTO user_waifu_top5 (user_id, waifu_id, rank_position, is_public) VALUES (%s, %s, %s, %s)",
                (user_id, int(waifu_id), i, is_public)
            )
    
    flash("Votre top 10 waifu a été mis à jour avec succès")
    return redirect(url_for('waifu.my_waifu_top5'))

@waifu_bp.route('/waifu-top5/users')
def waifu_top5_users():
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

@waifu_bp.route('/waifu-top5/user/<int:user_id>')
def view_user_waifu_top5(user_id):
    info = get_user_table_info()
    user_tbl = info['table']
    
    user = fetch_one(f"SELECT id, username FROM {user_tbl} WHERE id = %s", (user_id,))
    if not user:
        flash("Utilisateur non trouvé")
        return redirect(url_for('main.index'))
    
    current_user_obj = get_current_user()
    is_owner = current_user_obj and current_user_obj.id == user_id
    
    if not is_owner:
        public_check = fetch_one(
            "SELECT id FROM user_waifu_top5 WHERE user_id = %s AND is_public = 1 LIMIT 1",
            (user_id,)
        )
        if not public_check:
            flash("Ce top 10 waifu est privé")
            return redirect(url_for('waifu.waifu_top5_users'))
    
    top5 = fetch_all(f"""
        SELECT t.rank_position, t.is_public, w.id, w.name, w.image_url, w.description,
               a.title as anime_title, a.id as anime_id,
               v.title as videogame_title, v.id as videogame_id,
               CASE 
                   WHEN w.anime_id IS NOT NULL THEN 'anime'
                   WHEN w.videogame_id IS NOT NULL THEN 'videogame'
               END as source_type,
               COALESCE(ROUND(AVG(r.rating),1), 0) AS avg_rating
        FROM user_waifu_top5 t
        JOIN waifu w ON t.waifu_id = w.id
        LEFT JOIN anime a ON w.anime_id = a.id
        LEFT JOIN videogame v ON w.videogame_id = v.id
        LEFT JOIN waifu_review r ON w.id = r.waifu_id
        WHERE t.user_id = %s {"" if is_owner else "AND t.is_public = 1"}
        GROUP BY t.rank_position, t.is_public, w.id, w.name, w.image_url, w.description, a.title, a.id, v.title, v.id
        ORDER BY t.rank_position
    """, (user_id,))
    
    return render_template('view_waifu_top5.html', user=user, top5=top5, is_owner=is_owner)

@waifu_bp.route('/edit_waifu/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_waifu(id):
    waifu = fetch_one("SELECT * FROM waifu WHERE id = %s", (id,))
    if not waifu:
        flash('Personnage non trouvé')
        return redirect(url_for('waifu.waifus_list'))
    
    if request.method == 'POST':
        name = request.form['name']
        source_type = request.form['source_type']
        source_id = request.form['source_id']
        description = request.form.get('description', '')
        image_url = request.form.get('image_url', '')
        gender = request.form['gender']
        
        if source_type == 'anime' and source_id:
            anime_id = int(source_id)
            videogame_id = None
        elif source_type == 'videogame' and source_id:
            anime_id = None
            videogame_id = int(source_id)
        else:
            flash('Veuillez sélectionner une source valide pour le personnage')
            animes = fetch_all("SELECT id, title FROM anime ORDER BY title")
            videogames = fetch_all("SELECT id, title FROM videogame ORDER BY title")
            return render_template('edit_waifu.html', waifu=waifu, animes=animes, videogames=videogames)
        
        execute_query(
            "UPDATE waifu SET name = %s, anime_id = %s, videogame_id = %s, description = %s, image_url = %s, gender = %s WHERE id = %s",
            (name, anime_id, videogame_id, description, image_url, gender, id)
        )
        
        flash('Personnage modifié avec succès')
        return redirect(url_for('waifu.waifu_detail', id=id))
    
    animes = fetch_all("SELECT id, title FROM anime ORDER BY title")
    videogames = fetch_all("SELECT id, title FROM videogame ORDER BY title")
    return render_template('edit_waifu.html', waifu=waifu, animes=animes, videogames=videogames)

@waifu_bp.route('/waifus/anime/filles')
def waifus_anime_filles():
    q = (request.args.get('q') or '').strip()
    sort = request.args.get('sort') or 'name_asc'
    _allowed_sorts = {
        'name_asc': 'LOWER(w.name) ASC, w.id DESC',
        'name_desc': 'LOWER(w.name) DESC, w.id DESC',
        'rating_desc': 'AVG(r.rating) DESC, w.id DESC',
        'rating_asc': 'AVG(r.rating) ASC, w.id DESC',
        'reviews_desc': 'COUNT(r.id) DESC, w.id DESC',
        'reviews_asc': 'COUNT(r.id) ASC, w.id DESC'
    }
    order_clause = _allowed_sorts.get(sort, _allowed_sorts['name_asc'])
    where_conditions = ["w.gender = 'girl'", "w.anime_id IS NOT NULL"]
    params = []
    if q:
        pattern = f"%{q}%"
        where_conditions.append("(LOWER(w.name) LIKE %s OR LOWER(w.description) LIKE %s)")
        params.extend([pattern.lower(), pattern.lower()])
    
    waifus = fetch_all(
        f"""
        SELECT w.*, a.title as anime_title, 'anime' as source_type,
               COALESCE(ROUND(AVG(r.rating),1), 0) AS avg_rating, COUNT(r.id) AS review_count
        FROM waifu w
        LEFT JOIN anime a ON w.anime_id = a.id
        LEFT JOIN waifu_review r ON w.id = r.waifu_id
        WHERE {" AND ".join(where_conditions)}
        GROUP BY w.id ORDER BY {order_clause}
        """, params
    )
    return render_template('waifus_anime_filles.html', waifus=waifus, sort=sort)

@waifu_bp.route('/waifus/anime/garcons')
def waifus_anime_garcons():
    q = (request.args.get('q') or '').strip()
    sort = request.args.get('sort') or 'name_asc'
    _allowed_sorts = {
        'name_asc': 'LOWER(w.name) ASC, w.id DESC',
        'name_desc': 'LOWER(w.name) DESC, w.id DESC',
        'rating_desc': 'AVG(r.rating) DESC, w.id DESC',
        'rating_asc': 'AVG(r.rating) ASC, w.id DESC',
        'reviews_desc': 'COUNT(r.id) DESC, w.id DESC',
        'reviews_asc': 'COUNT(r.id) ASC, w.id DESC'
    }
    order_clause = _allowed_sorts.get(sort, _allowed_sorts['name_asc'])
    where_conditions = ["w.gender = 'boy'", "w.anime_id IS NOT NULL"]
    params = []
    if q:
        pattern = f"%{q}%"
        where_conditions.append("(LOWER(w.name) LIKE %s OR LOWER(w.description) LIKE %s)")
        params.extend([pattern.lower(), pattern.lower()])
    
    waifus = fetch_all(
        f"""
        SELECT w.*, a.title as anime_title, 'anime' as source_type,
               COALESCE(ROUND(AVG(r.rating),1), 0) AS avg_rating, COUNT(r.id) AS review_count
        FROM waifu w
        LEFT JOIN anime a ON w.anime_id = a.id
        LEFT JOIN waifu_review r ON w.id = r.waifu_id
        WHERE {" AND ".join(where_conditions)}
        GROUP BY w.id ORDER BY {order_clause}
        """, params
    )
    return render_template('waifus_anime_garcons.html', waifus=waifus, sort=sort)

@waifu_bp.route('/waifus/jeux-video/filles')
def waifus_jeux_video_filles():
    q = (request.args.get('q') or '').strip()
    sort = request.args.get('sort') or 'name_asc'
    _allowed_sorts = {
        'name_asc': 'LOWER(w.name) ASC, w.id DESC',
        'name_desc': 'LOWER(w.name) DESC, w.id DESC',
        'rating_desc': 'AVG(r.rating) DESC, w.id DESC',
        'rating_asc': 'AVG(r.rating) ASC, w.id DESC',
        'reviews_desc': 'COUNT(r.id) DESC, w.id DESC',
        'reviews_asc': 'COUNT(r.id) ASC, w.id DESC'
    }
    order_clause = _allowed_sorts.get(sort, _allowed_sorts['name_asc'])
    where_conditions = ["w.gender = 'girl'", "w.videogame_id IS NOT NULL"]
    params = []
    if q:
        pattern = f"%{q}%"
        where_conditions.append("(LOWER(w.name) LIKE %s OR LOWER(w.description) LIKE %s)")
        params.extend([pattern.lower(), pattern.lower()])
    
    waifus = fetch_all(
        f"""
        SELECT w.*, v.title as videogame_title, 'videogame' as source_type,
               COALESCE(ROUND(AVG(r.rating),1), 0) AS avg_rating, COUNT(r.id) AS review_count
        FROM waifu w
        LEFT JOIN videogame v ON w.videogame_id = v.id
        LEFT JOIN waifu_review r ON w.id = r.waifu_id
        WHERE {" AND ".join(where_conditions)}
        GROUP BY w.id ORDER BY {order_clause}
        """, params
    )
    return render_template('waifus_jeux_video_filles.html', waifus=waifus, sort=sort)

@waifu_bp.route('/waifus/jeux-video/garcons')
def waifus_jeux_video_garcons():
    q = (request.args.get('q') or '').strip()
    sort = request.args.get('sort') or 'name_asc'
    _allowed_sorts = {
        'name_asc': 'LOWER(w.name) ASC, w.id DESC',
        'name_desc': 'LOWER(w.name) DESC, w.id DESC',
        'rating_desc': 'AVG(r.rating) DESC, w.id DESC',
        'rating_asc': 'AVG(r.rating) ASC, w.id DESC',
        'reviews_desc': 'COUNT(r.id) DESC, w.id DESC',
        'reviews_asc': 'COUNT(r.id) ASC, w.id DESC'
    }
    order_clause = _allowed_sorts.get(sort, _allowed_sorts['name_asc'])
    where_conditions = ["w.gender = 'boy'", "w.videogame_id IS NOT NULL"]
    params = []
    if q:
        pattern = f"%{q}%"
        where_conditions.append("(LOWER(w.name) LIKE %s OR LOWER(w.description) LIKE %s)")
        params.extend([pattern.lower(), pattern.lower()])
    
    waifus = fetch_all(
        f"""
        SELECT w.*, v.title as videogame_title, 'videogame' as source_type,
               COALESCE(ROUND(AVG(r.rating),1), 0) AS avg_rating, COUNT(r.id) AS review_count
        FROM waifu w
        LEFT JOIN videogame v ON w.videogame_id = v.id
        LEFT JOIN waifu_review r ON w.id = r.waifu_id
        WHERE {" AND ".join(where_conditions)}
        GROUP BY w.id ORDER BY {order_clause}
        """, params
    )
    return render_template('waifus_jeux_video_garcons.html', waifus=waifus, sort=sort)
