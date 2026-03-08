from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.database import fetch_one, fetch_all, execute_query
from app.models import get_user_table_info
from app.utils import get_current_user
from app.decorators import login_required

videogame_bp = Blueprint('videogame', __name__)

@videogame_bp.route('/videogames')
def videogames_list():
    q = (request.args.get('q') or '').strip()
    sort = request.args.get('sort', 'recent')

    _allowed_sorts = {
        'recent': 'v.created_at DESC, v.id DESC',
        'title_asc': 'LOWER(v.title) ASC, v.id DESC',
        'title_desc': 'LOWER(v.title) DESC, v.id DESC',
        'rating_desc': 'AVG(r.rating) DESC, v.id DESC'
    }
    order_clause = _allowed_sorts.get(sort, _allowed_sorts['recent'])

    try:
        if q:
            pattern = f"%{q}%"
            videogames = fetch_all(
                f"""
                SELECT v.*, 
                       COALESCE(ROUND(AVG(r.rating),1), 0) AS avg_rating,
                       COUNT(r.id) AS review_count
                FROM videogame v
                LEFT JOIN videogame_review r ON v.id = r.videogame_id
                WHERE LOWER(v.title) LIKE %s OR LOWER(v.description) LIKE %s
                GROUP BY v.id
                ORDER BY {order_clause}
                """,
                (pattern.lower(), pattern.lower())
            )
        else:
            videogames = fetch_all(
                f"""
                SELECT v.*, 
                       COALESCE(ROUND(AVG(r.rating),1), 0) AS avg_rating,
                       COUNT(r.id) AS review_count
                FROM videogame v
                LEFT JOIN videogame_review r ON v.id = r.videogame_id
                GROUP BY v.id
                ORDER BY {order_clause}
                """
            )
    except Exception:
        flash("Erreur lors de la lecture des jeux vidéo.")
        videogames = []

    return render_template('videogames_list.html', videogames=videogames, sort=sort)

@videogame_bp.route('/add_videogame', methods=['GET', 'POST'])
@login_required
def add_videogame():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        genre = request.form['genre']
        year = request.form['year']
        platform = request.form['platform']
        cover_url = request.form.get('cover_url', '')
        
        execute_query(
            "INSERT INTO videogame (title, description, genre, year, platform, cover_url, added_by) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (title, description, genre, int(year), platform, cover_url, session['user_id'])
        )
        
        flash('Jeu vidéo ajouté avec succès')
        return redirect(url_for('videogame.videogames_list'))
    
    return render_template('add_videogame.html')

@videogame_bp.route('/videogame/<int:id>')
def videogame_detail(id):
    videogame = fetch_one("SELECT * FROM videogame WHERE id = %s", (id,))
    if not videogame:
        flash('Jeu vidéo non trouvé')
        return redirect(url_for('videogame.videogames_list'))
    
    info = get_user_table_info()
    user_tbl = info['table']
    reviews = fetch_all(f"""
        SELECT r.*, u.username 
        FROM videogame_review r 
        JOIN {user_tbl} u ON r.user_id = u.id 
        WHERE r.videogame_id = %s 
        ORDER BY r.created_at DESC
    """, (id,))
    
    avg_rating = 0
    if reviews:
        avg_rating = sum(review['rating'] for review in reviews) / len(reviews)
    
    return render_template('videogame_detail.html', videogame=videogame, reviews=reviews, avg_rating=round(avg_rating, 1))

@videogame_bp.route('/add_videogame_review/<int:videogame_id>', methods=['POST'])
@login_required
def add_videogame_review(videogame_id):
    rating = request.form.get('rating')
    comment = request.form['comment']
    parent_id = request.form.get('parent_id')
    
    if parent_id:
        execute_query(
            "INSERT INTO videogame_review (rating, comment, user_id, videogame_id, parent_id) VALUES (%s, %s, %s, %s, %s)",
            (rating, comment, session['user_id'], videogame_id, parent_id)
        )
        flash('Réponse ajoutée avec succès')
    else:
        existing_review = fetch_one(
            "SELECT id FROM videogame_review WHERE user_id = %s AND videogame_id = %s AND parent_id IS NULL",
            (session['user_id'], videogame_id)
        )
        
        if existing_review:
            execute_query(
                "UPDATE videogame_review SET rating = %s, comment = %s, created_at = NOW() WHERE id = %s",
                (rating, comment, existing_review['id'])
            )
            flash('Avis modifié avec succès')
        else:
            execute_query(
                "INSERT INTO videogame_review (rating, comment, user_id, videogame_id) VALUES (%s, %s, %s, %s)",
                (rating, comment, session['user_id'], videogame_id)
            )
            flash('Avis ajouté avec succès')
    
    return redirect(url_for('videogame.videogame_detail', id=videogame_id))

@videogame_bp.route('/videogame-top10/users')
def videogame_top10_users():
    info = get_user_table_info()
    user_tbl = info['table']
    
    users_with_top10 = fetch_all(f"""
        SELECT DISTINCT u.id, u.username, COUNT(t.id) as videogame_count
        FROM {user_tbl} u
        JOIN user_videogame_top10 t ON u.id = t.user_id
        WHERE t.is_public = 1
        GROUP BY u.id, u.username
        ORDER BY u.username
    """)
    
    return render_template('videogame_top10_users.html', users=users_with_top10)

@videogame_bp.route('/videogame-top10/user/<int:user_id>')
def view_user_videogame_top10(user_id):
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
            "SELECT id FROM user_videogame_top10 WHERE user_id = %s AND is_public = 1 LIMIT 1",
            (user_id,)
        )
        if not public_check:
            flash("Ce top 10 jeux vidéo est privé")
            return redirect(url_for('videogame.videogame_top10_users'))
    
    where_clause = "" if is_owner else "AND t.is_public = 1"
    
    top10 = fetch_all(f"""
        SELECT t.rank_position, t.is_public, v.id, v.title, v.cover_url, v.genre, v.year, v.platform,
               COALESCE(ROUND(AVG(r.rating),1), 0) AS avg_rating
        FROM user_videogame_top10 t
        JOIN videogame v ON t.videogame_id = v.id
        LEFT JOIN videogame_review r ON v.id = r.videogame_id
        WHERE t.user_id = %s {where_clause}
        GROUP BY t.rank_position, t.is_public, v.id, v.title, v.cover_url, v.genre, v.year, v.platform
        ORDER BY t.rank_position
    """, (user_id,))
    
    return render_template('view_videogame_top10.html', user=user, top10=top10, is_owner=is_owner)

@videogame_bp.route('/my-videogame-top10')
@login_required
def my_videogame_top10():
    user_id = session['user_id']
    
    top10 = fetch_all("""
        SELECT t.rank_position, t.is_public, v.id, v.title, v.cover_url
        FROM user_videogame_top10 t
        JOIN videogame v ON t.videogame_id = v.id
        WHERE t.user_id = %s
        ORDER BY t.rank_position
    """, (user_id,))
    
    all_videogames = fetch_all("SELECT id, title FROM videogame ORDER BY title")
    
    return render_template('manage_videogame_top10.html', top10=top10, all_videogames=all_videogames)

@videogame_bp.route('/my-videogame-top10/update', methods=['POST'])
@login_required
def update_videogame_top10():
    user_id = session['user_id']
    execute_query("DELETE FROM user_videogame_top10 WHERE user_id = %s", (user_id,))
    is_public = 1 if request.form.get('is_public') == 'on' else 0
    
    for i in range(1, 11):
        videogame_id = request.form.get(f'videogame_{i}')
        if videogame_id and videogame_id.isdigit():
            execute_query(
                "INSERT INTO user_videogame_top10 (user_id, videogame_id, rank_position, is_public) VALUES (%s, %s, %s, %s)",
                (user_id, int(videogame_id), i, is_public)
            )
    
    flash("Votre top 10 jeux vidéo a été mis à jour avec succès")
    return redirect(url_for('videogame.my_videogame_top10'))

@videogame_bp.route('/edit_videogame/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_videogame(id):
    videogame = fetch_one("SELECT * FROM videogame WHERE id = %s", (id,))
    if not videogame:
        flash('Jeu vidéo non trouvé')
        return redirect(url_for('videogame.videogames_list'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        genre = request.form['genre']
        year = request.form['year']
        platform = request.form['platform']
        cover_url = request.form.get('cover_url', '')
        
        execute_query(
            "UPDATE videogame SET title = %s, description = %s, genre = %s, year = %s, platform = %s, cover_url = %s WHERE id = %s",
            (title, description, genre, int(year), platform, cover_url, id)
        )
        
        flash('Jeu vidéo modifié avec succès')
        return redirect(url_for('videogame.videogame_detail', id=id))
    
    return render_template('edit_videogame.html', videogame=videogame)
