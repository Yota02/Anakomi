from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.database import fetch_one, fetch_all, execute_query
from app.models import get_user_table_info
from app.utils import get_current_user
from app.decorators import login_required

anime_bp = Blueprint('anime', __name__)

@anime_bp.route('/add_anime', methods=['GET', 'POST'])
@login_required
def add_anime():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        genre = request.form['genre']
        year = request.form['year']
        cover_url = request.form.get('cover_url', '')
        opening_url = request.form.get('opening_url', '')
        
        execute_query(
            "INSERT INTO anime (title, description, genre, year, cover_url, opening_url, added_by) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (title, description, genre, int(year), cover_url, opening_url, session['user_id'])
        )
        
        flash('Anime ajouté avec succès')
        return redirect(url_for('main.index'))
    
    return render_template('add_anime.html')

@anime_bp.route('/anime/<int:id>')
def anime_detail(id):
    anime = fetch_one("SELECT * FROM anime WHERE id = %s", (id,))
    if not anime:
        flash('Anime non trouvé')
        return redirect(url_for('main.index'))
    
    info = get_user_table_info()
    user_tbl = info['table']
    reviews = fetch_all(f"""
        SELECT r.*, u.username,
               (SELECT GROUP_CONCAT(CONCAT(emoji, ':', count) SEPARATOR '|') FROM (
                   SELECT emoji, COUNT(*) as count FROM review_reaction WHERE review_id = r.id GROUP BY emoji
               ) as t) as reactions
        FROM review r 
        JOIN {user_tbl} u ON r.user_id = u.id 
        WHERE r.anime_id = %s 
        ORDER BY r.date_created DESC
    """, (id,))
    
    avg_rating = 0
    if reviews:
        avg_rating = sum(review['rating'] for review in reviews) / len(reviews)
    
    return render_template('anime_detail.html', anime=anime, reviews=reviews, avg_rating=round(avg_rating, 1))

@anime_bp.route('/add_review/<int:anime_id>', methods=['POST'])
@login_required
def add_review(anime_id):
    rating = request.form.get('rating')
    comment = request.form['comment']
    parent_id = request.form.get('parent_id')
    
    if parent_id:
        # For replies, rating is usually not required or relevant if it's just a comment hierarchy
        # But we'll keep the structure. Ratings might be NULL for replies.
        execute_query(
            "INSERT INTO review (rating, comment, user_id, anime_id, parent_id) VALUES (%s, %s, %s, %s, %s)",
            (rating, comment, session['user_id'], anime_id, parent_id)
        )
        flash('Réponse ajoutée avec succès')
    else:
        existing_review = fetch_one(
            "SELECT id FROM review WHERE user_id = %s AND anime_id = %s AND parent_id IS NULL",
            (session['user_id'], anime_id)
        )
        
        if existing_review:
            execute_query(
                "UPDATE review SET rating = %s, comment = %s, date_created = NOW() WHERE id = %s",
                (rating, comment, existing_review['id'])
            )
            flash('Avis modifié avec succès')
        else:
            execute_query(
                "INSERT INTO review (rating, comment, user_id, anime_id) VALUES (%s, %s, %s, %s)",
                (rating, comment, session['user_id'], anime_id)
            )
            flash('Avis ajouté avec succès')
    
    return redirect(url_for('anime.anime_detail', id=anime_id))

@anime_bp.route('/react_review/<int:review_id>', methods=['POST'])
@login_required
def react_review(review_id):
    emoji = request.form.get('emoji')
    anime_id = request.form.get('anime_id')
    user_id = session['user_id']
    
    if emoji:
        execute_query("""
            INSERT INTO review_reaction (review_id, user_id, emoji) 
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE emoji = %s
        """, (review_id, user_id, emoji, emoji))
    
    return redirect(url_for('anime.anime_detail', id=anime_id))


@anime_bp.route('/edit_anime/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_anime(id):
    anime = fetch_one("SELECT * FROM anime WHERE id = %s", (id,))
    if not anime:
        flash('Anime non trouvé')
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        genre = request.form['genre']
        year = request.form['year']
        cover_url = request.form.get('cover_url', '')
        opening_url = request.form.get('opening_url', '')
        
        execute_query(
            "UPDATE anime SET title = %s, description = %s, genre = %s, year = %s, cover_url = %s, opening_url = %s WHERE id = %s",
            (title, description, genre, int(year), cover_url, opening_url, id)
        )
        
        flash('Anime modifié avec succès')
        return redirect(url_for('anime.anime_detail', id=id))
    
    return render_template('edit_anime.html', anime=anime)

@anime_bp.route('/top10/users')
def top10_users():
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

@anime_bp.route('/top10/user/<int:user_id>')
def view_user_top10(user_id):
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
            "SELECT id FROM user_top10 WHERE user_id = %s AND is_public = 1 LIMIT 1",
            (user_id,)
        )
        if not public_check:
            flash("Ce top 10 est privé")
            return redirect(url_for('anime.top10_users'))
    
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

@anime_bp.route('/my-top10')
@login_required
def my_top10():
    user_id = session['user_id']
    
    top10 = fetch_all("""
        SELECT t.rank_position, t.is_public, a.id, a.title, a.cover_url
        FROM user_top10 t
        JOIN anime a ON t.anime_id = a.id
        WHERE t.user_id = %s
        ORDER BY t.rank_position
    """, (user_id,))
    
    all_animes = fetch_all("SELECT id, title FROM anime ORDER BY title")
    
    return render_template('manage_top10.html', top10=top10, all_animes=all_animes)

@anime_bp.route('/my-top10/update', methods=['POST'])
@login_required
def update_top10():
    user_id = session['user_id']
    execute_query("DELETE FROM user_top10 WHERE user_id = %s", (user_id,))
    is_public = 1 if request.form.get('is_public') == 'on' else 0
    
    for i in range(1, 11):
        anime_id = request.form.get(f'anime_{i}')
        if anime_id and anime_id.isdigit():
            execute_query(
                "INSERT INTO user_top10 (user_id, anime_id, rank_position, is_public) VALUES (%s, %s, %s, %s)",
                (user_id, int(anime_id), i, is_public)
            )
    
    flash("Votre top 10 a été mis à jour avec succès")
    return redirect(url_for('anime.my_top10'))
