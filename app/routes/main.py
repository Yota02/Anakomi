from flask import Blueprint, render_template, request, flash
from app.database import fetch_all

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    q = (request.args.get('q') or '').strip()
    sort = request.args.get('sort', 'recent')

    # Liste blanche des tris autorisés
    _allowed_sorts = {
        'recent': 'a.created_at DESC, a.id DESC',
        'title_asc': 'LOWER(a.title) ASC, a.id DESC',
        'title_desc': 'LOWER(a.title) DESC, a.id DESC',
        'rating_desc': 'AVG(r.rating) DESC, a.id DESC'
    }
    order_clause = _allowed_sorts.get(sort, _allowed_sorts['recent'])

    try:
        # Fetch animes
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
                LIMIT 6
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
                LIMIT 6
                """
            )
        
        # Fetch latest video games (only if no search query to keep it clean, or we could filter them too)
        videogames = []
        if not q:
            videogames = fetch_all(
                """
                SELECT v.*, 
                       COALESCE(ROUND(AVG(vr.rating),1), 0) AS avg_rating
                FROM videogame v
                LEFT JOIN videogame_review vr ON v.id = vr.videogame_id
                GROUP BY v.id
                ORDER BY v.created_at DESC, v.id DESC
                LIMIT 4
                """
            )
            
        # Fetch latest waifus
        waifus = []
        if not q:
            waifus = fetch_all(
                """
                SELECT w.*, 
                       COALESCE(ROUND(AVG(wr.rating),1), 0) AS avg_rating
                FROM waifu w
                LEFT JOIN waifu_review wr ON w.id = wr.waifu_id
                GROUP BY w.id
                ORDER BY w.created_at DESC, w.id DESC
                LIMIT 4
                """
            )

    except Exception as e:
        flash("Erreur lors de la lecture des données.")
        animes = []
        videogames = []
        waifus = []

    return render_template('index.html', animes=animes, videogames=videogames, waifus=waifus, sort=sort)

@main_bp.route('/contact')
def contact():
    return render_template('contact.html')
