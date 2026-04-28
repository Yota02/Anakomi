from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.database import fetch_all, fetch_one, execute_query
from app.database import fetch_all, fetch_one, execute_query
from app.decorators import login_required
import random
from collections import Counter
from datetime import date

extra_bp = Blueprint('extra', __name__)

@extra_bp.route('/profile/stats')
@login_required
def user_stats():
    user_id = session['user_id']
    
    # 1. Distribution des genres (Animes ajoutés)
    genre_data = fetch_all("""
        SELECT genre, COUNT(*) as count 
        FROM anime 
        WHERE added_by = %s 
        GROUP BY genre
    """, (user_id,))
    
    # 2. Évolution de l'activité (Items ajoutés par mois)
    activity_data = fetch_all("""
        SELECT month, COUNT(*) as count FROM (
            SELECT DATE_FORMAT(created_at, '%%Y-%%m') as month FROM anime WHERE added_by = %s
            UNION ALL
            SELECT DATE_FORMAT(created_at, '%%Y-%%m') as month FROM videogame WHERE added_by = %s
            UNION ALL
            SELECT DATE_FORMAT(created_at, '%%Y-%%m') as month FROM waifu WHERE added_by = %s
        ) as combined_activity
        GROUP BY month
        ORDER BY month ASC
    """, (user_id, user_id, user_id))
    
    # 3. Distribution des notes données
    rating_data = fetch_all("""
        SELECT rating, COUNT(*) as count FROM (
            SELECT rating FROM review WHERE user_id = %s
            UNION ALL
            SELECT rating FROM videogame_review WHERE user_id = %s
            UNION ALL
            SELECT rating FROM waifu_review WHERE user_id = %s
        ) as all_ratings
        WHERE rating IS NOT NULL
        GROUP BY rating
        ORDER BY rating ASC
    """, (user_id, user_id, user_id))
    
    # 4. Quelques chiffres clés
    counts = fetch_one("""
        SELECT 
            (SELECT COUNT(*) FROM anime WHERE added_by = %s) as anime_count,
            (SELECT COUNT(*) FROM videogame WHERE added_by = %s) as vg_count,
            (SELECT COUNT(*) FROM waifu WHERE added_by = %s) as waifu_count,
            (SELECT COUNT(*) FROM review WHERE user_id = %s) + 
            (SELECT COUNT(*) FROM videogame_review WHERE user_id = %s) +
            (SELECT COUNT(*) FROM waifu_review WHERE user_id = %s) as total_reviews
    """, (user_id, user_id, user_id, user_id, user_id, user_id))
    
    return render_template('user_stats.html', 
                           genre_data=genre_data, 
                           activity_data=activity_data, 
                           rating_data=rating_data,
                           counts=counts)

@extra_bp.route('/random-picker')
def random_picker():
    category = request.args.get('category', 'anime')
    
    if category == 'anime':
        item = fetch_one("SELECT * FROM anime ORDER BY RAND() LIMIT 1")
    elif category == 'videogame':
        item = fetch_one("SELECT * FROM videogame ORDER BY RAND() LIMIT 1")
    elif category == 'waifu':
        item = fetch_one("SELECT * FROM waifu ORDER BY RAND() LIMIT 1")
    else:
        item = None
        
    return render_template('random_picker.html', item=item, category=category)

@extra_bp.route('/compare')
def compare():
    item_type = request.args.get('type', 'anime')
    
    if item_type == 'anime':
        items = fetch_all("SELECT * FROM anime ORDER BY RAND() LIMIT 2")
    else:
        items = fetch_all("SELECT * FROM videogame ORDER BY RAND() LIMIT 2")
        
    if len(items) < 2:
        flash("Pas assez d'éléments pour comparer.")
        return redirect(url_for('main.index'))
        
    return render_template('compare.html', item1=items[0], item2=items[1], item_type=item_type)

@extra_bp.route('/compare/vote', methods=['POST'])
def compare_vote():
    item_type = request.form.get('item_type')
    winner_id = request.form.get('winner_id')
    loser_id = request.form.get('loser_id')
    user_id = session.get('user_id')
    
    if winner_id and loser_id and item_type:
        execute_query(
            "INSERT INTO comparison_vote (item_type, winner_id, loser_id, user_id) VALUES (%s, %s, %s, %s)",
            (item_type, winner_id, loser_id, user_id)
        )
        flash("Vote enregistré !")
    
    return redirect(url_for('extra.compare', type=item_type))

@extra_bp.route('/roulette-russe')
def roulette_russe():
    user_id = session.get('user_id')
    if user_id:
        # Pick an anime the user hasn't rated yet
        item = fetch_one("""
            SELECT a.* FROM anime a 
            LEFT JOIN review r ON a.id = r.anime_id AND r.user_id = %s 
            WHERE r.id IS NULL 
            ORDER BY RAND() LIMIT 1
        """, (user_id,))
    else:
        item = fetch_one("SELECT * FROM anime ORDER BY RAND() LIMIT 1")
    
    if not item:
        flash("Plus d'anime à découvrir !")
        return redirect(url_for('main.index'))
        
    return render_template('roulette_russe.html', item=item)

@extra_bp.route('/dice-roll')
def dice_roll():
    genres = fetch_all("SELECT DISTINCT genre FROM anime WHERE genre IS NOT NULL AND genre != ''")
    if not genres:
        flash("Aucun genre trouvé.")
        return redirect(url_for('main.index'))
    
    selected_genre = random.choice(genres)['genre']
    animes = fetch_all("SELECT * FROM anime WHERE genre = %s ORDER BY RAND() LIMIT 5", (selected_genre,))
    
    return render_template('dice_roll.html', genre=selected_genre, animes=animes)

@extra_bp.route('/intruder')
def intruder():
    # 1. Pick a main genre
    all_genres = fetch_all("SELECT genre, COUNT(*) as count FROM anime GROUP BY genre HAVING count >= 3")
    if len(all_genres) < 2:
        flash("Pas assez de genres différents pour ce jeu.")
        return redirect(url_for('main.index'))
    
    main_genre_obj = random.choice(all_genres)
    main_genre = main_genre_obj['genre']
    
    # 2. Pick 3 animes from main genre
    animes = fetch_all("SELECT * FROM anime WHERE genre = %s ORDER BY RAND() LIMIT 3", (main_genre,))
    
    # 3. Pick 1 anime from another genre
    intruder_anime = fetch_one("SELECT * FROM anime WHERE genre != %s ORDER BY RAND() LIMIT 1", (main_genre,))
    
    if not intruder_anime or len(animes) < 3:
        flash("Pas assez de données pour générer une question.")
        return redirect(url_for('main.index'))
        
    choices = animes + [intruder_anime]
    random.shuffle(choices)
    
    return render_template('intruder.html', choices=choices, intruder_id=intruder_anime['id'], main_genre=main_genre)

@extra_bp.route('/blind-test')
def blind_test():
    # Pick an anime that has an opening_url
    anime = fetch_one("SELECT * FROM anime WHERE opening_url IS NOT NULL AND opening_url != '' ORDER BY RAND() LIMIT 1")
    
    if not anime:
        flash("Aucun anime avec opening trouvé. Ajoutez-en un !")
        return redirect(url_for('main.index'))
    
    # Other choices for the multiple choice question
    other_choices = fetch_all("SELECT id, title FROM anime WHERE id != %s ORDER BY RAND() LIMIT 3", (anime['id'],))
    
    choices = [{'id': anime['id'], 'title': anime['title']}] + [{'id': c['id'], 'title': c['title']} for c in other_choices]
    random.shuffle(choices)
    
    # Extract YouTube ID for embedding
    yt_id = ""
    if "v=" in anime['opening_url']:
        yt_id = anime['opening_url'].split("v=")[1].split("&")[0]
    elif "youtu.be/" in anime['opening_url']:
        yt_id = anime['opening_url'].split("youtu.be/")[1].split("?")[0]
        
    return render_template('blind_test.html', anime=anime, choices=choices, yt_id=yt_id)

@extra_bp.route('/quiz')
def quiz():
    # Simple quiz: "In what year was [Anime] released?" or "What is the genre of [Anime]?"
    anime = fetch_one("SELECT * FROM anime ORDER BY RAND() LIMIT 1")
    
    if not anime:
        flash("Aucun anime trouvé.")
        return redirect(url_for('main.index'))
    
    quiz_type = random.choice(['year', 'genre'])
    
    if quiz_type == 'year':
        question = f"En quelle année est sorti '{anime['title']}' ?"
        correct_answer = str(anime['year'])
        # Generate some fake years
        wrong_answers = set()
        while len(wrong_answers) < 3:
            y = anime['year'] + random.randint(-5, 5)
            if y != anime['year']:
                wrong_answers.add(str(y))
    else:
        question = f"Quel est le genre de '{anime['title']}' ?"
        correct_answer = anime['genre']
        # Get some other genres
        other_genres = fetch_all("SELECT DISTINCT genre FROM anime WHERE genre != %s AND genre != '' LIMIT 10", (correct_answer,))
        wrong_answers = random.sample([g['genre'] for g in other_genres], min(3, len(other_genres)))
        
    choices = [correct_answer] + list(wrong_answers)
    random.shuffle(choices)
    
    return render_template('quiz.html', question=question, choices=choices, correct_answer=correct_answer, anime=anime)

@extra_bp.route('/ship-generator')
def ship_generator():
    # Pick two random characters
    waifus = fetch_all("SELECT * FROM waifu ORDER BY RAND() LIMIT 2")
    
    if len(waifus) < 2:
        flash("Pas assez de personnages pour un ship !")
        return redirect(url_for('main.index'))
    
    # Optional: generate a ship name
    name1 = waifus[0]['name']
    name2 = waifus[1]['name']
    ship_name = name1[:len(name1)//2] + name2[len(name2)//2:]
    
    return render_template('ship_generator.html', ship1=waifus[0], ship2=waifus[1], ship_name=ship_name)

@extra_bp.route('/guess-rating')
def guess_rating():
    # Pick an anime with reviews
    anime = fetch_one("""
        SELECT a.*, AVG(r.rating) as true_rating 
        FROM anime a 
        JOIN review r ON a.id = r.anime_id 
        GROUP BY a.id 
        ORDER BY RAND() LIMIT 1
    """)
    
    if not anime:
        flash("Pas assez d'avis pour ce jeu !")
        return redirect(url_for('main.index'))
        
    return render_template('guess_rating.html', anime=anime, true_rating=round(anime['true_rating'], 1))

@extra_bp.route('/otaku-age')
@login_required
def otaku_age():
    user_id = session['user_id']
    
    stats = fetch_one("""
        SELECT 
            (SELECT COUNT(*) FROM anime WHERE added_by = %s) as animes,
            (SELECT COUNT(*) FROM review WHERE user_id = %s) as reviews,
            (SELECT COUNT(*) FROM user_collection WHERE user_id = %s) as collection
        FROM DUAL
    """, (user_id, user_id, user_id))
    
    score = stats['animes'] * 5 + stats['reviews'] * 10 + stats['collection'] * 2
    
    level = "Novice"
    if score > 500: level = "Dieu de l'Anime"
    elif score > 200: level = "Vétéran"
    elif score > 100: level = "Otaku Confirmé"
    elif score > 50: level = "Amateur"
    
    return render_template('otaku_age.html', stats=stats, score=score, level=level)

@extra_bp.route('/gacha')
@login_required
def gacha():
    user_id = session['user_id']
    user = fetch_one("SELECT points, gacha_pity FROM user WHERE id = %s", (user_id,))
    
    # Fetch daily quests
    today = date.today()
    quests = fetch_all("SELECT * FROM user_quest WHERE user_id = %s AND DATE(created_at) = %s", (user_id, today))
    if not quests:
        # Create default quests
        execute_query("INSERT INTO user_quest (user_id, quest_type, progress, target, completed, created_at) VALUES (%s, 'gacha_rolls', 0, 5, False, %s)", (user_id, today))
        quests = fetch_all("SELECT * FROM user_quest WHERE user_id = %s AND created_at = %s", (user_id, today))
    
    return render_template('gacha.html', points=user['points'] if user else 0, pity=user['gacha_pity'] if user else 0, quests=quests)

@extra_bp.route('/gacha/roll', methods=['POST'])
@login_required
def gacha_roll():
    user_id = session['user_id']
    banner = request.form.get('banner', 'standard')
    amount = int(request.form.get('amount', 1))
    
    user = fetch_one("SELECT points, gacha_pity FROM user WHERE id = %s", (user_id,))
    
    roll_cost = 10 * amount
    if not user or user['points'] < roll_cost:
        flash("Pas assez de points !")
        return redirect(url_for('extra.gacha'))
    
    pity = user.get('gacha_pity', 0)
    waifus = []
    
    for _ in range(amount):
        pity += 1
        # Rarity logic
        if pity >= 50:
            rarity_filter = "rarity = 'Légendaire'"
            pity = 0 # reset
        else:
            roll = random.random()
            if roll < 0.05: # 5% Legendaire
                rarity_filter = "rarity = 'Légendaire'"
                pity = 0
            elif roll < 0.20: # 15% Epique
                rarity_filter = "rarity = 'Épique'"
            elif roll < 0.50: # 30% Rare
                rarity_filter = "rarity = 'Rare'"
            else: # 50% Commune
                rarity_filter = "rarity = 'Commune'"
                
        # Banner logic
        if banner == 'shonen':
            # Try to get a shonen waifu
            waifu = fetch_one(f"SELECT w.* FROM waifu w JOIN anime a ON w.anime_id = a.id WHERE (a.genre LIKE '%%Shonen%%' OR a.genre LIKE '%%Shōnen%%') AND w.{rarity_filter} ORDER BY RAND() LIMIT 1")
            if not waifu:
                waifu = fetch_one(f"SELECT * FROM waifu WHERE {rarity_filter} ORDER BY RAND() LIMIT 1")
        else:
            waifu = fetch_one(f"SELECT * FROM waifu WHERE {rarity_filter} ORDER BY RAND() LIMIT 1")
            
        # Fallback if no waifu in that rarity
        if not waifu:
            waifu = fetch_one("SELECT * FROM waifu ORDER BY RAND() LIMIT 1")
        
        if waifu:
            waifus.append(waifu)
            # Add to collection
            execute_query("""
                INSERT INTO user_collection (user_id, waifu_id, quantity) 
                VALUES (%s, %s, 1) 
                ON DUPLICATE KEY UPDATE quantity = quantity + 1
            """, (user_id, waifu['id']))
            
    if not waifus:
        flash("Aucun personnage disponible dans le gacha.")
        return redirect(url_for('extra.gacha'))
    
    # Deduct points and update pity
    execute_query("UPDATE user SET points = points - %s, gacha_pity = %s WHERE id = %s", (roll_cost, pity, user_id))
    
    # Update Quests
    update_quest_progress(user_id, 'gacha_rolls', amount)
    
    return render_template('gacha_result.html', waifus=waifus)

def update_quest_progress(user_id, quest_type, amount):
    today = date.today()
    quest = fetch_one("SELECT * FROM user_quest WHERE user_id = %s AND quest_type = %s AND created_at = %s", (user_id, quest_type, today))
    if quest:
        if not quest['completed']:
            new_progress = min(quest['progress'] + amount, quest['target'])
            completed = new_progress >= quest['target']
            execute_query("UPDATE user_quest SET progress = %s, completed = %s WHERE id = %s", (new_progress, completed, quest['id']))
            if completed:
                execute_query("UPDATE user SET points = points + 20 WHERE id = %s", (user_id,))
    else:
        target = 5 if quest_type == 'gacha_rolls' else 10
        completed = amount >= target
        execute_query("INSERT INTO user_quest (user_id, quest_type, progress, target, completed, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
                      (user_id, quest_type, amount, target, completed, today))
        if completed:
            execute_query("UPDATE user SET points = points + 20 WHERE id = %s", (user_id,))

@extra_bp.route('/gacha/exchange', methods=['POST'])
@login_required
def gacha_exchange():
    user_id = session['user_id']
    waifu_id = request.form.get('waifu_id')
    
    item = fetch_one("SELECT quantity FROM user_collection WHERE user_id = %s AND waifu_id = %s", (user_id, waifu_id))
    if item and item['quantity'] > 1:
        # Sell duplicate
        execute_query("UPDATE user_collection SET quantity = quantity - 1 WHERE user_id = %s AND waifu_id = %s", (user_id, waifu_id))
        execute_query("UPDATE user SET points = points + 5 WHERE id = %s", (user_id,))
        flash("Doublon échangé contre 5 points !")
    else:
        flash("Impossible d'échanger cette carte.")
    
    return redirect(url_for('extra.collection'))

@extra_bp.route('/gacha/craft', methods=['POST'])
@login_required
def gacha_craft():
    user_id = session['user_id']
    waifu_id = request.form.get('waifu_id')
    
    item = fetch_one("SELECT c.quantity, w.rarity FROM user_collection c JOIN waifu w ON c.waifu_id = w.id WHERE c.user_id = %s AND c.waifu_id = %s", (user_id, waifu_id))
    if item and item['quantity'] >= 5 and item['rarity'] == 'Commune':
        # Craft a rare card
        execute_query("UPDATE user_collection SET quantity = quantity - 5 WHERE user_id = %s AND waifu_id = %s", (user_id, waifu_id))
        rare_waifu = fetch_one("SELECT id FROM waifu WHERE rarity = 'Rare' ORDER BY RAND() LIMIT 1")
        if rare_waifu:
            execute_query("""
                INSERT INTO user_collection (user_id, waifu_id, quantity) 
                VALUES (%s, %s, 1) 
                ON DUPLICATE KEY UPDATE quantity = quantity + 1
            """, (user_id, rare_waifu['id']))
            flash("Fusion réussie ! Vous avez obtenu une carte Rare.")
        else:
            execute_query("UPDATE user SET points = points + 50 WHERE id = %s", (user_id,))
            flash("Pas de carte Rare disponible. 50 points obtenus.")
    else:
        flash("Il faut 5 exemplaires d'une carte Commune pour fusionner.")
    
    return redirect(url_for('extra.collection'))

@extra_bp.route('/collection')
@login_required
def collection():
    user_id = session['user_id']
    items = fetch_all("""
        SELECT c.*, w.name, w.image_url, w.rarity 
        FROM user_collection c 
        JOIN waifu w ON c.waifu_id = w.id 
        WHERE c.user_id = %s
    """, (user_id,))
    
    return render_template('collection.html', items=items)

@extra_bp.route('/tier-lists')
def tier_lists():
    lists = fetch_all("""
        SELECT t.*, u.username 
        FROM tier_list t 
        JOIN user u ON t.user_id = u.id 
        WHERE t.is_public = 1 
        ORDER BY t.created_at DESC
    """)
    return render_template('tier_lists.html', lists=lists)

@extra_bp.route('/tier-list/create', methods=['GET', 'POST'])
@login_required
def create_tier_list():
    if request.method == 'POST':
        title = request.form['title']
        category = request.form['category']
        user_id = session['user_id']
        
        execute_query("INSERT INTO tier_list (user_id, title, category) VALUES (%s, %s, %s)", (user_id, title, category))
        list_id = fetch_one("SELECT LAST_INSERT_ID() as id")['id']
        
        # Add items
        items = fetch_all(f"SELECT id FROM {category} ORDER BY RAND() LIMIT 20")
        for item in items:
            execute_query("INSERT INTO tier_list_item (tier_list_id, item_id, tier) VALUES (%s, %s, 'B')", (list_id, item['id']))
            
        return redirect(url_for('extra.view_tier_list', id=list_id))
        
    return render_template('create_tier_list.html')

@extra_bp.route('/tier-list/<int:id>')
def view_tier_list(id):
    t_list = fetch_one("SELECT t.*, u.username FROM tier_list t JOIN user u ON t.user_id = u.id WHERE t.id = %s", (id,))
    if not t_list:
        flash("Tier list non trouvée")
        return redirect(url_for('extra.tier_lists'))
        
    items = fetch_all("""
        SELECT ti.*, 
               CASE 
                   WHEN %s = 'anime' THEN a.title
                   WHEN %s = 'videogame' THEN v.title
                   WHEN %s = 'waifu' THEN w.name
               END as name,
               CASE 
                   WHEN %s = 'anime' THEN a.cover_url
                   WHEN %s = 'videogame' THEN v.cover_url
                   WHEN %s = 'waifu' THEN w.image_url
               END as image_url
        FROM tier_list_item ti
        LEFT JOIN anime a ON ti.item_id = a.id AND %s = 'anime'
        LEFT JOIN videogame v ON ti.item_id = v.id AND %s = 'videogame'
        LEFT JOIN waifu w ON ti.item_id = w.id AND %s = 'waifu'
        WHERE ti.tier_list_id = %s
    """, (t_list['category'], t_list['category'], t_list['category'], 
          t_list['category'], t_list['category'], t_list['category'],
          t_list['category'], t_list['category'], t_list['category'], id))
    
    return render_template('view_tier_list.html', t_list=t_list, items=items)

@extra_bp.route('/tier-list/update-item', methods=['POST'])
@login_required
def update_tier_item():
    item_id = request.form.get('id')
    tier = request.form.get('tier')
    execute_query("UPDATE tier_list_item SET tier = %s WHERE id = %s", (tier, item_id))
    return {"status": "ok"}

@extra_bp.route('/battles')
def battle_list():
    battles = fetch_all("SELECT * FROM battle_royale ORDER BY created_at DESC")
    return render_template('battle_list.html', battles=battles)

@extra_bp.route('/battle/create', methods=['GET', 'POST'], endpoint='create_battle')
@login_required
def create_battle():
    if request.method == 'POST':
        title = request.form['title']
        
        try:
            # Pick 2 random waifus as participants
            waifus = fetch_all("SELECT id FROM waifu ORDER BY RAND() LIMIT 2")
            
            if len(waifus) < 2:
                flash("Pas assez de personnages pour créer une battle !")
                return redirect(url_for('extra.battle_list'))

            # Create the battle
            battle_id = execute_query("INSERT INTO battle_royale (title, status) VALUES (%s, 'active')", (title,))
            
            if not battle_id:
                # Fallback in case lastrowid failed (should not happen with updated execute_query)
                res = fetch_one("SELECT LAST_INSERT_ID() as id")
                battle_id = res['id'] if res else None

            if not battle_id:
                flash("Erreur lors de la récupération de l'ID de la battle.")
                return redirect(url_for('extra.battle_list'))

            for waifu in waifus:
                execute_query("INSERT INTO battle_participant (battle_id, waifu_id, votes) VALUES (%s, %s, 0)", (battle_id, waifu['id']))
                
            flash(f"Battle Royale '{title}' créée avec succès !")
            return redirect(url_for('extra.battle_list'))
            
        except Exception as e:
            flash(f"Une erreur est survenue : {str(e)}")
            return redirect(url_for('extra.battle_list'))
        
    return render_template('create_battle.html')

@extra_bp.route('/battle/<int:id>')
def view_battle(id):
    battle = fetch_one("SELECT * FROM battle_royale WHERE id = %s", (id,))
    participants = fetch_all("""
        SELECT bp.*, w.name, w.image_url 
        FROM battle_participant bp 
        JOIN waifu w ON bp.waifu_id = w.id 
        WHERE bp.battle_id = %s
    """, (id,))
    return render_template('view_battle.html', battle=battle, participants=participants)

@extra_bp.route('/battle/vote/<int:participant_id>', methods=['POST'])
def battle_vote(participant_id):
    execute_query("UPDATE battle_participant SET votes = votes + 1 WHERE id = %s", (participant_id,))
    battle_id = request.form.get('battle_id')
    flash("Vote enregistré !")
    return redirect(url_for('extra.view_battle', id=battle_id))


