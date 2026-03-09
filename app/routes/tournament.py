from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.database import fetch_all, fetch_one, execute_query
from app.decorators import login_required
import uuid
import random
import string

tournament_bp = Blueprint('tournament', __name__)

def generate_share_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

@tournament_bp.route('/tournaments')
def list_tournaments():
    tournaments = fetch_all("""
        SELECT t.*, u.username as creator, COUNT(tp.id) as participant_count
        FROM tournament t
        LEFT JOIN user u ON t.created_by = u.id
        LEFT JOIN tournament_participant tp ON t.id = tp.tournament_id
        GROUP BY t.id
        ORDER BY t.created_at DESC
    """)
    return render_template('tournament_list.html', tournaments=tournaments)

@tournament_bp.route('/tournament/create', methods=['GET', 'POST'])
@login_required
def create_tournament():
    if request.method == 'POST':
        title = request.form.get('title')
        item_type = request.form.get('item_type')
        tournament_type = request.form.get('tournament_type', 'bracket')
        selected_items = request.form.getlist('items')
        
        num_items = len(selected_items)
        # Validate power of 2 for bracket, or 4/8/16/32 for poules
        if num_items not in [4, 8, 16, 32]:
            flash("Veuillez sélectionner 4, 8, 16 ou 32 participants.")
            return redirect(url_for('tournament.create_tournament'))
            
        share_code = generate_share_code()
        
        # Create tournament
        execute_query(
            "INSERT INTO tournament (title, item_type, tournament_type, share_code, created_by) VALUES (%s, %s, %s, %s, %s)",
            (title, item_type, tournament_type, share_code, session['user_id'])
        )
        
        tournament = fetch_one("SELECT id FROM tournament WHERE share_code = %s", (share_code,))
        tournament_id = tournament['id']
        
        # Add participants
        participant_ids = []
        random.shuffle(selected_items) # Shuffle for random seeding
        for i, item_id in enumerate(selected_items):
            group_id = None
            if tournament_type == 'poule':
                group_id = chr(65 + (i // 4)) # A, B, C, D
            
            execute_query(
                "INSERT INTO tournament_participant (tournament_id, item_id, initial_position, group_id) VALUES (%s, %s, %s, %s)",
                (tournament_id, item_id, i, group_id)
            )
            p = fetch_one("SELECT id FROM tournament_participant WHERE tournament_id = %s AND item_id = %s", (tournament_id, item_id))
            participant_ids.append(p['id'])
            
        if tournament_type == 'bracket':
            # Initialize first round (Round 1)
            num_matches = num_items // 2
            for m in range(num_matches):
                execute_query(
                    "INSERT INTO tournament_match (tournament_id, round_number, match_number, participant1_id, participant2_id) VALUES (%s, %s, %s, %s, %s)",
                    (tournament_id, 1, m + 1, participant_ids[m*2], participant_ids[m*2 + 1])
                )
        else:
            # Initialize Group Stage (Round 0)
            # 4 participants per group. Groups: A, B, C...
            # Matches in group: (0,1), (2,3), (0,2), (1,3), (0,3), (1,2)
            num_groups = num_items // 4
            for g in range(num_groups):
                g_pids = participant_ids[g*4 : (g+1)*4]
                pairs = [(0,1), (2,3), (0,2), (1,3), (0,3), (1,2)]
                for idx, (p1_idx, p2_idx) in enumerate(pairs):
                    execute_query(
                        "INSERT INTO tournament_match (tournament_id, round_number, match_number, participant1_id, participant2_id) VALUES (%s, %s, %s, %s, %s)",
                        (tournament_id, 0, (g * 10) + idx + 1, g_pids[p1_idx], g_pids[p2_idx])
                    )
            
        flash(f"Tournoi créé avec {num_items} participants !")
        return redirect(url_for('tournament.view_tournament', code=share_code))
        
    animes = fetch_all("SELECT id, title as name FROM anime ORDER BY title")
    videogames = fetch_all("SELECT id, title as name FROM videogame ORDER BY title")
    waifus = fetch_all("SELECT id, name FROM waifu ORDER BY name")
    
    return render_template('create_tournament.html', animes=animes, videogames=videogames, waifus=waifus)

@tournament_bp.route('/tournament/<code>')
def view_tournament(code):
    tournament = fetch_one("""
        SELECT t.*, u.username as creator 
        FROM tournament t 
        LEFT JOIN user u ON t.created_by = u.id 
        WHERE t.share_code = %s
    """, (code,))
    
    if not tournament:
        flash("Tournoi non trouvé.")
        return redirect(url_for('tournament.list_tournaments'))
        
    # Get total number of participants to calculate total rounds
    p_count = fetch_one("SELECT COUNT(*) as count FROM tournament_participant WHERE tournament_id = %s", (tournament['id'],))['count']
    import math
    total_rounds = int(math.log2(p_count))

    # Fetch matches
    matches = fetch_all("""
        SELECT tm.*, 
               p1.id as p1_id, p1.item_id as p1_item_id,
               p2.id as p2_id, p2.item_id as p2_item_id,
               w.id as winner_id,
               (SELECT COUNT(*) FROM tournament_vote tv WHERE tv.match_id = tm.id AND tv.participant_id = tm.participant1_id) as p1_votes,
               (SELECT COUNT(*) FROM tournament_vote tv WHERE tv.match_id = tm.id AND tv.participant_id = tm.participant2_id) as p2_votes
        FROM tournament_match tm
        LEFT JOIN tournament_participant p1 ON tm.participant1_id = p1.id
        LEFT JOIN tournament_participant p2 ON tm.participant2_id = p2.id
        LEFT JOIN tournament_participant w ON tm.winner_id = w.id
        WHERE tm.tournament_id = %s
        ORDER BY tm.round_number, tm.match_number
    """, (tournament['id'],))
    
    for m in matches:
        for p_key in ['p1', 'p2']:
            item_id = m[f'{p_key}_item_id']
            if item_id:
                if tournament['item_type'] == 'anime':
                    item = fetch_one("SELECT title as name, cover_url as image FROM anime WHERE id = %s", (item_id,))
                elif tournament['item_type'] == 'videogame':
                    item = fetch_one("SELECT title as name, cover_url as image FROM videogame WHERE id = %s", (item_id,))
                else:
                    item = fetch_one("SELECT name, image_url as image FROM waifu WHERE id = %s", (item_id,))
                m[f'{p_key}_details'] = item

    session_id = session.get('user_id', request.remote_addr)
    votes = fetch_all("SELECT match_id FROM tournament_vote WHERE session_id = %s", (str(session_id),))
    user_votes = [v['match_id'] for v in votes]

    rounds = {}
    for m in matches:
        r = m['round_number']
        if r not in rounds: rounds[r] = []
        rounds[r].append(m)
        
    group_standings = {}
    if tournament['tournament_type'] == 'poule':
        participants = fetch_all("""
            SELECT tp.*, 
                   (SELECT COUNT(*) FROM tournament_match tm WHERE tm.tournament_id = tp.tournament_id AND tm.winner_id = tp.id AND tm.round_number = 0) as wins
            FROM tournament_participant tp
            WHERE tp.tournament_id = %s
        """, (tournament['id'],))
        
        # Add details (name, image) to participants for standings
        for p in participants:
            item_id = p['item_id']
            if tournament['item_type'] == 'anime':
                item = fetch_one("SELECT title as name, cover_url as image FROM anime WHERE id = %s", (item_id,))
            elif tournament['item_type'] == 'videogame':
                item = fetch_one("SELECT title as name, cover_url as image FROM videogame WHERE id = %s", (item_id,))
            else:
                item = fetch_one("SELECT name, image_url as image FROM waifu WHERE id = %s", (item_id,))
            p['details'] = item

        for p in participants:
            g = p['group_id']
            if g:
                if g not in group_standings: group_standings[g] = []
                group_standings[g].append(p)
        
        for g in group_standings:
            group_standings[g].sort(key=lambda x: x['wins'], reverse=True)

    # Helper for round labels
    def get_round_label(r, total):
        if r == 0: return "Phase de Poules"
        diff = total - r
        if diff == 0: return "Finale"
        if diff == 1: return "Demi-finales"
        if diff == 2: return "Quarts de finale"
        if diff == 3: return "8èmes de finale"
        if diff == 4: return "16èmes de finale"
        return f"Round {r}"

    return render_template('tournament_view.html', 
                           tournament=tournament, 
                           rounds=rounds, 
                           group_standings=group_standings,
                           user_votes=user_votes,
                           total_rounds=total_rounds,
                           get_label=get_round_label)

@tournament_bp.route('/tournament/vote', methods=['POST'])
def tournament_vote():
    match_id = request.form.get('match_id')
    participant_id = request.form.get('participant_id')
    code = request.form.get('code')
    
    session_id = session.get('user_id', request.remote_addr)
    user_id = session.get('user_id')
    
    match = fetch_one("SELECT * FROM tournament_match WHERE id = %s", (match_id,))
    if match and not match['winner_id']:
        try:
            execute_query(
                "INSERT INTO tournament_vote (match_id, participant_id, session_id, user_id) VALUES (%s, %s, %s, %s)",
                (match_id, participant_id, str(session_id), user_id)
            )
            flash("Vote enregistré !")
        except Exception:
            flash("Vous avez déjà voté pour ce match.")
            
    return redirect(url_for('tournament.view_tournament', code=code))

@tournament_bp.route('/tournament/advance/<code>', methods=['POST'])
@login_required
def advance_round(code):
    tournament = fetch_one("SELECT * FROM tournament WHERE share_code = %s", (code,))
    if not tournament or tournament['created_by'] != session['user_id']:
        flash("Action non autorisée.")
        return redirect(url_for('tournament.list_tournaments'))
        
    current_round = int(request.form.get('round'))
    matches = fetch_all("SELECT * FROM tournament_match WHERE tournament_id = %s AND round_number = %s", (tournament['id'], current_round))
    
    # 1. Determine winners for each match in the current round
    for m in matches:
        if not m['winner_id']:
            votes = fetch_all("SELECT participant_id, COUNT(*) as count FROM tournament_vote WHERE match_id = %s GROUP BY participant_id", (m['id'],))
            if not votes:
                # Random winner if no votes
                winner_id = m['participant1_id']
            elif len(votes) == 1:
                winner_id = votes[0]['participant_id']
            else:
                winner_id = votes[0]['participant_id'] if votes[0]['count'] >= votes[1]['count'] else votes[1]['participant_id']
            
            execute_query("UPDATE tournament_match SET winner_id = %s WHERE id = %s", (winner_id, m['id']))
            
    # 2. Create next round matches if applicable
    if current_round == 0:
        # Advancing from Group Stage to Bracket
        participants = fetch_all("""
            SELECT tp.*, 
                   (SELECT COUNT(*) FROM tournament_match tm WHERE tm.tournament_id = tp.tournament_id AND tm.winner_id = tp.id AND tm.round_number = 0) as wins
            FROM tournament_participant tp
            WHERE tp.tournament_id = %s
            ORDER BY tp.group_id, wins DESC
        """, (tournament['id'],))
        
        group_winners = {}
        for p in participants:
            g = p['group_id']
            if g not in group_winners: group_winners[g] = []
            if len(group_winners[g]) < 2:
                group_winners[g].append(p['id'])
        
        # Winners list: [G1_1, G1_2, G2_1, G2_2, ...]
        winners_flat = []
        groups = sorted(group_winners.keys())
        for g in groups:
            winners_flat.extend(group_winners[g])
            
        # Match winners of different groups: G1_1 vs G2_2, G2_1 vs G1_2...
        num_winners = len(winners_flat)
        next_round = 1
        num_matches = num_winners // 2
        
        for i in range(num_matches):
            # Example for 2 groups: G1_1 vs G2_2, G2_1 vs G1_2
            p1 = winners_flat[i*2]
            p2 = winners_flat[(i*2 + 3) % num_winners] if num_winners > 2 else winners_flat[1]
            
            execute_query(
                "INSERT INTO tournament_match (tournament_id, round_number, match_number, participant1_id, participant2_id) VALUES (%s, %s, %s, %s, %s)",
                (tournament['id'], next_round, i + 1, p1, p2)
            )
        flash(f"Phase de poules terminée. Passage à la Phase Finale !")
    else:
        winners = fetch_all("SELECT winner_id FROM tournament_match WHERE tournament_id = %s AND round_number = %s ORDER BY match_number", (tournament['id'], current_round))
        
        if len(winners) >= 2:
            next_round = current_round + 1
            for i in range(0, len(winners), 2):
                if i + 1 < len(winners):
                    execute_query(
                        "INSERT INTO tournament_match (tournament_id, round_number, match_number, participant1_id, participant2_id) VALUES (%s, %s, %s, %s, %s)",
                        (tournament['id'], next_round, (i // 2) + 1, winners[i]['winner_id'], winners[i+1]['winner_id'])
                    )
            flash(f"Round {current_round} terminé. Passage au round {next_round} !")
        else:
            flash("Le tournoi est terminé !")
        
    return redirect(url_for('tournament.view_tournament', code=code))
