from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.database import fetch_all, fetch_one, execute_query
from app.decorators import login_required

poll_bp = Blueprint('poll', __name__)

@poll_bp.route('/polls')
def list_polls():
    polls = fetch_all("""
        SELECT p.*, u.username as creator 
        FROM poll p 
        LEFT JOIN user u ON p.created_by = u.id 
        ORDER BY p.created_at DESC
    """)
    return render_template('poll_list.html', polls=polls)

@poll_bp.route('/polls/create', methods=['GET', 'POST'])
@login_required
def create_poll():
    if request.method == 'POST':
        question = request.form.get('question')
        options = request.form.getlist('options')
        options = [o.strip() for o in options if o.strip()]
        
        if not question or len(options) < 2:
            flash("La question et au moins 2 options sont requises.")
            return render_template('create_poll.html')
            
        # Insert poll
        execute_query(
            "INSERT INTO poll (question, created_by) VALUES (%s, %s)",
            (question, session['user_id'])
        )
        
        # Get last inserted id (this is a bit tricky with raw pymysql without cursor.lastrowid)
        # We can use fetch_one after insert or modify execute_query to return it.
        # For simplicity in this project, we'll fetch the latest poll by the user.
        poll = fetch_one("SELECT id FROM poll WHERE created_by = %s ORDER BY id DESC LIMIT 1", (session['user_id'],))
        poll_id = poll['id']
        
        for option_text in options:
            execute_query(
                "INSERT INTO poll_option (poll_id, option_text) VALUES (%s, %s)",
                (poll_id, option_text)
            )
            
        flash("Sondage créé !")
        return redirect(url_for('poll.list_polls'))
        
    return render_template('create_poll.html')

@poll_bp.route('/polls/<int:poll_id>')
def poll_detail(poll_id):
    poll = fetch_one("SELECT p.*, u.username as creator FROM poll p LEFT JOIN user u ON p.created_by = u.id WHERE p.id = %s", (poll_id,))
    if not poll:
        flash("Sondage non trouvé.")
        return redirect(url_for('poll.list_polls'))
        
    options = fetch_all("""
        SELECT po.*, COUNT(pv.id) as vote_count 
        FROM poll_option po 
        LEFT JOIN poll_vote pv ON po.id = pv.option_id 
        WHERE po.poll_id = %s 
        GROUP BY po.id
    """, (poll_id,))
    
    user_vote = None
    if 'user_id' in session:
        user_vote = fetch_one("SELECT * FROM poll_vote WHERE poll_id = %s AND user_id = %s", (poll_id, session['user_id']))
        
    total_votes = sum(o['vote_count'] for o in options)
    
    return render_template('poll_detail.html', poll=poll, options=options, user_vote=user_vote, total_votes=total_votes)

@poll_bp.route('/polls/<int:poll_id>/vote', methods=['POST'])
@login_required
def poll_vote(poll_id):
    option_id = request.form.get('option_id')
    user_id = session['user_id']
    
    if not option_id:
        flash("Veuillez choisir une option.")
        return redirect(url_for('poll.poll_detail', poll_id=poll_id))
        
    try:
        execute_query(
            "INSERT INTO poll_vote (poll_id, option_id, user_id) VALUES (%s, %s, %s)",
            (poll_id, option_id, user_id)
        )
        flash("Votre vote a été pris en compte !")
    except Exception:
        flash("Vous avez déjà voté pour ce sondage.")
        
    return redirect(url_for('poll.poll_detail', poll_id=poll_id))
