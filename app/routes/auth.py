from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from app.database import fetch_one, execute_query
from app.models import get_user_table_info
from app.utils import generate_reset_code
from app.decorators import login_required
from app.services import send_reset_email, dump_and_send_to_discord
import time
from datetime import date, timedelta

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
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
            return redirect(url_for('auth.register'))
        
        if fetch_one(f"SELECT id FROM {tbl} WHERE email = %s", (email,)):
            flash('Email déjà utilisé')
            return redirect(url_for('auth.register'))
        
        # Créer l'utilisateur
        password_hash = generate_password_hash(password)
        execute_query(
            f"INSERT INTO {tbl} (username, email, {pwdcol}) VALUES (%s, %s, %s)",
            (username, email, password_hash)
        )
        
        flash('Inscription réussie')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        info = get_user_table_info()
        tbl = info['table']
        pwdcol = info['password_col']

        # Récupérer l'utilisateur
        user = fetch_one(f"SELECT *, {pwdcol} AS password_hash FROM {tbl} WHERE username = %s", (username,))
        
        if user and check_password_hash(user.get('password_hash', ''), password):
            session['user_id'] = user['id']
            session['dump_done'] = False
            
            # Daily Login Logic
            today = date.today()
            last_login = user.get('last_login_date')
            streak = user.get('login_streak') or 0
            
            if last_login != today:
                if last_login == today - timedelta(days=1):
                    streak += 1
                else:
                    streak = 1
                
                # Reward: base 50 points + 10 points per streak day (max 100 bonus)
                bonus = min(streak * 10, 100)
                reward = 50 + bonus
                
                execute_query(
                    f"UPDATE {tbl} SET last_login_date = %s, login_streak = %s, points = points + %s WHERE id = %s",
                    (today, streak, reward, user['id'])
                )
                flash(f'Connexion réussie ! Bonus de connexion quotidienne : +{reward} points (Série: {streak} jours)')
            else:
                flash('Connexion réussie')
            
            return redirect(url_for('main.index'))
        else:
            flash('Identifiants incorrects')
    
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    # Déclenchement du dump lors de la déconnexion volontaire
    dump_and_send_to_discord()
    session.pop('user_id', None)
    flash('Déconnexion réussie')
    return redirect(url_for('main.index'))

@auth_bp.route('/exit_signal', methods=['POST'])
def exit_signal():
    # Déclenchement du dump quand l'utilisateur quitte l'onglet/la page
    # On ne le fait que si l'utilisateur est connecté pour éviter le spam par des visiteurs anonymes
    if 'user_id' in session:
        dump_and_send_to_discord()
    return '', 204

@auth_bp.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash("Veuillez fournir votre adresse email.")
            return redirect(url_for('auth.reset_password_request'))

        info = get_user_table_info()
        tbl = info['table']
        user = fetch_one(f"SELECT id, username, email FROM {tbl} WHERE email = %s", (email,))
        if user:
            code = generate_reset_code()
            session['reset_code'] = code
            session['reset_code_time'] = time.time()
            session['reset_user_id'] = user['id']
            send_reset_email(user['email'], code, user.get('username') or '')
        
        flash("Si un compte existe pour cet email, un code de réinitialisation a été envoyé.")
        return redirect(url_for('auth.reset_password'))
    return render_template('password_reset_request.html')

@auth_bp.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        password = request.form.get('password', '').strip()
        password2 = request.form.get('password2', '').strip()
        
        stored_code = session.get('reset_code')
        stored_time = session.get('reset_code_time')
        user_id = session.get('reset_user_id')
        
        if not stored_code or not stored_time or not user_id:
            flash("Délai expiré. Veuillez refaire une demande de réinitialisation.")
            return redirect(url_for('auth.reset_password_request'))
        
        if time.time() - stored_time > 600:
            session.pop('reset_code', None)
            session.pop('reset_code_time', None)
            session.pop('reset_user_id', None)
            flash("Le code a expiré (10 minutes). Veuillez refaire une demande.")
            return redirect(url_for('auth.reset_password_request'))
        
        if code != stored_code:
            flash("Code incorrect.")
            return redirect(url_for('auth.reset_password'))
        
        if not password or password != password2:
            flash("Les mots de passe doivent être identiques et non vides.")
            return redirect(url_for('auth.reset_password'))

        password_hash = generate_password_hash(password)
        info = get_user_table_info()
        tbl = info['table']
        pwdcol = info['password_col']
        execute_query(f"UPDATE {tbl} SET {pwdcol} = %s WHERE id = %s", (password_hash, user_id))
        
        session.pop('reset_code', None)
        session.pop('reset_code_time', None)
        session.pop('reset_user_id', None)
        
        flash("Mot de passe réinitialisé avec succès. Vous pouvez maintenant vous connecter.")
        return redirect(url_for('auth.login'))

    return render_template('password_reset.html')
