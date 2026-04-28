from flask import Flask
from datetime import datetime, timedelta
import os
import logging
from app.utils import get_current_user

def create_app():
    app = Flask(__name__, 
                template_folder='../templates', 
                static_folder='../static')
    
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'change_me_in_production'
    
    # Sécurité des cookies
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
    app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', '1') == '1'
    
    # Durée de session par défaut
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=int(os.getenv('SESSION_LIFETIME_DAYS', '7')))
    
    # Logging minimal
    logging.basicConfig(level=logging.INFO)
    
    # Register Blueprints
    from app.routes.main import main_bp
    from app.routes.auth import auth_bp
    from app.routes.anime import anime_bp
    from app.routes.videogame import videogame_bp
    from app.routes.waifu import waifu_bp
    from app.routes.extra import extra_bp
    from app.routes.poll import poll_bp
    from app.routes.tournament import tournament_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(anime_bp)
    app.register_blueprint(videogame_bp)
    app.register_blueprint(waifu_bp)
    app.register_blueprint(extra_bp)
    app.register_blueprint(poll_bp)
    app.register_blueprint(tournament_bp)
    
    @app.context_processor
    def inject_globals():
        return dict(current_user=get_current_user(), current_year=datetime.utcnow().year)
    
    from app.database import ensure_tables
    ensure_tables()
    
    return app

app = create_app()
