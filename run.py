from app import create_app
from app.database import get_connection
import os
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = create_app()

if __name__ == '__main__':
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', '5000'))
    debug = os.getenv('FLASK_DEBUG', '1') == '1'

    try:
        # Tester la connexion à la base de données
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
        logger.info("✅ Connexion à la base de données réussie.")
        
        # S'assurer que les tables existent
        from app.database import ensure_tables
        ensure_tables()
        logger.info("✅ Structure de la base de données vérifiée.")
    except Exception as e:
        logger.error(f"❌ Erreur de connexion à MySQL: {e}")
        # On ne quitte pas forcément, car resolve_user_table a des fallbacks
    
    app.run(host=host, port=port, debug=debug)
