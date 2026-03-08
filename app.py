from app import create_app
import os
from app.database import get_connection, ensure_tables
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = create_app()

if __name__ == '__main__':
    # Hôte/port et mode debug contrôlés par des variables d'environnement
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', '5000'))
    debug = os.getenv('FLASK_DEBUG', '1') == '1'

    try:
        # Tester la connexion à la base de données avant démarrage
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
        logger.info("✅ Connexion à la base de données réussie.")
    except Exception as e:
        logger.error("❌ Erreur de connexion à MySQL: %s", e)
        # On ne quitte pas forcément car l'app peut avoir des fallbacks

    # Assurer la présence des tables requises
    ensure_tables()
    logger.info("✅ Structure de la base de données vérifiée.")

    # Démarrer l'app (pour dev local)
    app.run(host=host, port=port, debug=debug)
