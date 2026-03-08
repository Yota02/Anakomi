import datetime
import requests
import os
import smtplib
import logging
from flask import url_for, current_app
from email.message import EmailMessage
from app.database import get_connection

logger = logging.getLogger(__name__)

def dump_and_send_to_discord():
    """Crée un dump SQL de la base de données et l'envoie à Discord."""
    webhook_url = os.getenv('DISCORD_WEBHOOK_URL', "https://discord.com/api/webhooks/1480201131266281641/YO_1yQ4lMXcCGW9zCS7R82bAsyKF7X5_Wj7ZfFeRKwVU80bBNA7lvoSj9or-vp1TE2Ub")
    
    tables = [
        'user', 'anime', 'review', 'user_top10', 
        'videogame', 'videogame_review', 'user_videogame_top10', 
        'waifu', 'waifu_review', 'user_waifu_top5'
    ]
    
    dump_content = f"-- Anakomi Database Dump\n-- Generated on: {datetime.datetime.now()}\n\n"
    dump_content += "SET FOREIGN_KEY_CHECKS = 0;\n\n"
    
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                for table in tables:
                    # Vérifier si la table existe avant de dumper
                    cursor.execute(f"SHOW TABLES LIKE '{table}'")
                    if not cursor.fetchone():
                        continue
                        
                    dump_content += f"-- Table: {table}\n"
                    
                    # CREATE TABLE statement
                    cursor.execute(f"SHOW CREATE TABLE `{table}`")
                    create_sql_res = cursor.fetchone()
                    create_sql = create_sql_res['Create Table'] if isinstance(create_sql_res, dict) else create_sql_res[1]
                    dump_content += create_sql + ";\n\n"
                    
                    # INSERT statements
                    cursor.execute(f"SELECT * FROM `{table}`")
                    rows = cursor.fetchall()
                    if rows:
                        for row in rows:
                            cols = ", ".join([f"`{c}`" for c in row.keys()])
                            vals = []
                            for v in row.values():
                                if v is None:
                                    vals.append("NULL")
                                elif isinstance(v, (int, float)):
                                    vals.append(str(v))
                                elif isinstance(v, (datetime.datetime, datetime.date)):
                                    vals.append(f"'{v}'")
                                else:
                                    escaped = str(v).replace("'", "''")
                                    vals.append(f"'{escaped}'")
                            
                            vals_str = ", ".join(vals)
                            dump_content += f"INSERT INTO `{table}` ({cols}) VALUES ({vals_str});\n"
                        dump_content += "\n"
        
        dump_content += "SET FOREIGN_KEY_CHECKS = 1;\n"
        
        filename = f"anakomi_dump_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
        files = {'file': (filename, dump_content, 'text/plain')}
        requests.post(webhook_url, files=files, timeout=15)
            
    except Exception as e:
        logger.error(f"Erreur dump/discord: {e}")

def send_reset_email(to_email, token, username):
    host = os.getenv('SMTP_HOST')
    port = int(os.getenv('SMTP_PORT', '587')) if os.getenv('SMTP_PORT') else None
    user = os.getenv('SMTP_USER')
    password = os.getenv('SMTP_PASSWORD')
    mail_from = os.getenv('MAIL_FROM', 'no-reply@anakomi.local')

    reset_url = url_for('auth.reset_password', token=token, _external=True)
    subject = "Réinitialisation de votre mot de passe - Anakomi"
    body = f"Bonjour {username},\n\nPour réinitialiser votre mot de passe, cliquez sur le lien suivant (valide 1h) :\n\n{reset_url}\n\nSi vous n'avez pas demandé ce reset, ignorez ce message.\n\n— L'équipe Anakomi"

    if host and user and password and port:
        try:
            msg = EmailMessage()
            msg['Subject'] = subject
            msg['From'] = mail_from
            msg['To'] = to_email
            msg.set_content(body)

            with smtplib.SMTP(host, port, timeout=10) as smtp:
                smtp.starttls()
                smtp.login(user, password)
                smtp.send_message(msg)
            return True
        except Exception as e:
            logger.error(f"Échec envoi email reset: {e}")
    
    logger.info(f"Lien de réinitialisation (dev/console) pour {to_email} : {reset_url}")
    return False
