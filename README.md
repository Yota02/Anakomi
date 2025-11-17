# Rate My Anime - Application Flask

Application web pour noter et commenter des animes avec authentification utilisateur et base de données MySQL.

## Prérequis

1. **Python 3.7+** installé
2. **MySQL Server** installé et démarré
3. **pip** pour installer les dépendances

## Installation

### 1. Installer les dépendances Python
```bash
pip install -r requirements.txt
```

### 2. Configurer MySQL

1. Démarrez MySQL Server
2. Modifiez les paramètres de connexion dans `app.py` :
   ```python
   app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://utilisateur:motdepasse@localhost:3306/rate_my_anime'
   ```
   
3. Créez la base de données :
   ```bash
   python config_db.py
   ```

### 3. Lancer l'application
```bash
python app.py
```

L'application sera accessible sur `http://localhost:5000`

## Fonctionnalités

- ✅ Inscription et connexion utilisateur
- ✅ Ajout d'animes par les utilisateurs connectés
- ✅ Système de notation avec étoiles (1-5)
- ✅ Commentaires sur les animes
- ✅ Calcul de la note moyenne
- ✅ Interface responsive avec Bootstrap

## Configuration MySQL

### Paramètres de connexion par défaut :
- **Host**: localhost
- **Port**: 3306
- **Utilisateur**: root
- **Mot de passe**: password
- **Base de données**: rate_my_anime

Modifiez ces paramètres dans `app.py` selon votre configuration MySQL.

## Structure de la base de données

### Table `user`
- id (INT, PRIMARY KEY)
- username (VARCHAR(80), UNIQUE)
- email (VARCHAR(120), UNIQUE)
- password_hash (VARCHAR(120))

### Table `anime`
- id (INT, PRIMARY KEY)
- title (VARCHAR(200))
- description (TEXT)
- genre (VARCHAR(100))
- year (INT)
- added_by (INT, FOREIGN KEY → user.id)

### Table `review`
- id (INT, PRIMARY KEY)
- rating (INT, 1-5)
- comment (TEXT)
- date_created (DATETIME)
- user_id (INT, FOREIGN KEY → user.id)
- anime_id (INT, FOREIGN KEY → anime.id)

### Table `waifu` (maintenant appelée "personnage" dans l'UI)
- id (INT, PRIMARY KEY)
- name (VARCHAR(255))
- anime_id (INT, FOREIGN KEY → anime.id, NULL si videogame)
- videogame_id (INT, FOREIGN KEY → videogame.id, NULL si anime)
- description (TEXT)
- image_url (VARCHAR(500))
- added_by (INT, FOREIGN KEY → user.id)

### Table `waifu_review` (avis sur personnages)
- id (INT, PRIMARY KEY)
- rating (INT, 1-5)
- comment (TEXT)
- user_id (INT, FOREIGN KEY → user.id)
- waifu_id (INT, FOREIGN KEY → waifu.id)
- created_at (DATETIME)

### Table `videogame`
- id (INT, PRIMARY KEY)
- title (VARCHAR(255))
- description (TEXT)
- genre (VARCHAR(100))
- year (INT)
- platform (VARCHAR(100))
- cover_url (VARCHAR(500))
- added_by (INT, FOREIGN KEY → user.id)

### Table `videogame_review`
- id (INT, PRIMARY KEY)
- rating (INT, 1-5)
- comment (TEXT)
- user_id (INT, FOREIGN KEY → user.id)
- videogame_id (INT, FOREIGN KEY → videogame.id)
- created_at (DATETIME)

### Table `user_waifu_top5` (top 5 personnages)
- id (INT, PRIMARY KEY)
- user_id (INT, FOREIGN KEY → user.id)
- waifu_id (INT, FOREIGN KEY → waifu.id)
- rank_position (INT, 1-5)
- is_public (BOOLEAN)

### Table `user_videogame_top10`
- id (INT, PRIMARY KEY)
- user_id (INT, FOREIGN KEY → user.id)
- videogame_id (INT, FOREIGN KEY → videogame.id)
- rank_position (INT, 1-10)
- is_public (BOOLEAN)
