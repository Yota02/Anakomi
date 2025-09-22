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
