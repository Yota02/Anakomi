from app.database import fetch_all, fetch_one, ensure_tables

def diagnose():
    print("--- Diagnostic Battle Royale ---")
    
    # 1. Ensure tables exist
    print("Vérification des tables...")
    ensure_tables()
    
    # 2. Check waifu count
    waifus = fetch_all("SELECT COUNT(*) as count FROM waifu")
    waifu_count = waifus[0]['count'] if waifus else 0
    print(f"Nombre de personnages (waifu) : {waifu_count}")
    
    if waifu_count < 2:
        print("ERREUR : Pas assez de personnages pour créer une battle (minimum 2 requis).")
    
    # 3. Check existing battles
    battles = fetch_all("SELECT * FROM battle_royale")
    print(f"Nombre de battles existantes : {len(battles)}")
    
    for b in battles:
        participants = fetch_all("SELECT * FROM battle_participant WHERE battle_id = %s", (b['id'],))
        print(f"  - Battle '{b['title']}' (ID: {b['id']}) : {len(participants)} participants")

if __name__ == "__main__":
    try:
        diagnose()
    except Exception as e:
        print(f"ERREUR lors du diagnostic : {e}")
