from app.database import fetch_all, execute_query
import os

def sync_rarities():
    try:
        # Fetch all characters with their average ratings
        waifus = fetch_all("""
            SELECT w.id, COALESCE(AVG(r.rating), 0) as avg_rating, COUNT(r.id) as count
            FROM waifu w 
            LEFT JOIN waifu_review r ON w.id = r.waifu_id 
            GROUP BY w.id
        """)
        
        updates = 0
        for w in waifus:
            # We only update if there are reviews, or we can decide a default
            # If no reviews, we'll keep it as 'Commune' for now or whatever was there.
            # But the user specifically wants > 4.5 to be Legendaire.
            
            avg = w['avg_rating']
            count = w['count']
            
            if count == 0:
                # Optional: Handle characters with no reviews
                # For now, let's not touch them or set them to 'Commune'
                continue
            
            new_rarity = 'Commune'
            if avg >= 4.5:
                new_rarity = 'Légendaire'
            elif avg >= 4.0:
                new_rarity = 'Épique'
            elif avg >= 3.0:
                new_rarity = 'Rare'
            
            execute_query("UPDATE waifu SET rarity = %s WHERE id = %s", (new_rarity, w['id']))
            updates += 1
            
        print(f"Successfully updated {updates} characters.")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    sync_rarities()
