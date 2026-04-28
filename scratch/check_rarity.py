from app.database import fetch_all, execute_query
import os

def check_rarity():
    try:
        # Check current ratings
        ratings = fetch_all("""
            SELECT w.id, w.name, w.rarity, COALESCE(AVG(r.rating), 0) as avg_rating 
            FROM waifu w 
            LEFT JOIN waifu_review r ON w.id = r.waifu_id 
            GROUP BY w.id
        """)
        
        print("Current status:")
        for r in ratings:
            print(f"{r['name']} - Rarity: {r['rarity']} - Rating: {r['avg_rating']:.2f}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_rarity()
