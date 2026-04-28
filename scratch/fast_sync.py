from app.database import execute_query
import os

def fast_sync():
    try:
        # Simplified query without parent_id
        sql = """
            UPDATE waifu w
            JOIN (
                SELECT waifu_id, AVG(rating) as avg_r
                FROM waifu_review
                GROUP BY waifu_id
            ) r ON w.id = r.waifu_id
            SET w.rarity = CASE 
                WHEN r.avg_r >= 4.5 THEN 'Légendaire'
                WHEN r.avg_r >= 4.0 THEN 'Épique'
                WHEN r.avg_r >= 3.0 THEN 'Rare'
                ELSE 'Commune'
            END;
        """
        execute_query(sql)
        print("Rarities synchronized successfully.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    fast_sync()
