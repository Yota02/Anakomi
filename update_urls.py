import os
import re

mappings = {
    'index': 'main.index',
    'contact': 'main.contact',
    'register': 'auth.register',
    'login': 'auth.login',
    'logout': 'auth.logout',
    'reset_password_request': 'auth.reset_password_request',
    'reset_password': 'auth.reset_password',
    'add_anime': 'anime.add_anime',
    'anime_detail': 'anime.anime_detail',
    'add_review': 'anime.add_review',
    'edit_anime': 'anime.edit_anime',
    'top10_users': 'anime.top10_users',
    'view_user_top10': 'anime.view_user_top10',
    'my_top10': 'anime.my_top10',
    'update_top10': 'anime.update_top10',
    'videogames_list': 'videogame.videogames_list',
    'add_videogame': 'videogame.add_videogame',
    'videogame_detail': 'videogame.videogame_detail',
    'add_videogame_review': 'videogame.add_videogame_review',
    'videogame_top10_users': 'videogame.videogame_top10_users',
    'view_user_videogame_top10': 'videogame.view_user_videogame_top10',
    'my_videogame_top10': 'videogame.my_videogame_top10',
    'update_videogame_top10': 'videogame.update_videogame_top10',
    'edit_videogame': 'videogame.edit_videogame',
    'waifus_list': 'waifu.waifus_list',
    'add_waifu': 'waifu.add_waifu',
    'waifu_detail': 'waifu.waifu_detail',
    'add_waifu_review': 'waifu.add_waifu_review',
    'my_waifu_top5': 'waifu.my_waifu_top5',
    'update_waifu_top5': 'waifu.update_waifu_top5',
    'waifu_top5_users': 'waifu.waifu_top5_users',
    'view_user_waifu_top5': 'waifu.view_user_waifu_top5',
    'edit_waifu': 'waifu.edit_waifu',
    'waifus_anime_filles': 'waifu.waifus_anime_filles',
    'waifus_anime_garcons': 'waifu.waifus_anime_garcons',
    'waifus_jeux_video_filles': 'waifu.waifus_jeux_video_filles',
    'waifus_jeux_video_garcons': 'waifu.waifus_jeux_video_garcons'
}

templates_dir = r'C:\Users\Alexis\Desktop\Anakomi\templates'

for filename in os.listdir(templates_dir):
    if filename.endswith('.html'):
        filepath = os.path.join(templates_dir, filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        for old_func, new_func in mappings.items():
            # Match url_for('old_func') or url_for("old_func") or url_for('old_func', ...)
            pattern = r"url_for\(\s*['\"]" + re.escape(old_func) + r"['\"]"
            replacement = f"url_for('{new_func}'"
            content = re.sub(pattern, replacement, content)
        
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Updated {filename}")
        else:
            print(f"No changes in {filename}")
