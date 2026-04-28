from flask import request
from app.extensions import socketio
from flask_socketio import join_room, leave_room

@socketio.on('join_poll')
def on_join_poll(data):
    poll_id = data.get('poll_id')
    if poll_id:
        join_room(f"poll_{poll_id}")

@socketio.on('join_battle')
def on_join_battle(data):
    battle_id = data.get('battle_id')
    if battle_id:
        join_room(f"battle_{battle_id}")

@socketio.on('join_tournament')
def on_join_tournament(data):
    tournament_id = data.get('tournament_id')
    if tournament_id:
        join_room(f"tournament_{tournament_id}")
