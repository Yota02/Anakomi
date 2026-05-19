import os
import sys
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import app as app_module
from app import create_app


@pytest.fixture()
def app(monkeypatch):
    app_module.app = None
    import app.database as database

    import app.routes.main as main_routes
    import app.routes.auth as auth_routes
    import app.routes.anime as anime_routes
    import app.routes.videogame as videogame_routes
    import app.routes.waifu as waifu_routes
    import app.routes.extra as extra_routes
    import app.routes.poll as poll_routes
    import app.routes.tournament as tournament_routes

    for bp in (
        main_routes.main_bp,
        auth_routes.auth_bp,
        anime_routes.anime_bp,
        videogame_routes.videogame_bp,
        waifu_routes.waifu_bp,
        extra_routes.extra_bp,
        poll_routes.poll_bp,
        tournament_routes.tournament_bp,
    ):
        bp._got_registered_once = False

    monkeypatch.setattr(database, "ensure_tables", lambda: None)
    app = create_app()
    app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret",
    )
    return app


@pytest.fixture()
def client(app):
    return app.test_client()
