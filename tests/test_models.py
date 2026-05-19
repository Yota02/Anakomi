import app.models as models


def test_get_user_table_info_falls_back_on_error(monkeypatch):
    def boom():
        raise RuntimeError("db down")

    monkeypatch.setattr(models, "resolve_user_table", boom)
    models._user_table_cache = None

    info = models.get_user_table_info()

    assert info == {"table": "user", "password_col": "password_hash"}


def test_get_user_table_info_uses_cached_value(monkeypatch):
    models._user_table_cache = {"table": "users", "password_col": "password"}
    monkeypatch.setattr(models, "resolve_user_table", lambda: {"table": "x", "password_col": "y"})

    info = models.get_user_table_info()

    assert info == {"table": "users", "password_col": "password"}
