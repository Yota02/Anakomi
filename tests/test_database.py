import app.database as database


def test_resolve_user_table_returns_fallback_on_exception(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("db down")

    monkeypatch.setattr(database, "fetch_all", boom)

    info = database.resolve_user_table()

    assert info == {"table": "user", "password_col": "password_hash"}
