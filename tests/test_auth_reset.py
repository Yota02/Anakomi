import app.routes.auth as auth_routes


def test_reset_password_request_requires_email(client):
    response = client.post("/reset_password_request", data={"email": ""})

    assert response.status_code == 302
    assert "/reset_password_request" in response.headers.get("Location", "")


def test_reset_password_request_sets_session_when_user_found(client, monkeypatch):
    monkeypatch.setattr(auth_routes, "fetch_one", lambda *args, **kwargs: {
        "id": 7,
        "username": "user",
        "email": "user@example.com",
    })
    monkeypatch.setattr(auth_routes, "generate_reset_code", lambda: "123456")
    monkeypatch.setattr(auth_routes, "send_reset_email", lambda *args, **kwargs: True)

    response = client.post("/reset_password_request", data={"email": "user@example.com"})

    assert response.status_code == 302
    assert "/reset_password" in response.headers.get("Location", "")

    with client.session_transaction() as sess:
        assert sess.get("reset_code") == "123456"
        assert sess.get("reset_user_id") == 7
        assert sess.get("reset_code_time") is not None


def test_reset_password_expires_code(client, monkeypatch):
    base_time = 1_000_000
    monkeypatch.setattr(auth_routes.time, "time", lambda: base_time + 601)

    with client.session_transaction() as sess:
        sess["reset_code"] = "123456"
        sess["reset_code_time"] = base_time
        sess["reset_user_id"] = 7

    response = client.post(
        "/reset_password",
        data={"code": "123456", "password": "abc123", "password2": "abc123"},
    )

    assert response.status_code == 302
    assert "/reset_password_request" in response.headers.get("Location", "")

    with client.session_transaction() as sess:
        assert sess.get("reset_code") is None
        assert sess.get("reset_user_id") is None
        assert sess.get("reset_code_time") is None


def test_reset_password_rejects_bad_code(client, monkeypatch):
    base_time = 1_000_000
    monkeypatch.setattr(auth_routes.time, "time", lambda: base_time + 10)

    with client.session_transaction() as sess:
        sess["reset_code"] = "123456"
        sess["reset_code_time"] = base_time
        sess["reset_user_id"] = 7

    response = client.post(
        "/reset_password",
        data={"code": "000000", "password": "abc123", "password2": "abc123"},
    )

    assert response.status_code == 302
    assert "/reset_password" in response.headers.get("Location", "")

    with client.session_transaction() as sess:
        assert sess.get("reset_code") == "123456"
        assert sess.get("reset_user_id") == 7


def test_reset_password_updates_password(client, monkeypatch):
    base_time = 1_000_000
    monkeypatch.setattr(auth_routes.time, "time", lambda: base_time + 10)
    monkeypatch.setattr(auth_routes, "get_user_table_info", lambda: {
        "table": "user",
        "password_col": "password_hash",
    })

    captured = {}

    def fake_execute(query, params):
        captured["query"] = query
        captured["params"] = params

    monkeypatch.setattr(auth_routes, "execute_query", fake_execute)

    with client.session_transaction() as sess:
        sess["reset_code"] = "123456"
        sess["reset_code_time"] = base_time
        sess["reset_user_id"] = 7

    response = client.post(
        "/reset_password",
        data={"code": "123456", "password": "abc123", "password2": "abc123"},
    )

    assert response.status_code == 302
    assert "/login" in response.headers.get("Location", "")
    assert captured["query"].startswith("UPDATE user SET password_hash")
    assert captured["params"][1] == 7

    with client.session_transaction() as sess:
        assert sess.get("reset_code") is None
        assert sess.get("reset_user_id") is None
        assert sess.get("reset_code_time") is None


def test_reset_password_requires_session_data(client):
    response = client.post(
        "/reset_password",
        data={"code": "123456", "password": "abc123", "password2": "abc123"},
    )

    assert response.status_code == 302
    assert "/reset_password_request" in response.headers.get("Location", "")


def test_reset_password_rejects_mismatched_passwords(client, monkeypatch):
    base_time = 1_000_000
    monkeypatch.setattr(auth_routes.time, "time", lambda: base_time + 10)

    with client.session_transaction() as sess:
        sess["reset_code"] = "123456"
        sess["reset_code_time"] = base_time
        sess["reset_user_id"] = 7

    response = client.post(
        "/reset_password",
        data={"code": "123456", "password": "abc123", "password2": "zzz"},
    )

    assert response.status_code == 302
    assert "/reset_password" in response.headers.get("Location", "")
