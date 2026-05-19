import app.routes.poll as poll_routes


def test_list_polls_renders(client, monkeypatch):
    monkeypatch.setattr(poll_routes, "fetch_all", lambda *args, **kwargs: [])

    response = client.get("/polls")

    assert response.status_code == 200


def test_create_poll_requires_auth(client):
    response = client.get("/polls/create")

    assert response.status_code == 302
    assert "/login" in response.headers.get("Location", "")


def test_create_poll_requires_question_and_two_options(client, monkeypatch):
    with client.session_transaction() as sess:
        sess["user_id"] = 1

    response = client.post(
        "/polls/create",
        data={"question": "", "options": ["only one"]},
    )

    assert response.status_code == 200


def test_create_poll_inserts_poll_and_options(client, monkeypatch):
    with client.session_transaction() as sess:
        sess["user_id"] = 1

    executed = []

    def fake_execute(query, params):
        executed.append((query, params))

    monkeypatch.setattr(poll_routes, "execute_query", fake_execute)
    monkeypatch.setattr(poll_routes, "fetch_one", lambda *args, **kwargs: {"id": 9})

    response = client.post(
        "/polls/create",
        data={"question": "Q?", "options": ["A", "B", ""]},
    )

    assert response.status_code == 302
    assert "/polls" in response.headers.get("Location", "")
    assert executed[0][0].startswith("INSERT INTO poll")
    assert any(q.startswith("INSERT INTO poll_option") for q, _ in executed[1:])


def test_poll_detail_redirects_when_missing(client, monkeypatch):
    monkeypatch.setattr(poll_routes, "fetch_one", lambda *args, **kwargs: None)

    response = client.get("/polls/1")

    assert response.status_code == 302
    assert "/polls" in response.headers.get("Location", "")


def test_poll_detail_renders_with_votes(client, monkeypatch):
    monkeypatch.setattr(
        poll_routes,
        "fetch_one",
        lambda *args, **kwargs: {
            "id": 1,
            "question": "Q",
            "creator": "User",
            "created_at": __import__("datetime").datetime(2024, 1, 1),
        },
    )
    monkeypatch.setattr(
        poll_routes,
        "fetch_all",
        lambda *args, **kwargs: [
            {"id": 1, "vote_count": 2},
            {"id": 2, "vote_count": 3},
        ],
    )

    response = client.get("/polls/1")

    assert response.status_code == 200


def test_poll_vote_requires_option_id(client, monkeypatch):
    with client.session_transaction() as sess:
        sess["user_id"] = 1

    response = client.post("/polls/1/vote", data={})

    assert response.status_code == 302
    assert "/polls/1" in response.headers.get("Location", "")


def test_poll_vote_emits_update(client, monkeypatch):
    with client.session_transaction() as sess:
        sess["user_id"] = 1

    monkeypatch.setattr(poll_routes, "execute_query", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        poll_routes,
        "fetch_all",
        lambda *args, **kwargs: [
            {"id": 1, "vote_count": 2},
            {"id": 2, "vote_count": 3},
        ],
    )

    emitted = {}

    def fake_emit(event, payload, room=None):
        emitted["event"] = event
        emitted["payload"] = payload
        emitted["room"] = room

    monkeypatch.setattr(poll_routes.socketio, "emit", fake_emit)

    response = client.post("/polls/1/vote", data={"option_id": "2"})

    assert response.status_code == 302
    assert emitted["event"] == "poll_update"
    assert emitted["room"] == "poll_1"
