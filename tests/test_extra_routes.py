import app.routes.extra as extra_routes


def test_compare_redirects_when_not_enough_items(client, monkeypatch):
    monkeypatch.setattr(extra_routes, "fetch_all", lambda *args, **kwargs: [])

    response = client.get("/compare?type=anime")

    assert response.status_code == 302
    assert "/" in response.headers.get("Location", "")


def test_compare_renders_with_two_items(client, monkeypatch):
    monkeypatch.setattr(
        extra_routes,
        "fetch_all",
        lambda *args, **kwargs: [{"id": 1}, {"id": 2}],
    )

    response = client.get("/compare?type=anime")

    assert response.status_code == 200


def test_compare_vote_inserts_and_redirects(client, monkeypatch):
    with client.session_transaction() as sess:
        sess["user_id"] = 5

    captured = {}

    def fake_execute(query, params):
        captured["query"] = query
        captured["params"] = params

    monkeypatch.setattr(extra_routes, "execute_query", fake_execute)

    response = client.post(
        "/compare/vote",
        data={"item_type": "anime", "winner_id": "1", "loser_id": "2"},
    )

    assert response.status_code == 302
    assert "/compare" in response.headers.get("Location", "")
    assert captured["query"].startswith("INSERT INTO comparison_vote")


def test_dice_roll_redirects_when_no_genres(client, monkeypatch):
    def fake_fetch_all(query, params=None):
        if "DISTINCT genre" in query:
            return []
        return []

    monkeypatch.setattr(extra_routes, "fetch_all", fake_fetch_all)

    response = client.get("/dice-roll")

    assert response.status_code == 302
    assert "/" in response.headers.get("Location", "")


def test_dice_roll_renders_with_results(client, monkeypatch):
    def fake_fetch_all(query, params=None):
        if "DISTINCT genre" in query:
            return [{"genre": "Action"}]
        return [{"id": 1}, {"id": 2}]

    monkeypatch.setattr(extra_routes, "fetch_all", fake_fetch_all)

    response = client.get("/dice-roll")

    assert response.status_code == 200


def test_intruder_redirects_when_not_enough_genres(client, monkeypatch):
    def fake_fetch_all(query, params=None):
        if "GROUP BY genre" in query:
            return [{"genre": "Action", "count": 3}]
        return []

    monkeypatch.setattr(extra_routes, "fetch_all", fake_fetch_all)

    response = client.get("/intruder")

    assert response.status_code == 302
    assert "/" in response.headers.get("Location", "")


def test_update_quest_progress_updates_and_rewards(monkeypatch):
    quest = {
        "id": 10,
        "progress": 4,
        "target": 5,
        "completed": False,
    }
    monkeypatch.setattr(extra_routes, "fetch_one", lambda *args, **kwargs: quest)

    executed = []

    def fake_execute(query, params):
        executed.append((query, params))

    monkeypatch.setattr(extra_routes, "execute_query", fake_execute)

    extra_routes.update_quest_progress(1, "gacha_rolls", 1)

    assert executed[0][0].startswith("UPDATE user_quest SET progress")
    assert any(q.startswith("UPDATE user SET points") for q, _ in executed)


def test_update_quest_progress_creates_new(monkeypatch):
    monkeypatch.setattr(extra_routes, "fetch_one", lambda *args, **kwargs: None)

    executed = []

    def fake_execute(query, params):
        executed.append((query, params))

    monkeypatch.setattr(extra_routes, "execute_query", fake_execute)

    extra_routes.update_quest_progress(1, "gacha_rolls", 5)

    assert executed[0][0].startswith("INSERT INTO user_quest")
    assert any(q.startswith("UPDATE user SET points") for q, _ in executed)
