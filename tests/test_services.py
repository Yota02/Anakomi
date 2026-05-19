import app.services as services


def test_send_reset_email_falls_back_to_logging(monkeypatch):
    monkeypatch.setattr(services.os, "getenv", lambda *args, **kwargs: None)

    result = services.send_reset_email("user@example.com", "123456", "User")

    assert result is False
