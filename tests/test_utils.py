from itsdangerous import URLSafeTimedSerializer
import app.utils as utils


def test_generate_reset_code_has_six_digits():
    code = utils.generate_reset_code()

    assert code.isdigit()
    assert len(code) == 6


def test_generate_reset_token_and_verify_returns_user_id(app):
    with app.app_context():
        token = utils.generate_reset_token(42)

    with app.app_context():
        user_id = utils.verify_reset_token(token, max_age=60)

    assert user_id == 42


def test_verify_reset_token_returns_none_on_bad_signature(app):
    with app.app_context():
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        token = serializer.dumps({"user_id": 1})

    with app.app_context():
        user_id = utils.verify_reset_token(f"{token}tampered", max_age=60)

    assert user_id is None
