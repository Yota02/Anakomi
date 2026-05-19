from flask import Flask
import app.routes.auth as auth_routes
from app.decorators import login_required


def test_login_required_redirects_when_logged_out():
    app = Flask(__name__)
    app.secret_key = "test"
    app.register_blueprint(auth_routes.auth_bp)
    app.config.update(TESTING=True)

    @app.route("/private")
    @login_required
    def private():
        return "ok"

    with app.test_client() as client:
        response = client.get("/private")

    assert response.status_code == 302
    assert "/login" in response.headers.get("Location", "")


def test_login_required_allows_when_logged_in():
    app = Flask(__name__)
    app.secret_key = "test"
    app.register_blueprint(auth_routes.auth_bp)
    app.config.update(TESTING=True)

    @app.route("/private")
    @login_required
    def private():
        return "ok"

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = 1
        response = client.get("/private")

    assert response.status_code == 200
