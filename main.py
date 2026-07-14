from flask import Flask

from dashboard.dashboard import dashboard_blueprint


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)

    app.config.update(
        SECRET_KEY="development-only-change-later",
        JSON_SORT_KEYS=False,
    )

    app.register_blueprint(dashboard_blueprint)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)