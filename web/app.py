"""Flask application entry point."""

from pathlib import Path
from flask import Flask, send_from_directory
from .api import api_bp


def create_app():
    app = Flask(__name__, static_folder="static")
    app.register_blueprint(api_bp, url_prefix="/api")

    @app.route("/")
    @app.route("/<path:path>")
    def serve_spa(path=""):
        if path:
            static_file = Path(app.static_folder) / path
            if static_file.exists() and static_file.is_file():
                return send_from_directory(app.static_folder, path)
        return send_from_directory("static", "index.html")

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=8080, debug=True)
