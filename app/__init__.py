
from flask import Flask
import os

def create_app():
    """Application factory function."""
    app = Flask(__name__)

    app.config.from_object('config')

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


    with app.app_context():
        from .routes import main as main_blueprint
        app.register_blueprint(main_blueprint)

    return app