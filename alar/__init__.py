from os import environ

from flask import Flask, send_from_directory, current_app

from .ext import db
from .api import api_v1_bp


def create_app() -> 'Flask':
    """Flask application factory

    :return: Flask instance
    """
    app = Flask(__name__)
    app.config.from_object(environ.get('ALAR_CONFIG', 'config.ProductionConfig'))
    db.init_app(app)
    app.register_blueprint(api_v1_bp)
    app.add_url_rule('/', 'index', from_static, methods=('GET', ), defaults={'filename': 'index.html'})
    app.add_url_rule('/<path:filename>', 'index', from_static, methods=('GET', ))
    return app


def from_static(filename: str):
    """Proxy request to static file

    :param filename: Static filename
    :return: Static file
    """
    return send_from_directory(current_app.static_folder, filename)
