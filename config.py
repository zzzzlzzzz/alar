from os import environ
from datetime import timedelta


class Config:
    SECRET_KEY = environ.get('ALAR_SECRET_KEY', '')
    SQLALCHEMY_DATABASE_URI = environ.get('ALAR_DATABASE_URI', '')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = dict(pool_pre_ping=True)
    TOKEN_SALT = 'token'
    TOKEN_TIME = timedelta(hours=1)


class DevelopmentConfig(Config):
    SEND_FILE_MAX_AGE_DEFAULT = 0


class ProductionConfig(Config):
    pass


class TestConfig(Config):
    pass
