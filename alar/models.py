from enum import Enum

from .ext import db


class UserRight(Enum):
    VIEW = 1
    CREATE = VIEW << 1
    DELETE = CREATE << 1
    UPDATE = DELETE << 1


class User(db.Model):
    __tablename__ = 'user'

    user_id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    rights = db.Column(db.Integer, nullable=False, default=0)
