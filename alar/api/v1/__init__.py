from functools import wraps
from multiprocessing.dummy import Pool
from itertools import chain

from flask import Blueprint, request, jsonify, current_app, g, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import URLSafeTimedSerializer, BadData
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
from sqlalchemy.exc import IntegrityError
import requests

from alar.ext import db
from alar.models import User, UserRight


bp = Blueprint('api_v1', __name__, url_prefix='/api/v1/')


def rights_required(rights):
    """Configurable decorator for access control

    :param rights: Rights integer value
    :return: Configured decorator
    """
    def rights_required_internal(view):
        @wraps(view)
        def rights_required_wraps(*args, **kwargs):
            if g.user is None:
                return jsonify({'error': 'invalid token'}), 401
            if (g.user.rights & rights) != rights:
                return jsonify({'error': 'invalid rights'}), 401
            return view(*args, **kwargs)
        return rights_required_wraps
    return rights_required_internal


@bp.before_request
def before_request():
    """Pull current user from DB"""
    try:
        signer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'], current_app.config['TOKEN_SALT'])
        user_id = signer.loads(request.headers['X-Token-Auth'], current_app.config['TOKEN_TIME'].seconds)
        g.user = User.query.get(user_id)
    except (KeyError, BadData):
        g.user = None


@bp.errorhandler(Exception)
@bp.errorhandler(500)
def error_500(_):
    """Internal Server Error handler"""
    current_app.logger.exception('internal server error')
    db.session.rollback()
    return jsonify({'error': 'internal server error'}), 500


def user_dump(target_user):
    return {
        'id': target_user.user_id,
        'login': target_user.login,
        'can_view': bool(target_user.rights & UserRight.VIEW.value),
        'can_create': bool(target_user.rights & UserRight.CREATE.value),
        'can_update': bool(target_user.rights & UserRight.UPDATE.value),
        'can_delete': bool(target_user.rights & UserRight.DELETE.value),
    }


def rights_from_flags(can_view, can_create, can_update, can_delete):
    rights = 0
    if can_view:
        rights |= UserRight.VIEW.value
    if can_create:
        rights |= UserRight.CREATE.value
    if can_update:
        rights |= UserRight.UPDATE.value
    if can_delete:
        rights |= UserRight.DELETE.value
    return rights


@bp.route('login', methods=('POST', ))
def login():
    """Login view"""
    user_login = request.json.get('login', '')
    user_password = request.json.get('password', '')
    user = User.query.filter_by(login=user_login).first()
    if not user or not check_password_hash(user.password, user_password):
        return jsonify({'error': 'invalid credentials'}), 400
    return jsonify({
        'token': URLSafeTimedSerializer(current_app.config['SECRET_KEY'],
                                        current_app.config['TOKEN_SALT']).dumps(user.user_id),
        **user_dump(user),
    })


@bp.route('user', methods=('GET', ))
@rights_required(UserRight.VIEW.value)
def user_list():
    """User List View"""
    try:
        offset = request.args['offset']
        limit = request.args['limit']
    except KeyError:
        return jsonify({'error': 'limit and offset argument is required'}), 400
    return jsonify([user_dump(_) for _ in User.query.order_by(User.user_id).offset(offset).limit(limit).all()])


@bp.route('user/<int:user_id>', methods=('DELETE', ))
@rights_required(UserRight.DELETE.value)
def user_delete(user_id):
    """Delete user by user_id"""
    if user_id == g.user.user_id:
        return jsonify({'error': 'can not delete self'}), 400
    result = db.session.execute('DELETE FROM "user" WHERE "user_id" = :user_id', {'user_id': user_id})
    db.session.commit()
    if not result.rowcount:
        return jsonify({'error': 'user does not exists'}), 404
    return '', 204


@bp.route('user', methods=('POST', ))
@rights_required(UserRight.CREATE.value)
def user_create():
    """Create new user"""
    try:
        new_user = User()
        new_user.login = request.json['login']
        new_user.password = generate_password_hash(request.json['password'])
        new_user.rights = rights_from_flags(request.json['can_view'], request.json['can_create'],
                                            request.json['can_update'], request.json['can_delete'])
        db.session.add(new_user)
        db.session.commit()
        return user_dump(new_user), 201
    except KeyError:
        return jsonify({'error': 'invalid input'}), 400
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'login already registered'}), 400


@bp.route('user/<int:user_id>', methods=('GET', ))
@rights_required(UserRight.VIEW.value)
def user_view(user_id):
    """View single user"""
    try:
        return jsonify(user_dump(User.query.filter_by(user_id=user_id).one()))
    except (NoResultFound, MultipleResultsFound):
        return jsonify({'error': 'user does not exists'}), 404


@bp.route('user/<int:user_id>', methods=('PUT', ))
@rights_required(UserRight.UPDATE.value)
def user_update(user_id):
    """Update exists user"""
    try:
        exists_user = User.query.filter_by(user_id=user_id).one()
        exists_user.login = request.json['login']
        exists_user.rights = rights_from_flags(request.json['can_view'], request.json['can_create'],
                                               request.json['can_update'], request.json['can_delete'])
        if request.json.get('password', ''):
            exists_user.password = generate_password_hash(request.json['password'])
        db.session.commit()
        return user_dump(exists_user)
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'login already registered'}), 400
    except (NoResultFound, MultipleResultsFound):
        return jsonify({'error': 'user does not exists'}), 404
    except KeyError:
        return jsonify({'error': 'invalid input'}), 400


@bp.route('data', methods=('GET', ))
def data():
    """Async request data from many sources"""
    def request_data(uri):
        try:
            response = requests.get(uri, timeout=2)
            response.raise_for_status()
            return response.json()
        except (IOError, ValueError):
            return []
    with Pool(3) as pool:
        responses = pool.map(request_data,
                             (url_for('static', filename='s0.json', _external=True),
                              url_for('static', filename='s1.json', _external=True),
                              url_for('static', filename='s2.json', _external=True), ))
        pool.close()
        pool.join()
    return jsonify(list(sorted(filter(lambda _: 'id' in _, chain(*responses)), key=lambda _: _['id'])))
