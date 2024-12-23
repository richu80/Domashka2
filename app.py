from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt, check_password_hash, generate_password_hash
import jwt
import time
from functools import wraps


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# секретный ключ, которым мы шифруем данные
app.config['SECRET_KEY'] = 'secret'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    country_code = db.Column(db.String(10), nullable=False)
    is_public = db.Column(db.Boolean, default=True)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    image = db.Column(db.String(500), nullable=True)
    bio = db.Column(db.Text)
    last_generation = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(100), nullable=False)

def format_user(user): #вернется в виде словаря???
    return {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'bio': user.bio,
        'country': user.country_code,
        'phone_number': user.phone,
        'is_public': user.is_public,
        'profile_image': user.image,
        'login': user.login,
        'image': user.image
    }


class CountryInfo(db.Model): #создаем класс стран каждого пользователя, который авторизовался и вошел
    __tablename__ = 'countries'

    id = db.Column(db.Integer, primary_key=True)
    country_name = db.Column(db.String(100), nullable=False)
    alpha2_code = db.Column(db.String(2), nullable=False, unique=True)
    alpha3_code = db.Column(db.String(3), nullable=False, unique=True)
    region_name = db.Column(db.String(100))

def format_country(country):
    return {
        'id': country.id,
        'name': country.country_name,
        'alpha2': country.alpha2_code,
        'alpha3': country.alpha3_code,
        'region': country.region_name
    }


def requires_user(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # получаем токен из заголовков запроса (просто запомнить)
        token = request.headers.get('Authorization', '').replace('Bearer ', '')

        # если токена нет - возвращаем ошибку
        if not token:
            return jsonify({'error': 'Missing token'}), 401

        # расшифровываем токен и получаем его содержимое
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except Exception as e:
            return jsonify({'error': 'Invalid token'}), 401

        # получаем id пользователя и время генерации из токена
        user_id = payload.get('user_id')
        created_at = payload.get('created_at')

        # если чего-то нет - возвращаем ошибку
        if not user_id or not created_at:
            return jsonify({'error': 'Invalid token'}), 401

        # находим пользователя, если его нет - возвращаем ошибку
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 401

        # если с момента генерации прошло больше суток, просим войти заного
        if created_at + 60 * 60 * 24 < int(time.time()):
            return jsonify({'error': 'Token expired'}), 401

        # передаем в целевой эндпоинт пользователя и параметры пути
        return func(user, *args, **kwargs)

    return wrapper

@app.route('/api/ping', methods=['GET'])
def send():
    return jsonify({"status": "ok"}), 200

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Missing data'}), 400

    login = data['login']
    username = data['username']
    email = data['email']
    password = data['password']
    country_code = data['countryCode']
    is_public = data['isPublic']
    phone = data['phone']
    image = data['image']
    bio = data['bio']

    if User.query.filter_by(login=login).first():
        return jsonify({'error': 'User already exists'}), 400


        # заменяем пароль на хэш пароля
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(
        login=login,
        email=email,
        password=hashed_password,
        country_code=country_code,
        is_public=is_public,
        phone=phone,
        image=image,
        bio=bio,
        username=username
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'success': True}), 201

@app.route('/api/sign-in', methods=['POST'])
def login():
    data = request.get_json()

    login = data.get('login')
    password = data.get('password')

    if not login or not password:
        return jsonify({'error': 'Missing data'}), 400

    # ищем пользователя в базе и проверяем хэш пароля
    user = User.query.filter_by(login=login).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    # генерируем токен с id пользователя и временем создания
    token = jwt.encode({'user_id': user.id, 'created_at': int(time.time())}, app.config['SECRET_KEY'],
                       algorithm='HS256')

    return jsonify({'token': token}), 200

@app.route('/api/countries', methods=['GET'])  #получение всех стран, возвращение в виде джисон
def get_countries():
    countries = CountryInfo.query.all()
    return jsonify([format_country(c) for c in countries])

@app.route('/api/country/<string:alpha2>', methods=['GET'])
def get_country(alpha2):
    # country = Certain_CountryInfo.query.filter_by(alpha2=alpha2).first()
    country = CountryInfo.query.filter_by(alpha2=alpha2).first()
    # ищем конкретную страну, если ее нет, то выводится ошибка
    if not country:
        return jsonify({'error': 'Country not found'}), 404
    # return jsonify(special_format_country(country))
    return jsonify(format_country(country)), 200

@app.route('/api/me/profile', methods=['GET'])
@requires_user
def generate_number(user):
    # если пользователь посылает запросы чаще раза в секунду - отправляем ошибку
    if user.last_generation == int(time.time()):
        return jsonify({'error': 'Too many request per second'}), 401

    user.last_generation = int(time.time())
    db.session.commit()

    return jsonify(format_user(user)), 200

@app.route('/api/me/profile', methods=['PATCH'])
@requires_user
def update_user(user):
    data = request.get_json()
    try:
        countryCode = data.get('country')
    except Exception as e:
        return jsonify({'error': 'Missing username'}), 400
    user.country_code = countryCode

    try:
        isPublic = data.get('is_public')
    except Exception as e:
        return jsonify({'error': 'Missing isPublic'}), 400
    user.is_public = isPublic

    try:
        phone = data.get('phone')
    except Exception as e:
        return jsonify({'error': 'Missing Phone'}), 400
    user.phone = phone

    try:
        image = data.get('image')
    except Exception as e:
        return jsonify({'error': 'Missing image'}), 400
    user.image = image
    user.last_generation = int(time.time())
    db.session.commit()
    return jsonify(format_user(user)), 200

@app.route('/api/profiles/<string:login>', methods=['GET'])
@requires_user
def get_user_profile(login):
    user = User.query.filter_by(login=login).first()
    if not user:
        return jsonify({'reason': "Missing user"}), 404

    return jsonify({
        "profile": {
            'username': user.username,
            'email': user.email,
            'bio': user.bio,
            'country': user.country_code,
            'phone_number': user.phone,
            'is_public': user.is_public,
            'profile_image': user.image,
            'login': user.login,
            'image': user.image
        }
    }), 200

@app.route('/api/profiles/<string:login>', methods=['PUT'])
@requires_user
def update_password(user):
    data = request.get_json()
    old_password = data.get("oldPassword")
    new_password = data.get('newPassword')
    if not old_password or not new_password:
        return jsonify({'reason': "Missing password"})

    if not check_password_hash(user.password, old_password):
        return jsonify({'reason': "old password is incorrect"})

    user.password = generate_password_hash(new_password)
    db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run()
