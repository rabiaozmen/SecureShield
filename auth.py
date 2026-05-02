import jwt
from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

SECRET_KEY = 'your-secret-key-change-this-in-production-2025'
ALGORITHM = 'HS256'
TOKEN_EXPIRATION_HOURS = 24

def hash_password(password):
    """Şifreyi hashle ve salt ekle"""
    return bcrypt.generate_password_hash(password).decode('utf-8')

def verify_password(password, password_hash):
    """Şifreyi doğrula"""
    return bcrypt.check_password_hash(password_hash, password)

def create_token(username, role):
    """JWT token oluştur"""
    payload = {
        'username': username,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=TOKEN_EXPIRATION_HOURS),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token):
    """JWT token'ı decode et"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token süresi dolmuş
    except jwt.InvalidTokenError:
        return None  # Geçersiz token
