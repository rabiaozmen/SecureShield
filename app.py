from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from models import Database
from auth import hash_password, verify_password, create_token
from middleware import token_required, admin_required, log_security_event

app = Flask(__name__)
bcrypt = Bcrypt(app)
db = Database()

# İlk admin kullanıcısını oluştur
@app.before_request
def create_default_admin():
    if not hasattr(app, 'admin_created'):
        admin = db.get_user_by_username('admin')
        if not admin:
            admin_hash = hash_password('admin123')
            db.create_user('admin', admin_hash, 'Admin')
            print("✅ Default admin user created: admin/admin123")
        app.admin_created = True

@app.route('/')
def home():
    return jsonify({
        'message': 'SecureShield RBAC API',
        'version': '1.0',
        'endpoints': {
            'POST /register': 'Register a new user',
            'POST /login': 'Login and get JWT token',
            'POST /logout': 'Logout and blacklist token',
            'GET /profile': 'Get user profile (User/Admin)',
            'DELETE /user/<id>': 'Delete user (Admin only)'
        }
    })

# Task 1: Secure Password Storage
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password are required'}), 400
    
    username = data['username']
    password = data['password']
    role = data.get('role', 'User')
    
    # Sadece User rolü ile kayıt olunabilir
    if role == 'Admin':
        return jsonify({'message': 'Cannot register as Admin'}), 403
    
    # Şifreyi hashle
    password_hash = hash_password(password)
    
    # Kullanıcıyı oluştur
    user_id = db.create_user(username, password_hash, role)
    
    if user_id is None:
        return jsonify({'message': 'Username already exists'}), 409
    
    log_security_event('REGISTRATION', username, '/register', 'Success')
    
    return jsonify({
        'message': 'User registered successfully',
        'user_id': user_id,
        'username': username,
        'role': role
    }), 201

# Task 2: JWT Issuance
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password are required'}), 400
    
    username = data['username']
    password = data['password']
    
    # Kullanıcıyı bul
    user = db.get_user_by_username(username)
    
    if not user or not verify_password(password, user['password_hash']):
        log_security_event('LOGIN_FAILED', username, '/login', 'Invalid credentials')
        return jsonify({'message': 'Invalid username or password'}), 401
    
    # JWT token oluştur
    token = create_token(user['username'], user['role'])
    
    user_role = user['role']
    log_security_event('LOGIN_SUCCESS', username, '/login', 'Role: ' + user_role)
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'username': user['username'],
        'role': user['role']
    }), 200

# Task 3 & 4: Token Validation & Role-Based Routing (User/Admin)
@app.route('/profile', methods=['GET'])
@token_required
def get_profile(payload):
    """Hem User hem Admin erişebilir"""
    user = db.get_user_by_username(payload['username'])
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'created_at': user['created_at']
    }), 200

# Task 4: Role-Based Routing (Admin only)
@app.route('/user/<int:user_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_user(payload, user_id):
    """Sadece Admin erişebilir"""
    
    # Kendi hesabını silmeyi engelle
    current_user = db.get_user_by_username(payload['username'])
    if current_user['id'] == user_id:
        return jsonify({'message': 'Cannot delete your own account'}), 403
    
    # Kullanıcıyı sil
    deleted = db.delete_user(user_id)
    
    if not deleted:
        return jsonify({'message': 'User not found'}), 404
    
    user_path = '/user/{}'.format(user_id)
    log_security_event('USER_DELETED', payload['username'], user_path, 'Success')
    
    return jsonify({'message': 'User {} deleted successfully'.format(user_id)}), 200

# Task 5: Token Revocation (Blacklisting)
@app.route('/logout', methods=['POST'])
@token_required
def logout(payload):
    """Token'ı blacklist'e ekle"""
    token = request.headers['Authorization'].split(' ')[1]
    
    db.add_to_blacklist(token)
    
    log_security_event('LOGOUT', payload['username'], '/logout', 'Token blacklisted')
    
    return jsonify({'message': 'Logout successful, token has been revoked'}), 200

if __name__ == '__main__':
    print("🚀 SecureShield API starting...")
    print("📍 Server: http://localhost:5000")
    print("📖 Documentation: http://localhost:5000/")
    app.run(debug=True, port=5000)
