from functools import wraps
from flask import request, jsonify
from datetime import datetime
from auth import decode_token
from models import Database

db = Database()

def log_security_event(event_type, username, action, status):
    """Güvenlik olaylarını logla"""
    with open('security.log', 'a', encoding='utf-8') as f:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = "[{}] {} | User: {} | Action: {} | Status: {}\n".format(
            timestamp, event_type, username, action, status)
        f.write(log_entry)

def token_required(f):
    """Token doğrulama decorator'ı"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Authorization header'dan token'ı al
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]  # "Bearer TOKEN" formatı
            except IndexError:
                return jsonify({'message': 'Token format is invalid'}), 401
        
        if not token:
            log_security_event('UNAUTHORIZED', 'Unknown', request.path, 'No token provided')
            return jsonify({'message': 'Token is missing'}), 401
        
        # Token blacklist'te mi kontrol et
        if db.is_token_blacklisted(token):
            log_security_event('UNAUTHORIZED', 'Unknown', request.path, 'Token is blacklisted')
            return jsonify({'message': 'Token has been revoked'}), 401
        
        # Token'ı decode et
        payload = decode_token(token)
        if payload is None:
            log_security_event('UNAUTHORIZED', 'Unknown', request.path, 'Invalid or expired token')
            return jsonify({'message': 'Token is invalid or expired'}), 401
        
        # Payload'ı fonksiyona gönder
        return f(payload, *args, **kwargs)
    
    return decorated

def admin_required(f):
    """Admin yetkisi gerektiren decorator"""
    @wraps(f)
    def decorated(payload, *args, **kwargs):
        if payload['role'] != 'Admin':
            user_role = payload['role']
            msg = "User role '{}' attempted admin action".format(user_role)
            log_security_event(
                'FORBIDDEN', 
                payload['username'], 
                request.path, 
                msg
            )
            return jsonify({'message': 'Admin access required'}), 403
        
        return f(payload, *args, **kwargs)
    
    return decorated
