"""
Authentication Management Component - Flask Extensions
"""
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize extensions without binding to a specific application instance
# These will be initialized with the application in the create_app function

# SQLAlchemy for ORM
db = SQLAlchemy()

# Flask-Migrate for database migrations
migrate = Migrate()

# JWT for authentication
jwt = JWTManager()

# Bcrypt for password hashing
bcrypt = Bcrypt()

# CORS for cross-origin resource sharing
cors = CORS()

# Rate limiter for API rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


# JWT token callbacks
@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload):
    """
    Callback function to check if a JWT token is revoked.
    
    Args:
        jwt_header (dict): The JWT header.
        jwt_payload (dict): The JWT payload.
        
    Returns:
        bool: True if the token is revoked, False otherwise.
    """
    # This will be implemented when the TokenBlacklist model is created
    # For now, return False to indicate no tokens are revoked
    return False


@jwt.user_lookup_loader
def load_user_from_jwt(jwt_header, jwt_payload):
    """
    Callback function to load a user from a JWT token.
    
    Args:
        jwt_header (dict): The JWT header.
        jwt_payload (dict): The JWT payload.
        
    Returns:
        User: The user object if found, None otherwise.
    """
    # This will be implemented when the User model is created
    # For now, return None
    return None


# Error handlers for JWT
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    """
    Callback function for expired JWT tokens.
    
    Args:
        jwt_header (dict): The JWT header.
        jwt_payload (dict): The JWT payload.
        
    Returns:
        tuple: A tuple containing a JSON response and a status code.
    """
    return {
        'status': 'error',
        'message': 'The token has expired',
        'error': 'token_expired'
    }, 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    """
    Callback function for invalid JWT tokens.
    
    Args:
        error (str): The error message.
        
    Returns:
        tuple: A tuple containing a JSON response and a status code.
    """
    return {
        'status': 'error',
        'message': 'Signature verification failed',
        'error': 'invalid_token'
    }, 401


@jwt.unauthorized_loader
def missing_token_callback(error):
    """
    Callback function for missing JWT tokens.
    
    Args:
        error (str): The error message.
        
    Returns:
        tuple: A tuple containing a JSON response and a status code.
    """
    return {
        'status': 'error',
        'message': 'Request does not contain an access token',
        'error': 'authorization_required'
    }, 401


@jwt.needs_fresh_token_loader
def token_not_fresh_callback(jwt_header, jwt_payload):
    """
    Callback function for non-fresh JWT tokens.
    
    Args:
        jwt_header (dict): The JWT header.
        jwt_payload (dict): The JWT payload.
        
    Returns:
        tuple: A tuple containing a JSON response and a status code.
    """
    return {
        'status': 'error',
        'message': 'Fresh token required',
        'error': 'fresh_token_required'
    }, 401


@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    """
    Callback function for revoked JWT tokens.
    
    Args:
        jwt_header (dict): The JWT header.
        jwt_payload (dict): The JWT payload.
        
    Returns:
        tuple: A tuple containing a JSON response and a status code.
    """
    return {
        'status': 'error',
        'message': 'Token has been revoked',
        'error': 'token_revoked'
    }, 401