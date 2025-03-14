"""
Authentication Management Component - Configuration Management
"""
import os
from datetime import timedelta


class Config:
    """Base configuration class with common settings."""
    
    # Flask settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    DEBUG = False
    TESTING = False
    
    # SQLAlchemy settings
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/auth_service')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # JWT settings
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
    
    # Bcrypt settings
    BCRYPT_LOG_ROUNDS = 12
    
    # CORS settings
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', '*').split(',')
    
    # Rate limiting settings
    RATELIMIT_DEFAULT = "200 per day, 50 per hour"
    RATELIMIT_STORAGE_URL = os.getenv('REDIS_URL', 'memory://')
    RATELIMIT_STRATEGY = 'fixed-window'
    
    # Email settings
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.sendgrid.net')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'apikey')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@example.com')
    
    # Security settings
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_MAX_LENGTH = 128
    PASSWORD_COMPLEXITY_REGEX = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]'
    ACCOUNT_LOCKOUT_THRESHOLD = 5
    ACCOUNT_LOCKOUT_DURATION = timedelta(minutes=15)
    
    # Logging settings
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE = os.path.join('logs', 'auth_service.log')


class DevelopmentConfig(Config):
    """Development configuration."""
    
    DEBUG = True
    SQLALCHEMY_ECHO = True
    BCRYPT_LOG_ROUNDS = 4  # Lower rounds for faster tests
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=1)  # Longer expiration for development
    
    # Development-specific settings
    DEVELOPMENT_MODE = True


class TestingConfig(Config):
    """Testing configuration."""
    
    TESTING = True
    DEBUG = True
    
    # Use in-memory SQLite for tests
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Faster password hashing for tests
    BCRYPT_LOG_ROUNDS = 4
    
    # Shorter token expiration for tests
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=5)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(hours=1)
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    """Production configuration."""
    
    # Production requires proper secret keys
    SECRET_KEY = os.getenv('SECRET_KEY', 'prod-secret-key-placeholder')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'prod-jwt-secret-key-placeholder')
    
    # In a real production environment, we would validate these are set
    # But for testing purposes, we'll use placeholders
    
    # Production database should be properly configured
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/auth_service')
    
    # Higher security settings for production
    BCRYPT_LOG_ROUNDS = 12
    
    # Stricter CORS in production
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', '').split(',')
    
    # Rate limiting in production
    RATELIMIT_DEFAULT = "100 per day, 20 per hour"
    
    # Secure cookies
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True


# Configuration dictionary
config_dict = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}


def get_config(config_name):
    """
    Get the configuration class based on the provided name.
    
    Args:
        config_name (str): The name of the configuration to use.
        
    Returns:
        Config: The configuration class.
    """
    return config_dict.get(config_name, config_dict['default'])
