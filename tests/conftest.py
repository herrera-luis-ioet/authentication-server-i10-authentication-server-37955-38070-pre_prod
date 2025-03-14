"""
Authentication Management Component - Test Fixtures

This module contains pytest fixtures for testing the Authentication Management Component.
"""
import os
import pytest
from datetime import datetime, timedelta

from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import text

from app import create_app
from app.extensions import db as _db
from app.models.user import User, UserRole, UserStatus
from app.models.token import Token, TokenType


@pytest.fixture(scope='session')
def app():
    """Create and configure a Flask app for testing."""
    # Use the testing configuration
    app = create_app('testing')
    
    # Create an application context
    with app.app_context():
        # Create all tables
        _db.create_all()
        
        yield app
        
        # Clean up after tests
        _db.session.remove()
        _db.drop_all()


@pytest.fixture(scope='session')
def db(app):
    """Database fixture for testing."""
    return _db


@pytest.fixture(scope='function')
def session(db):
    """Creates a new database session for each test."""
    connection = db.engine.connect()
    transaction = connection.begin()
    
    # Create a session bound to the connection
    session = db.session
    db.session = session
    
    yield session
    
    # Rollback the transaction and close the connection
    transaction.rollback()
    connection.close()
    session.remove()


@pytest.fixture(scope='function')
def client(app):
    """A test client for the app."""
    with app.test_client() as client:
        yield client


@pytest.fixture(scope='function')
def test_user(session):
    """Create a test user."""
    user = User(
        username='testuser',
        email='test@example.com',
        first_name='Test',
        last_name='User',
        role=UserRole.USER,
        status=UserStatus.ACTIVE,
        email_verified=True,
        email_verified_at=datetime.utcnow()
    )
    user.password = 'Password123!'
    session.add(user)
    session.commit()
    
    yield user
    
    # Clean up
    session.delete(user)
    session.commit()


@pytest.fixture(scope='function')
def admin_user(session):
    """Create an admin user."""
    user = User(
        username='adminuser',
        email='admin@example.com',
        first_name='Admin',
        last_name='User',
        role=UserRole.ADMIN,
        status=UserStatus.ACTIVE,
        email_verified=True,
        email_verified_at=datetime.utcnow()
    )
    user.password = 'AdminPass123!'
    session.add(user)
    session.commit()
    
    yield user
    
    # Clean up
    session.delete(user)
    session.commit()


@pytest.fixture(scope='function')
def unverified_user(session):
    """Create an unverified user."""
    user = User(
        username='unverified',
        email='unverified@example.com',
        first_name='Unverified',
        last_name='User',
        role=UserRole.USER,
        status=UserStatus.PENDING_VERIFICATION,
        email_verified=False
    )
    user.password = 'Password123!'
    session.add(user)
    session.commit()
    
    yield user
    
    # Clean up
    session.delete(user)
    session.commit()


@pytest.fixture(scope='function')
def locked_user(session):
    """Create a locked user."""
    user = User(
        username='locked',
        email='locked@example.com',
        first_name='Locked',
        last_name='User',
        role=UserRole.USER,
        status=UserStatus.LOCKED,
        email_verified=True,
        email_verified_at=datetime.utcnow(),
        failed_login_attempts=5
    )
    user.password = 'Password123!'
    session.add(user)
    session.commit()
    
    yield user
    
    # Clean up
    session.delete(user)
    session.commit()


@pytest.fixture(scope='function')
def refresh_token(session, test_user):
    """Create a refresh token for the test user."""
    token = Token(
        token='test_refresh_token',
        token_type=TokenType.REFRESH,
        user_id=test_user.id,
        expires_at=datetime.utcnow() + timedelta(days=30),
        is_revoked=False
    )
    session.add(token)
    session.commit()
    
    yield token
    
    # Clean up
    session.delete(token)
    session.commit()


@pytest.fixture(scope='function')
def reset_token(session, test_user):
    """Create a password reset token for the test user."""
    token = Token(
        token='test_reset_token',
        token_type=TokenType.RESET_PASSWORD,
        user_id=test_user.id,
        expires_at=datetime.utcnow() + timedelta(hours=1),
        is_revoked=False
    )
    session.add(token)
    session.commit()
    
    yield token
    
    # Clean up
    session.delete(token)
    session.commit()


@pytest.fixture(scope='function')
def verification_token(session, unverified_user):
    """Create an email verification token for the unverified user."""
    token = Token(
        token='test_verification_token',
        token_type=TokenType.EMAIL_VERIFICATION,
        user_id=unverified_user.id,
        expires_at=datetime.utcnow() + timedelta(days=7),
        is_revoked=False
    )
    session.add(token)
    session.commit()
    
    yield token
    
    # Clean up
    session.delete(token)
    session.commit()


@pytest.fixture(scope='function')
def api_key(session, test_user):
    """Create an API key for the test user."""
    token = Token(
        token='test_api_key',
        token_type=TokenType.API_KEY,
        user_id=test_user.id,
        expires_at=datetime.utcnow() + timedelta(days=365),
        is_revoked=False
    )
    session.add(token)
    session.commit()
    
    yield token
    
    # Clean up
    session.delete(token)
    session.commit()


@pytest.fixture(scope='function')
def auth_headers(test_user, app):
    """Generate authentication headers for the test user."""
    from app.utils.security import generate_jwt_token
    
    access_token = generate_jwt_token(test_user.id, "access")
    
    return {
        'Authorization': f'Bearer {access_token}'
    }


@pytest.fixture(scope='function')
def admin_auth_headers(admin_user, app):
    """Generate authentication headers for the admin user."""
    from app.utils.security import generate_jwt_token
    
    access_token = generate_jwt_token(admin_user.id, "access")
    
    return {
        'Authorization': f'Bearer {access_token}'
    }


class AuthActions:
    """Helper class for authentication actions in tests."""
    
    def __init__(self, client):
        self._client = client
        
    def login(self, username_or_email='testuser', password='Password123!'):
        """Log in with the given credentials."""
        return self._client.post(
            '/api/auth/login',
            json={
                'username_or_email': username_or_email,
                'password': password
            }
        )
    
    def logout(self, access_token):
        """Log out with the given access token."""
        return self._client.post(
            '/api/auth/logout',
            headers={'Authorization': f'Bearer {access_token}'}
        )
    
    def register(self, username='newuser', email='new@example.com', password='Password123!',
                first_name='New', last_name='User'):
        """Register a new user."""
        return self._client.post(
            '/api/auth/register',
            json={
                'username': username,
                'email': email,
                'password': password,
                'first_name': first_name,
                'last_name': last_name
            }
        )


@pytest.fixture(scope='function')
def auth(client):
    """Authentication actions for tests."""
    return AuthActions(client)
