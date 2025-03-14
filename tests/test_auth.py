"""
Authentication Management Component - Authentication API Tests

This module contains tests for the authentication API endpoints.
"""
import json
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from app.models.user import User, UserStatus
from app.models.token import Token, TokenType


def test_register_success(client, session):
    """Test successful user registration."""
    response = client.post(
        '/api/auth/register',
        json={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'Password123!',
            'first_name': 'New',
            'last_name': 'User'
        }
    )
    
    assert response.status_code == 201
    data = json.loads(response.data)
    assert 'message' in data
    assert 'user' in data
    assert data['user']['username'] == 'newuser'
    assert data['user']['email'] == 'newuser@example.com'
    assert data['user']['first_name'] == 'New'
    assert data['user']['last_name'] == 'User'
    
    # Verify user was created in the database
    user = User.find_by_username('newuser')
    assert user is not None
    assert user.email == 'newuser@example.com'
    assert user.status == UserStatus.PENDING_VERIFICATION
    assert user.email_verified is False


def test_register_missing_fields(client):
    """Test registration with missing required fields."""
    response = client.post(
        '/api/auth/register',
        json={
            'username': 'newuser',
            'email': 'newuser@example.com'
            # Missing password
        }
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Missing required fields' in data['error']


def test_register_weak_password(client):
    """Test registration with a weak password."""
    response = client.post(
        '/api/auth/register',
        json={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'weak',  # Weak password
            'first_name': 'New',
            'last_name': 'User'
        }
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data


def test_register_existing_username(client, test_user):
    """Test registration with an existing username."""
    response = client.post(
        '/api/auth/register',
        json={
            'username': 'testuser',  # Existing username
            'email': 'different@example.com',
            'password': 'Password123!',
            'first_name': 'New',
            'last_name': 'User'
        }
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Username already exists' in data['error']


def test_register_existing_email(client, test_user):
    """Test registration with an existing email."""
    response = client.post(
        '/api/auth/register',
        json={
            'username': 'different',
            'email': 'test@example.com',  # Existing email
            'password': 'Password123!',
            'first_name': 'New',
            'last_name': 'User'
        }
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Email already exists' in data['error']


def test_login_success(client, test_user):
    """Test successful login with username."""
    response = client.post(
        '/api/auth/login',
        json={
            'username_or_email': 'testuser',
            'password': 'Password123!'
        }
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'access_token' in data
    assert 'refresh_token' in data
    assert 'user_id' in data
    assert 'message' in data
    assert 'Login successful' in data['message']


def test_login_with_email(client, test_user):
    """Test successful login with email."""
    response = client.post(
        '/api/auth/login',
        json={
            'username_or_email': 'test@example.com',
            'password': 'Password123!'
        }
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'access_token' in data
    assert 'refresh_token' in data


def test_login_invalid_credentials(client, test_user):
    """Test login with invalid credentials."""
    response = client.post(
        '/api/auth/login',
        json={
            'username_or_email': 'testuser',
            'password': 'WrongPassword123!'
        }
    )
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Invalid password' in data['error']


def test_login_nonexistent_user(client):
    """Test login with a nonexistent user."""
    response = client.post(
        '/api/auth/login',
        json={
            'username_or_email': 'nonexistent',
            'password': 'Password123!'
        }
    )
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Invalid username or email' in data['error']


def test_login_locked_account(client, locked_user):
    """Test login with a locked account."""
    response = client.post(
        '/api/auth/login',
        json={
            'username_or_email': 'locked',
            'password': 'Password123!'
        }
    )
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Account is locked' in data['error']


def test_login_unverified_account(client, unverified_user):
    """Test login with an unverified account."""
    # Unverified users should still be able to log in
    response = client.post(
        '/api/auth/login',
        json={
            'username_or_email': 'unverified',
            'password': 'Password123!'
        }
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'access_token' in data
    assert 'refresh_token' in data


def test_login_account_lockout(client, session):
    """Test account lockout after multiple failed login attempts."""
    # Create a new user for this test
    user = User(
        username='lockout_test',
        email='lockout@example.com',
        status=UserStatus.ACTIVE,
        email_verified=True
    )
    user.password = 'Password123!'
    session.add(user)
    session.commit()
    
    # Attempt login with incorrect password multiple times
    for i in range(5):
        response = client.post(
            '/api/auth/login',
            json={
                'username_or_email': 'lockout_test',
                'password': 'WrongPassword123!'
            }
        )
        assert response.status_code == 401
    
    # Check that the account is now locked
    user = User.find_by_username('lockout_test')
    assert user.status == UserStatus.LOCKED
    assert user.failed_login_attempts == 5
    
    # Try to login with correct password
    response = client.post(
        '/api/auth/login',
        json={
            'username_or_email': 'lockout_test',
            'password': 'Password123!'
        }
    )
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Account is locked' in data['error']


def test_logout_success(client, test_user, auth_headers):
    """Test successful logout."""
    response = client.post(
        '/api/auth/logout',
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'message' in data
    assert 'Logout successful' in data['message']


def test_logout_no_token(client):
    """Test logout without a token."""
    response = client.post('/api/auth/logout')
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data


def test_refresh_token_success(client, test_user, refresh_token):
    """Test successful token refresh."""
    response = client.post(
        '/api/auth/refresh',
        json={
            'refresh_token': refresh_token.token
        }
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'access_token' in data
    assert 'message' in data
    assert 'Token refreshed successfully' in data['message']


def test_refresh_token_invalid(client):
    """Test refresh with an invalid token."""
    response = client.post(
        '/api/auth/refresh',
        json={
            'refresh_token': 'invalid_token'
        }
    )
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Invalid or expired refresh token' in data['error']


def test_refresh_token_missing(client):
    """Test refresh without a token."""
    response = client.post(
        '/api/auth/refresh',
        json={}
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Missing refresh token' in data['error']


def test_verify_email_success(client, unverified_user, verification_token):
    """Test successful email verification."""
    response = client.get(f'/api/auth/verify-email/{verification_token.token}')
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'message' in data
    assert 'Email verified successfully' in data['message']
    
    # Check that the user's email is now verified
    user = User.find_by_id(unverified_user.id)
    assert user.email_verified is True
    assert user.status == UserStatus.ACTIVE


def test_verify_email_invalid_token(client):
    """Test email verification with an invalid token."""
    response = client.get('/api/auth/verify-email/invalid_token')
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Invalid or expired verification token' in data['error']


def test_request_password_reset(client, test_user):
    """Test requesting a password reset."""
    with patch('app.services.email_service.EmailService.send_password_reset_email', return_value=True) as mock_send:
        response = client.post(
            '/api/auth/request-password-reset',
            json={
                'email': 'test@example.com'
            }
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'message' in data
        assert 'If the email exists' in data['message']
        
        # Verify that the email service was called
        mock_send.assert_called_once()


def test_request_password_reset_nonexistent_email(client):
    """Test requesting a password reset for a nonexistent email."""
    with patch('app.services.email_service.EmailService.send_password_reset_email', return_value=True) as mock_send:
        response = client.post(
            '/api/auth/request-password-reset',
            json={
                'email': 'nonexistent@example.com'
            }
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'message' in data
        assert 'If the email exists' in data['message']
        
        # Verify that the email service was not called
        mock_send.assert_not_called()


def test_reset_password_success(client, test_user, reset_token):
    """Test successful password reset."""
    response = client.post(
        '/api/auth/reset-password',
        json={
            'token': reset_token.token,
            'new_password': 'NewPassword123!'
        }
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'message' in data
    assert 'Password reset successfully' in data['message']
    
    # Verify that the password was changed
    user = User.find_by_id(test_user.id)
    assert user.verify_password('NewPassword123!')
    assert not user.verify_password('Password123!')


def test_reset_password_invalid_token(client):
    """Test password reset with an invalid token."""
    response = client.post(
        '/api/auth/reset-password',
        json={
            'token': 'invalid_token',
            'new_password': 'NewPassword123!'
        }
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Invalid or expired reset token' in data['error']


def test_reset_password_weak_password(client, reset_token):
    """Test password reset with a weak password."""
    response = client.post(
        '/api/auth/reset-password',
        json={
            'token': reset_token.token,
            'new_password': 'weak'
        }
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data


def test_reset_password_missing_fields(client):
    """Test password reset with missing fields."""
    response = client.post(
        '/api/auth/reset-password',
        json={
            'token': 'some_token'
            # Missing new_password
        }
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Missing required fields' in data['error']