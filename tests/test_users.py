"""
Authentication Management Component - User Management API Tests

This module contains tests for the user management API endpoints.
"""
import json
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from app.models.user import User
from app.models.token import Token, TokenType


def test_get_profile_success(client, test_user, auth_headers):
    """Test successful profile retrieval."""
    response = client.get(
        '/api/users/profile',
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'user' in data
    assert data['user']['username'] == test_user.username
    assert data['user']['email'] == test_user.email
    assert data['user']['first_name'] == test_user.first_name
    assert data['user']['last_name'] == test_user.last_name


def test_get_profile_no_auth(client):
    """Test profile retrieval without authentication."""
    response = client.get('/api/users/profile')
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data


def test_update_profile_success(client, test_user, auth_headers):
    """Test successful profile update."""
    response = client.put(
        '/api/users/profile',
        headers=auth_headers,
        json={
            'first_name': 'Updated',
            'last_name': 'Name'
        }
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'message' in data
    assert 'Profile updated successfully' in data['message']
    assert 'user' in data
    assert data['user']['first_name'] == 'Updated'
    assert data['user']['last_name'] == 'Name'
    
    # Verify that the user was updated in the database
    user = User.find_by_id(test_user.id)
    assert user.first_name == 'Updated'
    assert user.last_name == 'Name'


def test_update_profile_partial(client, test_user, auth_headers):
    """Test partial profile update."""
    # Update only first name
    response = client.put(
        '/api/users/profile',
        headers=auth_headers,
        json={
            'first_name': 'Updated'
        }
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['user']['first_name'] == 'Updated'
    assert data['user']['last_name'] == test_user.last_name
    
    # Update only last name
    response = client.put(
        '/api/users/profile',
        headers=auth_headers,
        json={
            'last_name': 'Name'
        }
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['user']['first_name'] == 'Updated'
    assert data['user']['last_name'] == 'Name'


def test_update_profile_no_auth(client):
    """Test profile update without authentication."""
    response = client.put(
        '/api/users/profile',
        json={
            'first_name': 'Updated',
            'last_name': 'Name'
        }
    )
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data


def test_change_password_success(client, test_user, auth_headers):
    """Test successful password change."""
    response = client.post(
        '/api/users/change-password',
        headers=auth_headers,
        json={
            'current_password': 'Password123!',
            'new_password': 'NewPassword123!'
        }
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'message' in data
    assert 'Password changed successfully' in data['message']
    
    # Verify that the password was changed
    user = User.find_by_id(test_user.id)
    assert user.verify_password('NewPassword123!')
    assert not user.verify_password('Password123!')


def test_change_password_incorrect_current(client, test_user, auth_headers):
    """Test password change with incorrect current password."""
    response = client.post(
        '/api/users/change-password',
        headers=auth_headers,
        json={
            'current_password': 'WrongPassword123!',
            'new_password': 'NewPassword123!'
        }
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Current password is incorrect' in data['error']
    
    # Verify that the password was not changed
    user = User.find_by_id(test_user.id)
    assert user.verify_password('Password123!')
    assert not user.verify_password('NewPassword123!')


def test_change_password_weak_new(client, test_user, auth_headers):
    """Test password change with a weak new password."""
    response = client.post(
        '/api/users/change-password',
        headers=auth_headers,
        json={
            'current_password': 'Password123!',
            'new_password': 'weak'
        }
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    
    # Verify that the password was not changed
    user = User.find_by_id(test_user.id)
    assert user.verify_password('Password123!')
    assert not user.verify_password('weak')


def test_change_password_missing_fields(client, auth_headers):
    """Test password change with missing fields."""
    response = client.post(
        '/api/users/change-password',
        headers=auth_headers,
        json={
            'current_password': 'Password123!'
            # Missing new_password
        }
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Missing required fields' in data['error']


def test_change_password_no_auth(client):
    """Test password change without authentication."""
    response = client.post(
        '/api/users/change-password',
        json={
            'current_password': 'Password123!',
            'new_password': 'NewPassword123!'
        }
    )
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data


def test_generate_api_key_success(client, test_user, auth_headers):
    """Test successful API key generation."""
    response = client.post(
        '/api/users/api-keys',
        headers=auth_headers,
        json={
            'expires_in_days': 30
        }
    )
    
    assert response.status_code == 201
    data = json.loads(response.data)
    assert 'message' in data
    assert 'API key generated successfully' in data['message']
    assert 'api_key' in data
    assert 'expires_at' in data
    
    # Verify that the API key was created in the database
    token = Token.find_by_token(data['api_key'])
    assert token is not None
    assert token.token_type == TokenType.API_KEY
    assert token.user_id == test_user.id
    assert not token.is_revoked


def test_generate_api_key_no_expiration(client, test_user, auth_headers):
    """Test API key generation without specifying expiration."""
    response = client.post(
        '/api/users/api-keys',
        headers=auth_headers
    )
    
    assert response.status_code == 201
    data = json.loads(response.data)
    assert 'api_key' in data
    assert 'expires_at' in data


def test_generate_api_key_no_auth(client):
    """Test API key generation without authentication."""
    response = client.post('/api/users/api-keys')
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data


def test_revoke_api_key_success(client, test_user, api_key, auth_headers):
    """Test successful API key revocation."""
    response = client.delete(
        f'/api/users/api-keys/{api_key.token}',
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'message' in data
    assert 'API key revoked successfully' in data['message']
    
    # Verify that the API key was revoked in the database
    token = Token.find_by_token(api_key.token)
    assert token is not None
    assert token.is_revoked


def test_revoke_api_key_nonexistent(client, test_user, auth_headers):
    """Test revocation of a nonexistent API key."""
    response = client.delete(
        '/api/users/api-keys/nonexistent_key',
        headers=auth_headers
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Failed to revoke API key' in data['error']


def test_revoke_api_key_no_auth(client, api_key):
    """Test API key revocation without authentication."""
    response = client.delete(f'/api/users/api-keys/{api_key.token}')
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data


def test_revoke_api_key_wrong_user(client, api_key, admin_user, admin_auth_headers):
    """Test API key revocation by a different user."""
    response = client.delete(
        f'/api/users/api-keys/{api_key.token}',
        headers=admin_auth_headers
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Failed to revoke API key' in data['error']
    
    # Verify that the API key was not revoked
    token = Token.find_by_token(api_key.token)
    assert token is not None
    assert not token.is_revoked