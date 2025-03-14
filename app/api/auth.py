"""
Authentication API routes.

This module defines the API routes for user authentication, including registration,
login, logout, token refresh, email verification, and password reset.
"""
from flask import Blueprint, request, jsonify, current_app, url_for
from flask_jwt_extended import (
    jwt_required, get_jwt_identity, get_jwt, create_access_token
)
from app.services.auth_service import AuthService
from app.utils.security import validate_password_strength, sanitize_input
from app.extensions import limiter

# Create blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# Apply rate limiting to sensitive endpoints
auth_routes_limiter = limiter.shared_limit(
    "5 per minute", scope="auth_routes"
)


# PUBLIC_INTERFACE
@auth_bp.route('/register', methods=['POST'])
@auth_routes_limiter
def register():
    """
    Register a new user.
    
    Request body:
    {
        "username": "string",
        "email": "string",
        "password": "string",
        "first_name": "string" (optional),
        "last_name": "string" (optional)
    }
    
    Returns:
        JSON response with user data or error message
    """
    data = request.get_json()
    
    # Validate required fields
    if not all(key in data for key in ['username', 'email', 'password']):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Sanitize inputs
    username = sanitize_input(data['username'])
    email = sanitize_input(data['email'])
    password = data['password']  # Don't sanitize password
    first_name = sanitize_input(data.get('first_name', '')) or None
    last_name = sanitize_input(data.get('last_name', '')) or None
    
    # Validate password strength
    is_valid, message = validate_password_strength(password)
    if not is_valid:
        return jsonify({"error": message}), 400
    
    # Generate verification URL
    verification_url_pattern = f"{request.host_url.rstrip('/')}/api/auth/verify-email/{{token}}"
    
    # Register user
    success, result = AuthService.register_user(
        username=username,
        email=email,
        password=password,
        first_name=first_name,
        last_name=last_name,
        send_verification=True,
        verification_url_pattern=verification_url_pattern
    )
    
    if success:
        user_dict = result.to_dict()
        return jsonify({
            "message": "User registered successfully. Please check your email to verify your account.",
            "user": user_dict
        }), 201
    else:
        return jsonify({"error": result}), 400


# PUBLIC_INTERFACE
@auth_bp.route('/login', methods=['POST'])
@auth_routes_limiter
def login():
    """
    Authenticate a user and generate access and refresh tokens.
    
    Request body:
    {
        "username_or_email": "string",
        "password": "string"
    }
    
    Returns:
        JSON response with tokens or error message
    """
    data = request.get_json()
    
    # Validate required fields
    if not all(key in data for key in ['username_or_email', 'password']):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Sanitize inputs
    username_or_email = sanitize_input(data['username_or_email'])
    password = data['password']  # Don't sanitize password
    
    # Login user
    success, result = AuthService.login_user(
        username_or_email=username_or_email,
        password=password
    )
    
    if success:
        return jsonify({
            "message": "Login successful",
            "access_token": result.get("access_token"),
            "refresh_token": result.get("refresh_token"),
            "user_id": result.get("user_id")
        }), 200
    else:
        return jsonify({"error": result}), 401


# PUBLIC_INTERFACE
@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    Log out a user by revoking their tokens.
    
    Request headers:
        Authorization: Bearer <access_token>
    
    Returns:
        JSON response with success message or error
    """
    user_id = get_jwt_identity()
    token_data = get_jwt()
    token_value = token_data.get('jti')
    
    success = AuthService.logout_user(user_id=user_id, token_value=token_value)
    
    if success:
        return jsonify({"message": "Logout successful"}), 200
    else:
        return jsonify({"error": "Logout failed"}), 400


# PUBLIC_INTERFACE
@auth_bp.route('/refresh', methods=['POST'])
def refresh_token():
    """
    Generate a new access token using a refresh token.
    
    Request body:
    {
        "refresh_token": "string"
    }
    
    Returns:
        JSON response with new access token or error message
    """
    data = request.get_json()
    
    # Validate required fields
    if 'refresh_token' not in data:
        return jsonify({"error": "Missing refresh token"}), 400
    
    refresh_token = data['refresh_token']
    
    # Refresh token
    success, result = AuthService.refresh_token(refresh_token=refresh_token)
    
    if success:
        return jsonify({
            "message": "Token refreshed successfully",
            "access_token": result.get("access_token")
        }), 200
    else:
        return jsonify({"error": result}), 401


# PUBLIC_INTERFACE
@auth_bp.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    """
    Verify a user's email using a verification token.
    
    Path parameters:
        token: The email verification token
    
    Returns:
        JSON response with success message or error
    """
    success, message = AuthService.verify_email(token_value=token)
    
    if success:
        return jsonify({"message": message}), 200
    else:
        return jsonify({"error": message}), 400


# PUBLIC_INTERFACE
@auth_bp.route('/request-password-reset', methods=['POST'])
@auth_routes_limiter
def request_password_reset():
    """
    Request a password reset for a user.
    
    Request body:
    {
        "email": "string"
    }
    
    Returns:
        JSON response with success message or error
    """
    data = request.get_json()
    
    # Validate required fields
    if 'email' not in data:
        return jsonify({"error": "Missing email"}), 400
    
    email = sanitize_input(data['email'])
    
    # Generate reset URL
    reset_url_pattern = f"{request.host_url.rstrip('/')}/api/auth/reset-password/{{token}}"
    
    # Request password reset
    success, message = AuthService.request_password_reset(
        email=email,
        reset_url_pattern=reset_url_pattern
    )
    
    # Always return success to prevent email enumeration
    return jsonify({
        "message": "If the email exists, a password reset link has been sent."
    }), 200


# PUBLIC_INTERFACE
@auth_bp.route('/reset-password', methods=['POST'])
@auth_routes_limiter
def reset_password():
    """
    Reset a user's password using a reset token.
    
    Request body:
    {
        "token": "string",
        "new_password": "string"
    }
    
    Returns:
        JSON response with success message or error
    """
    data = request.get_json()
    
    # Validate required fields
    if not all(key in data for key in ['token', 'new_password']):
        return jsonify({"error": "Missing required fields"}), 400
    
    token = data['token']
    new_password = data['new_password']
    
    # Validate password strength
    is_valid, message = validate_password_strength(new_password)
    if not is_valid:
        return jsonify({"error": message}), 400
    
    # Reset password
    success, message = AuthService.reset_password(
        token_value=token,
        new_password=new_password
    )
    
    if success:
        return jsonify({"message": message}), 200
    else:
        return jsonify({"error": message}), 400