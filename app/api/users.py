"""
User management API routes.

This module defines the API routes for user management, including profile management,
password changes, and API key management.
"""
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import timedelta
from app.services.auth_service import AuthService
from app.models.user import User
from app.utils.security import validate_password_strength, sanitize_input
from app.extensions import limiter

# Create blueprint
users_bp = Blueprint('users', __name__, url_prefix='/api/users')

# Apply rate limiting to sensitive endpoints
users_routes_limiter = limiter.shared_limit(
    "10 per minute", scope="users_routes"
)


# PUBLIC_INTERFACE
@users_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """
    Get the current user's profile.
    
    Request headers:
        Authorization: Bearer <access_token>
    
    Returns:
        JSON response with user profile data or error message
    """
    user_id = get_jwt_identity()
    
    user = User.find_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({"user": user.to_dict()}), 200


# PUBLIC_INTERFACE
@users_bp.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    """
    Update the current user's profile.
    
    Request headers:
        Authorization: Bearer <access_token>
    
    Request body:
    {
        "first_name": "string" (optional),
        "last_name": "string" (optional)
    }
    
    Returns:
        JSON response with updated user profile or error message
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    
    # Sanitize inputs
    first_name = sanitize_input(data.get('first_name', '')) or None
    last_name = sanitize_input(data.get('last_name', '')) or None
    
    # Update profile
    success, result = AuthService.update_profile(
        user_id=user_id,
        first_name=first_name,
        last_name=last_name
    )
    
    if success:
        return jsonify({
            "message": "Profile updated successfully",
            "user": result.to_dict()
        }), 200
    else:
        return jsonify({"error": result}), 400


# PUBLIC_INTERFACE
@users_bp.route('/change-password', methods=['POST'])
@jwt_required()
@users_routes_limiter
def change_password():
    """
    Change the current user's password.
    
    Request headers:
        Authorization: Bearer <access_token>
    
    Request body:
    {
        "current_password": "string",
        "new_password": "string"
    }
    
    Returns:
        JSON response with success message or error
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    
    # Validate required fields
    if not all(key in data for key in ['current_password', 'new_password']):
        return jsonify({"error": "Missing required fields"}), 400
    
    current_password = data['current_password']
    new_password = data['new_password']
    
    # Validate password strength
    is_valid, message = validate_password_strength(new_password)
    if not is_valid:
        return jsonify({"error": message}), 400
    
    # Change password
    success, message = AuthService.change_password(
        user_id=user_id,
        current_password=current_password,
        new_password=new_password
    )
    
    if success:
        return jsonify({"message": message}), 200
    else:
        return jsonify({"error": message}), 400


# PUBLIC_INTERFACE
@users_bp.route('/api-keys', methods=['POST'])
@jwt_required()
def generate_api_key():
    """
    Generate a new API key for the current user.
    
    Request headers:
        Authorization: Bearer <access_token>
    
    Request body:
    {
        "expires_in_days": integer (optional)
    }
    
    Returns:
        JSON response with API key or error message
    """
    user_id = get_jwt_identity()
    data = request.get_json() or {}
    
    # Set expiration time
    expires_in = None
    if 'expires_in_days' in data and isinstance(data['expires_in_days'], int):
        expires_in = timedelta(days=data['expires_in_days'])
    
    # Generate API key
    success, result = AuthService.generate_api_key(
        user_id=user_id,
        expires_in=expires_in
    )
    
    if success:
        return jsonify({
            "message": "API key generated successfully",
            "api_key": result.get("api_key"),
            "expires_at": result.get("expires_at")
        }), 201
    else:
        return jsonify({"error": result}), 400


# PUBLIC_INTERFACE
@users_bp.route('/api-keys/<api_key>', methods=['DELETE'])
@jwt_required()
def revoke_api_key(api_key):
    """
    Revoke an API key.
    
    Request headers:
        Authorization: Bearer <access_token>
    
    Path parameters:
        api_key: The API key to revoke
    
    Returns:
        JSON response with success message or error
    """
    user_id = get_jwt_identity()
    
    # Revoke API key
    success = AuthService.revoke_api_key(
        user_id=user_id,
        api_key=api_key
    )
    
    if success:
        return jsonify({"message": "API key revoked successfully"}), 200
    else:
        return jsonify({"error": "Failed to revoke API key"}), 400