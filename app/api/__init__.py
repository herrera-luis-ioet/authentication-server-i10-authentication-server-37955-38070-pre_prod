"""
API Blueprint initialization module.

This module initializes and exports the API blueprints for the authentication system.
"""
from flask import Blueprint

# Import blueprints
from app.api.auth import auth_bp
from app.api.users import users_bp

# Export blueprints for registration with the Flask app
__all__ = ["auth_bp", "users_bp"]