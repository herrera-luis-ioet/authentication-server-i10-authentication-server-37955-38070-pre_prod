"""
Authentication Management Component - Security Utilities

This module provides security-related utilities for the authentication service,
including password validation, token generation, and JWT handling.
"""
import re
import secrets
import string
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Union

import jwt
from flask import current_app

from app.extensions import bcrypt


# PUBLIC_INTERFACE
def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password strength based on configured requirements.
    
    Args:
        password (str): The password to validate
        
    Returns:
        Tuple[bool, str]: A tuple containing (is_valid, error_message)
    """
    # Check password length
    min_length = current_app.config.get('PASSWORD_MIN_LENGTH', 8)
    max_length = current_app.config.get('PASSWORD_MAX_LENGTH', 128)
    
    if len(password) < min_length:
        return False, f"Password must be at least {min_length} characters long"
    
    if len(password) > max_length:
        return False, f"Password cannot exceed {max_length} characters"
    
    # Check password complexity
    complexity_regex = current_app.config.get(
        'PASSWORD_COMPLEXITY_REGEX',
        r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]'
    )
    
    if not re.search(complexity_regex, password):
        return False, "Password must include uppercase, lowercase, number, and special character"
    
    return True, ""


# PUBLIC_INTERFACE
def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    
    Args:
        password (str): The plain text password to hash
        
    Returns:
        str: The hashed password
    """
    return bcrypt.generate_password_hash(password).decode('utf-8')


# PUBLIC_INTERFACE
def check_password(hashed_password: str, password: str) -> bool:
    """
    Verify a password against a hash.
    
    Args:
        hashed_password (str): The hashed password to check against
        password (str): The plain text password to verify
        
    Returns:
        bool: True if the password matches, False otherwise
    """
    return bcrypt.check_password_hash(hashed_password, password)


# PUBLIC_INTERFACE
def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.
    
    Args:
        length (int, optional): The length of the token. Defaults to 32.
        
    Returns:
        str: A secure random token
    """
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


# PUBLIC_INTERFACE
def generate_jwt_token(
    user_id: int,
    token_type: str = "access",
    expires_delta: Optional[timedelta] = None,
    fresh: bool = False,
    additional_claims: Optional[Dict] = None
) -> str:
    """
    Generate a JWT token for a user.
    
    Args:
        user_id (int): The ID of the user
        token_type (str, optional): The type of token ("access" or "refresh"). Defaults to "access".
        expires_delta (Optional[timedelta], optional): Custom expiration time. 
            Defaults to None (uses config values).
        fresh (bool, optional): Whether the token is fresh. Defaults to False.
        additional_claims (Optional[Dict], optional): Additional claims to include in the token.
            Defaults to None.
            
    Returns:
        str: The encoded JWT token
    """
    now = datetime.utcnow()
    
    # Set token expiration based on type if not provided
    if expires_delta is None:
        if token_type == "access":
            expires_delta = current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', timedelta(hours=1))
        else:
            expires_delta = current_app.config.get('JWT_REFRESH_TOKEN_EXPIRES', timedelta(days=30))
    
    # Base payload
    payload = {
        'iat': now,
        'nbf': now,
        'jti': generate_secure_token(24),
        'exp': now + expires_delta,
        'sub': user_id,
        'type': token_type,
        'fresh': fresh
    }
    
    # Add additional claims if provided
    if additional_claims:
        payload.update(additional_claims)
    
    # Encode the token
    return jwt.encode(
        payload,
        current_app.config['JWT_SECRET_KEY'],
        algorithm='HS256'
    )


# PUBLIC_INTERFACE
def decode_jwt_token(token: str) -> Union[Dict, None]:
    """
    Decode and validate a JWT token.
    
    Args:
        token (str): The JWT token to decode
        
    Returns:
        Union[Dict, None]: The decoded token payload or None if invalid
    """
    try:
        return jwt.decode(
            token,
            current_app.config['JWT_SECRET_KEY'],
            algorithms=['HS256']
        )
    except jwt.PyJWTError:
        return None


# PUBLIC_INTERFACE
def is_token_expired(token: str) -> bool:
    """
    Check if a JWT token is expired.
    
    Args:
        token (str): The JWT token to check
        
    Returns:
        bool: True if the token is expired, False otherwise
    """
    try:
        payload = jwt.decode(
            token,
            current_app.config['JWT_SECRET_KEY'],
            algorithms=['HS256'],
            options={"verify_exp": False}
        )
        now = datetime.utcnow().timestamp()
        return payload.get('exp', 0) < now
    except jwt.PyJWTError:
        return True


# PUBLIC_INTERFACE
def sanitize_input(input_str: str) -> str:
    """
    Sanitize user input to prevent common security issues.
    
    Args:
        input_str (str): The input string to sanitize
        
    Returns:
        str: The sanitized string
    """
    # Basic sanitization - remove control characters and trim
    if not input_str:
        return ""
    
    # Remove control characters
    sanitized = ''.join(c for c in input_str if c.isprintable())
    
    # Trim whitespace
    return sanitized.strip()