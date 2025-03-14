"""
Authentication Management Component - Authentication Service

This module provides authentication-related services for the application,
including user registration, login, logout, password reset, etc.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Union

from flask import current_app, url_for
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models.token import Token, TokenType
from app.models.user import User, UserStatus
from app.services.email_service import EmailService
from app.utils.security import (
    generate_jwt_token,
    generate_secure_token,
    validate_password_strength
)

logger = logging.getLogger(__name__)


class AuthService:
    """Service for handling authentication-related operations."""
    
    # PUBLIC_INTERFACE
    @classmethod
    def register_user(
        cls,
        username: str,
        email: str,
        password: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        send_verification: bool = True,
        verification_url_pattern: Optional[str] = None
    ) -> Tuple[bool, Union[User, str]]:
        """
        Register a new user.
        
        Args:
            username (str): The username for the new user
            email (str): The email address for the new user
            password (str): The password for the new user
            first_name (Optional[str], optional): The user's first name. Defaults to None.
            last_name (Optional[str], optional): The user's last name. Defaults to None.
            send_verification (bool, optional): Whether to send a verification email. Defaults to True.
            verification_url_pattern (Optional[str], optional): URL pattern for verification.
                Should contain '{token}' placeholder. Defaults to None.
                
        Returns:
            Tuple[bool, Union[User, str]]: A tuple containing (success, user_or_error_message)
        """
        # Validate password strength
        is_valid, error_message = validate_password_strength(password)
        if not is_valid:
            return False, error_message
        
        # Check if username or email already exists
        if User.find_by_username(username):
            return False, "Username already exists"
        
        if User.find_by_email(email):
            return False, "Email already exists"
        
        # Create new user
        user = User(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            status=UserStatus.PENDING_VERIFICATION
        )
        user.password = password
        
        try:
            # Save user to database
            db.session.add(user)
            db.session.commit()
            
            # Send verification email if requested
            if send_verification:
                cls._send_verification_email(user, verification_url_pattern)
                
            logger.info(f"User registered successfully: {username}")
            return True, user
        except IntegrityError as e:
            db.session.rollback()
            logger.error(f"Failed to register user: {str(e)}")
            return False, "Database error occurred during registration"
        except Exception as e:
            db.session.rollback()
            logger.error(f"Unexpected error during registration: {str(e)}")
            return False, "An unexpected error occurred"
    
    # PUBLIC_INTERFACE
    @classmethod
    def login_user(cls, username_or_email: str, password: str) -> Tuple[bool, Union[Dict, str]]:
        """
        Authenticate a user and generate access and refresh tokens.
        
        Args:
            username_or_email (str): The username or email of the user
            password (str): The user's password
            
        Returns:
            Tuple[bool, Union[Dict, str]]: A tuple containing (success, tokens_or_error_message)
        """
        # Find user by username or email
        user = User.find_by_username(username_or_email)
        if not user:
            user = User.find_by_email(username_or_email)
            
        if not user:
            return False, "Invalid username or email"
        
        # Check if account is locked or inactive
        if user.status == UserStatus.LOCKED:
            return False, "Account is locked due to too many failed login attempts"
        
        if user.status == UserStatus.INACTIVE or user.status == UserStatus.SUSPENDED:
            return False, "Account is inactive or suspended"
        
        # Verify password
        if not user.verify_password(password):
            user.update_login_failure()
            db.session.commit()
            
            if user.status == UserStatus.LOCKED:
                # Send account locked email
                cls._send_account_locked_email(user)
                return False, "Account has been locked due to too many failed login attempts"
            
            return False, "Invalid password"
        
        # Update login success
        user.update_login_success()
        db.session.commit()
        
        # Generate tokens
        access_token = generate_jwt_token(user.id, "access", fresh=True)
        refresh_token = generate_jwt_token(user.id, "refresh")
        
        # Store refresh token in database
        token = Token.generate_token(
            user.id,
            TokenType.REFRESH,
            expires_in=current_app.config.get('JWT_REFRESH_TOKEN_EXPIRES')
        )
        db.session.add(token)
        db.session.commit()
        
        logger.info(f"User logged in successfully: {user.username}")
        
        return True, {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": user.to_dict()
        }
    
    # PUBLIC_INTERFACE
    @classmethod
    def logout_user(cls, user_id: int, token_value: Optional[str] = None) -> bool:
        """
        Log out a user by revoking their tokens.
        
        Args:
            user_id (int): The ID of the user to log out
            token_value (Optional[str], optional): The specific refresh token to revoke.
                If None, all refresh tokens for the user will be revoked. Defaults to None.
                
        Returns:
            bool: True if logout was successful, False otherwise
        """
        try:
            if token_value:
                # Revoke specific token
                token = Token.find_by_token(token_value)
                if token and token.user_id == user_id:
                    token.revoke()
                    db.session.commit()
            else:
                # Revoke all refresh tokens for user
                Token.revoke_all_user_tokens(user_id, TokenType.REFRESH)
                
            logger.info(f"User logged out successfully: {user_id}")
            return True
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error during logout: {str(e)}")
            return False
    
    # PUBLIC_INTERFACE
    @classmethod
    def refresh_token(cls, refresh_token: str) -> Tuple[bool, Union[Dict, str]]:
        """
        Generate a new access token using a refresh token.
        
        Args:
            refresh_token (str): The refresh token
            
        Returns:
            Tuple[bool, Union[Dict, str]]: A tuple containing (success, new_tokens_or_error_message)
        """
        # Find token in database
        token = Token.find_valid_token(refresh_token, TokenType.REFRESH)
        
        if not token:
            return False, "Invalid or expired refresh token"
        
        # Get user
        user = User.find_by_id(token.user_id)
        if not user:
            return False, "User not found"
        
        # Check user status
        if user.status != UserStatus.ACTIVE:
            return False, "User account is not active"
        
        # Generate new access token
        access_token = generate_jwt_token(user.id, "access")
        
        logger.info(f"Token refreshed successfully for user: {user.username}")
        
        return True, {
            "access_token": access_token,
            "user": user.to_dict()
        }
    
    # PUBLIC_INTERFACE
    @classmethod
    def verify_email(cls, token_value: str) -> Tuple[bool, str]:
        """
        Verify a user's email using a verification token.
        
        Args:
            token_value (str): The verification token
            
        Returns:
            Tuple[bool, str]: A tuple containing (success, message)
        """
        # Find token in database
        token = Token.find_valid_token(token_value, TokenType.EMAIL_VERIFICATION)
        
        if not token:
            return False, "Invalid or expired verification token"
        
        # Get user
        user = User.find_by_id(token.user_id)
        if not user:
            return False, "User not found"
        
        # Verify email
        user.verify_email()
        
        # Revoke token
        token.revoke()
        
        db.session.commit()
        
        # Send welcome email
        EmailService.send_welcome_email(user.email, user.username)
        
        logger.info(f"Email verified successfully for user: {user.username}")
        
        return True, "Email verified successfully"
    
    # PUBLIC_INTERFACE
    @classmethod
    def request_password_reset(
        cls,
        email: str,
        reset_url_pattern: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Request a password reset for a user.
        
        Args:
            email (str): The email address of the user
            reset_url_pattern (Optional[str], optional): URL pattern for reset.
                Should contain '{token}' placeholder. Defaults to None.
                
        Returns:
            Tuple[bool, str]: A tuple containing (success, message)
        """
        # Find user by email
        user = User.find_by_email(email)
        
        # Always return success to prevent email enumeration
        if not user:
            logger.info(f"Password reset requested for non-existent email: {email}")
            return True, "If your email is registered, you will receive a password reset link"
        
        # Generate reset token
        token = Token.generate_token(
            user.id,
            TokenType.RESET_PASSWORD,
            expires_in=timedelta(hours=1)
        )
        
        db.session.add(token)
        db.session.commit()
        
        # Send password reset email
        if reset_url_pattern:
            reset_url = reset_url_pattern.format(token=token.token)
        else:
            reset_url = f"/reset-password/{token.token}"
            
        EmailService.send_password_reset_email(user.email, user.username, reset_url)
        
        logger.info(f"Password reset requested for user: {user.username}")
        
        return True, "If your email is registered, you will receive a password reset link"
    
    # PUBLIC_INTERFACE
    @classmethod
    def reset_password(cls, token_value: str, new_password: str) -> Tuple[bool, str]:
        """
        Reset a user's password using a reset token.
        
        Args:
            token_value (str): The reset token
            new_password (str): The new password
            
        Returns:
            Tuple[bool, str]: A tuple containing (success, message)
        """
        # Validate password strength
        is_valid, error_message = validate_password_strength(new_password)
        if not is_valid:
            return False, error_message
        
        # Find token in database
        token = Token.find_valid_token(token_value, TokenType.RESET_PASSWORD)
        
        if not token:
            return False, "Invalid or expired reset token"
        
        # Get user
        user = User.find_by_id(token.user_id)
        if not user:
            return False, "User not found"
        
        # Change password
        user.change_password(new_password)
        
        # If account was locked, unlock it
        if user.status == UserStatus.LOCKED:
            user.unlock_account()
        
        # Revoke token and all refresh tokens
        token.revoke()
        Token.revoke_all_user_tokens(user.id, TokenType.REFRESH)
        
        db.session.commit()
        
        logger.info(f"Password reset successfully for user: {user.username}")
        
        return True, "Password reset successfully"
    
    # PUBLIC_INTERFACE
    @classmethod
    def change_password(
        cls,
        user_id: int,
        current_password: str,
        new_password: str
    ) -> Tuple[bool, str]:
        """
        Change a user's password.
        
        Args:
            user_id (int): The ID of the user
            current_password (str): The current password
            new_password (str): The new password
            
        Returns:
            Tuple[bool, str]: A tuple containing (success, message)
        """
        # Find user
        user = User.find_by_id(user_id)
        if not user:
            return False, "User not found"
        
        # Verify current password
        if not user.verify_password(current_password):
            return False, "Current password is incorrect"
        
        # Validate new password strength
        is_valid, error_message = validate_password_strength(new_password)
        if not is_valid:
            return False, error_message
        
        # Change password
        user.change_password(new_password)
        
        # Revoke all refresh tokens
        Token.revoke_all_user_tokens(user.id, TokenType.REFRESH)
        
        db.session.commit()
        
        logger.info(f"Password changed successfully for user: {user.username}")
        
        return True, "Password changed successfully"
    
    # PUBLIC_INTERFACE
    @classmethod
    def update_profile(
        cls,
        user_id: int,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None
    ) -> Tuple[bool, Union[User, str]]:
        """
        Update a user's profile information.
        
        Args:
            user_id (int): The ID of the user
            first_name (Optional[str], optional): The new first name. Defaults to None.
            last_name (Optional[str], optional): The new last name. Defaults to None.
            
        Returns:
            Tuple[bool, Union[User, str]]: A tuple containing (success, user_or_error_message)
        """
        # Find user
        user = User.find_by_id(user_id)
        if not user:
            return False, "User not found"
        
        # Update fields if provided
        if first_name is not None:
            user.first_name = first_name
            
        if last_name is not None:
            user.last_name = last_name
        
        try:
            db.session.commit()
            logger.info(f"Profile updated successfully for user: {user.username}")
            return True, user
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating profile: {str(e)}")
            return False, "An error occurred while updating profile"
    
    # PUBLIC_INTERFACE
    @classmethod
    def generate_api_key(cls, user_id: int, expires_in: Optional[timedelta] = None) -> Tuple[bool, Union[Dict, str]]:
        """
        Generate an API key for a user.
        
        Args:
            user_id (int): The ID of the user
            expires_in (Optional[timedelta], optional): The expiration time for the API key.
                Defaults to None (uses config value).
                
        Returns:
            Tuple[bool, Union[Dict, str]]: A tuple containing (success, api_key_info_or_error_message)
        """
        # Find user
        user = User.find_by_id(user_id)
        if not user:
            return False, "User not found"
        
        # Check user status
        if user.status != UserStatus.ACTIVE:
            return False, "User account is not active"
        
        # Set default expiration if not provided
        if expires_in is None:
            expires_in = timedelta(days=365)  # Default to 1 year
        
        # Generate token
        token = Token.generate_token(user.id, TokenType.API_KEY, expires_in)
        
        db.session.add(token)
        db.session.commit()
        
        logger.info(f"API key generated successfully for user: {user.username}")
        
        return True, {
            "api_key": token.token,
            "expires_at": token.expires_at.isoformat()
        }
    
    # PUBLIC_INTERFACE
    @classmethod
    def revoke_api_key(cls, user_id: int, api_key: str) -> bool:
        """
        Revoke an API key.
        
        Args:
            user_id (int): The ID of the user
            api_key (str): The API key to revoke
            
        Returns:
            bool: True if the API key was revoked successfully, False otherwise
        """
        # Find token
        token = Token.find_by_token(api_key)
        
        if not token or token.token_type != TokenType.API_KEY or token.user_id != user_id:
            return False
        
        # Revoke token
        token.revoke()
        db.session.commit()
        
        logger.info(f"API key revoked successfully for user ID: {user_id}")
        
        return True
    
    @classmethod
    def _send_verification_email(cls, user: User, url_pattern: Optional[str] = None) -> bool:
        """
        Send a verification email to a user.
        
        Args:
            user (User): The user to send the verification email to
            url_pattern (Optional[str], optional): URL pattern for verification.
                Should contain '{token}' placeholder. Defaults to None.
                
        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        # Generate verification token
        token = Token.generate_token(
            user.id,
            TokenType.EMAIL_VERIFICATION,
            expires_in=timedelta(hours=24)
        )
        
        db.session.add(token)
        db.session.commit()
        
        # Create verification URL
        if url_pattern:
            verification_url = url_pattern.format(token=token.token)
        else:
            verification_url = f"/verify-email/{token.token}"
            
        # Send email
        return EmailService.send_verification_email(
            user.email,
            user.username,
            verification_url
        )
    
    @classmethod
    def _send_account_locked_email(cls, user: User, url_pattern: Optional[str] = None) -> bool:
        """
        Send an account locked email to a user.
        
        Args:
            user (User): The user to send the email to
            url_pattern (Optional[str], optional): URL pattern for password reset.
                Should contain '{token}' placeholder. Defaults to None.
                
        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        # Generate reset token
        token = Token.generate_token(
            user.id,
            TokenType.RESET_PASSWORD,
            expires_in=timedelta(hours=1)
        )
        
        db.session.add(token)
        db.session.commit()
        
        # Create reset URL
        if url_pattern:
            reset_url = url_pattern.format(token=token.token)
        else:
            reset_url = f"/reset-password/{token.token}"
            
        # Get lockout duration in minutes
        lockout_minutes = current_app.config.get('ACCOUNT_LOCKOUT_DURATION', timedelta(minutes=15)).total_seconds() // 60
        
        # Send email
        return EmailService.send_account_locked_email(
            user.email,
            user.username,
            reset_url,
            int(lockout_minutes)
        )