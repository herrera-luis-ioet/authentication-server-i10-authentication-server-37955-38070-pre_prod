"""
Authentication Management Component - Token Model

This module defines the Token model for the authentication service.
"""
from datetime import datetime, timedelta
import enum
import secrets
from typing import Optional
from sqlalchemy.orm import relationship

from app.extensions import db


class TokenType(enum.Enum):
    """Enum for token types."""
    REFRESH = "refresh"
    RESET_PASSWORD = "reset_password"
    EMAIL_VERIFICATION = "email_verification"
    API_KEY = "api_key"


class Token(db.Model):
    """Token model for storing various types of tokens."""
    
    __tablename__ = "tokens"
    
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    token_type = db.Column(db.Enum(TokenType), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_revoked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="tokens")
    
    # PUBLIC_INTERFACE
    def is_expired(self) -> bool:
        """
        Check if the token has expired.
        
        Returns:
            bool: True if the token has expired, False otherwise.
        """
        return datetime.utcnow() > self.expires_at
    
    # PUBLIC_INTERFACE
    def is_valid(self) -> bool:
        """
        Check if the token is valid (not expired and not revoked).
        
        Returns:
            bool: True if the token is valid, False otherwise.
        """
        return not self.is_revoked and not self.is_expired()
    
    # PUBLIC_INTERFACE
    def revoke(self) -> None:
        """
        Revoke the token.
        """
        self.is_revoked = True
        db.session.commit()
    
    # PUBLIC_INTERFACE
    def to_dict(self) -> dict:
        """
        Convert the token object to a dictionary.
        
        Returns:
            dict: Dictionary representation of the token.
        """
        return {
            "id": self.id,
            "token": self.token,
            "token_type": self.token_type.value,
            "user_id": self.user_id,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_revoked": self.is_revoked,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
    
    @classmethod
    def generate_token(cls, user_id: int, token_type: TokenType, expires_in: timedelta = None) -> "Token":
        """
        Generate a new token.
        
        Args:
            user_id (int): The ID of the user the token belongs to.
            token_type (TokenType): The type of token to generate.
            expires_in (timedelta, optional): How long the token should be valid for.
                Defaults to None, which uses a default expiration based on token type.
                
        Returns:
            Token: The newly created token.
        """
        # Set default expiration based on token type if not provided
        if expires_in is None:
            if token_type == TokenType.REFRESH:
                expires_in = timedelta(days=30)
            elif token_type == TokenType.RESET_PASSWORD:
                expires_in = timedelta(hours=24)
            elif token_type == TokenType.EMAIL_VERIFICATION:
                expires_in = timedelta(days=7)
            elif token_type == TokenType.API_KEY:
                expires_in = timedelta(days=365)
            else:
                expires_in = timedelta(hours=1)
        
        # Generate a secure token
        token_value = secrets.token_urlsafe(32)
        
        # Create the token
        token = cls(
            token=token_value,
            token_type=token_type,
            user_id=user_id,
            expires_at=datetime.utcnow() + expires_in
        )
        
        # Save to database
        db.session.add(token)
        db.session.commit()
        
        return token
    
    @classmethod
    def find_by_token(cls, token_value: str) -> Optional["Token"]:
        """
        Find a token by its value.
        
        Args:
            token_value (str): The token value to search for.
            
        Returns:
            Optional[Token]: The token if found, None otherwise.
        """
        return cls.query.filter_by(token=token_value).first()
    
    @classmethod
    def find_valid_token(cls, token_value: str, token_type: TokenType) -> Optional["Token"]:
        """
        Find a valid (not expired, not revoked) token by its value and type.
        
        Args:
            token_value (str): The token value to search for.
            token_type (TokenType): The type of token to search for.
            
        Returns:
            Optional[Token]: The token if found and valid, None otherwise.
        """
        token = cls.query.filter_by(token=token_value, token_type=token_type).first()
        if token and token.is_valid():
            return token
        return None
    
    @classmethod
    def revoke_all_user_tokens(cls, user_id: int, token_type: TokenType = None) -> int:
        """
        Revoke all tokens for a specific user, optionally filtered by token type.
        
        Args:
            user_id (int): The ID of the user whose tokens should be revoked.
            token_type (TokenType, optional): The type of tokens to revoke.
                If None, all token types will be revoked. Defaults to None.
                
        Returns:
            int: The number of tokens revoked.
        """
        query = cls.query.filter_by(user_id=user_id, is_revoked=False)
        
        if token_type:
            query = query.filter_by(token_type=token_type)
        
        tokens = query.all()
        count = 0
        
        for token in tokens:
            token.is_revoked = True
            count += 1
        
        if count > 0:
            db.session.commit()
        
        return count
    
    def __repr__(self) -> str:
        """
        String representation of the Token object.
        
        Returns:
            str: String representation.
        """
        return f"<Token {self.token_type.value} for user {self.user_id}>"