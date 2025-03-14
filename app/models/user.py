"""
Authentication Management Component - User Model

This module defines the User model for the authentication service.
"""
from datetime import datetime, timedelta
import enum
from typing import Optional, List
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship

from app.extensions import db, bcrypt


class UserRole(enum.Enum):
    """Enum for user roles."""
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"


class UserStatus(enum.Enum):
    """Enum for user account status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"
    LOCKED = "locked"


class User(db.Model):
    """User model for authentication and user management."""
    
    __tablename__ = "users"
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    _password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(64), nullable=True)
    last_name = db.Column(db.String(64), nullable=True)
    role = db.Column(db.Enum(UserRole), default=UserRole.USER, nullable=False)
    status = db.Column(db.Enum(UserStatus), default=UserStatus.PENDING_VERIFICATION, nullable=False)
    
    # Account security fields
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_login_attempt = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime, nullable=True)
    
    # Email verification
    email_verified = db.Column(db.Boolean, default=False)
    email_verified_at = db.Column(db.DateTime, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    tokens = relationship("Token", back_populates="user", cascade="all, delete-orphan")
    
    @hybrid_property
    def password(self) -> str:
        """
        Password property that raises an exception when accessed.
        
        Raises:
            AttributeError: Always raises this exception as password should not be readable.
            
        Returns:
            str: Never returns, always raises an exception.
        """
        raise AttributeError("Password is not a readable attribute")
    
    @password.setter
    def password(self, password: str) -> None:
        """
        Set the password hash from a plain text password.
        
        Args:
            password (str): The plain text password to hash.
        """
        self._password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        self.password_changed_at = datetime.utcnow()
    
    # PUBLIC_INTERFACE
    def verify_password(self, password: str) -> bool:
        """
        Verify a password against the stored hash.
        
        Args:
            password (str): The plain text password to verify.
            
        Returns:
            bool: True if the password matches, False otherwise.
        """
        return bcrypt.check_password_hash(self._password_hash, password)
    
    # PUBLIC_INTERFACE
    def update_login_success(self) -> None:
        """
        Update user fields after a successful login.
        """
        self.failed_login_attempts = 0
        self.last_login = datetime.utcnow()
        self.last_login_attempt = datetime.utcnow()
        db.session.commit()
    
    # PUBLIC_INTERFACE
    def update_login_failure(self) -> None:
        """
        Update user fields after a failed login attempt.
        
        Returns:
            bool: True if the account is now locked, False otherwise.
        """
        self.failed_login_attempts += 1
        self.last_login_attempt = datetime.utcnow()
        
        # Check if account should be locked
        if self.failed_login_attempts >= 5:  # This could be a configurable value
            self.status = UserStatus.LOCKED
        
        db.session.commit()
        return self.status == UserStatus.LOCKED
    
    # PUBLIC_INTERFACE
    def unlock_account(self) -> None:
        """
        Unlock a locked account.
        """
        if self.status == UserStatus.LOCKED:
            self.status = UserStatus.ACTIVE
            self.failed_login_attempts = 0
            db.session.commit()
    
    # PUBLIC_INTERFACE
    def verify_email(self) -> None:
        """
        Mark the user's email as verified.
        """
        self.email_verified = True
        self.email_verified_at = datetime.utcnow()
        
        if self.status == UserStatus.PENDING_VERIFICATION:
            self.status = UserStatus.ACTIVE
            
        db.session.commit()
    
    # PUBLIC_INTERFACE
    def change_password(self, new_password: str) -> None:
        """
        Change the user's password.
        
        Args:
            new_password (str): The new password to set.
        """
        self.password = new_password
        db.session.commit()
    
    # PUBLIC_INTERFACE
    def is_password_expired(self, max_age_days: int = 90) -> bool:
        """
        Check if the user's password has expired.
        
        Args:
            max_age_days (int, optional): Maximum password age in days. Defaults to 90.
            
        Returns:
            bool: True if the password has expired, False otherwise.
        """
        if not self.password_changed_at:
            return False
            
        expiry_date = self.password_changed_at + timedelta(days=max_age_days)
        return datetime.utcnow() > expiry_date
    
    # PUBLIC_INTERFACE
    def to_dict(self) -> dict:
        """
        Convert the user object to a dictionary.
        
        Returns:
            dict: Dictionary representation of the user.
        """
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "role": self.role.value if self.role else None,
            "status": self.status.value if self.status else None,
            "email_verified": self.email_verified,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None
        }
    
    @classmethod
    def find_by_username(cls, username: str) -> Optional["User"]:
        """
        Find a user by username.
        
        Args:
            username (str): The username to search for.
            
        Returns:
            Optional[User]: The user if found, None otherwise.
        """
        return cls.query.filter_by(username=username).first()
    
    @classmethod
    def find_by_email(cls, email: str) -> Optional["User"]:
        """
        Find a user by email.
        
        Args:
            email (str): The email to search for.
            
        Returns:
            Optional[User]: The user if found, None otherwise.
        """
        return cls.query.filter_by(email=email).first()
    
    @classmethod
    def find_by_id(cls, user_id: int) -> Optional["User"]:
        """
        Find a user by ID.
        
        Args:
            user_id (int): The user ID to search for.
            
        Returns:
            Optional[User]: The user if found, None otherwise.
        """
        return cls.query.get(user_id)
    
    def __repr__(self) -> str:
        """
        String representation of the User object.
        
        Returns:
            str: String representation.
        """
        return f"<User {self.username}>"