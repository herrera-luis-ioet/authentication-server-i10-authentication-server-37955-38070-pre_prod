"""
Authentication Management Component - Email Service

This module provides email functionality for the authentication service,
including sending verification emails, password reset emails, etc.
"""
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional, Union

from flask import current_app, render_template_string

logger = logging.getLogger(__name__)


class EmailService:
    """Service for sending emails in the authentication system."""
    
    # Email templates
    _TEMPLATES = {
        'verification': {
            'subject': 'Verify Your Email Address',
            'html': """
                <html>
                <body>
                    <h1>Email Verification</h1>
                    <p>Hello {{ username }},</p>
                    <p>Thank you for registering. Please click the link below to verify your email address:</p>
                    <p><a href="{{ verification_url }}">Verify Email</a></p>
                    <p>This link will expire in {{ expiration_hours }} hours.</p>
                    <p>If you did not create an account, please ignore this email.</p>
                </body>
                </html>
            """,
            'text': """
                Email Verification
                
                Hello {{ username }},
                
                Thank you for registering. Please click the link below to verify your email address:
                
                {{ verification_url }}
                
                This link will expire in {{ expiration_hours }} hours.
                
                If you did not create an account, please ignore this email.
            """
        },
        'password_reset': {
            'subject': 'Password Reset Request',
            'html': """
                <html>
                <body>
                    <h1>Password Reset</h1>
                    <p>Hello {{ username }},</p>
                    <p>We received a request to reset your password. Please click the link below to reset it:</p>
                    <p><a href="{{ reset_url }}">Reset Password</a></p>
                    <p>This link will expire in {{ expiration_hours }} hours.</p>
                    <p>If you did not request a password reset, please ignore this email.</p>
                </body>
                </html>
            """,
            'text': """
                Password Reset
                
                Hello {{ username }},
                
                We received a request to reset your password. Please click the link below to reset it:
                
                {{ reset_url }}
                
                This link will expire in {{ expiration_hours }} hours.
                
                If you did not request a password reset, please ignore this email.
            """
        },
        'account_locked': {
            'subject': 'Account Security Alert',
            'html': """
                <html>
                <body>
                    <h1>Account Security Alert</h1>
                    <p>Hello {{ username }},</p>
                    <p>Your account has been temporarily locked due to multiple failed login attempts.</p>
                    <p>You can try again after {{ lockout_minutes }} minutes or reset your password using the link below:</p>
                    <p><a href="{{ reset_url }}">Reset Password</a></p>
                    <p>If you did not attempt to log in, please reset your password immediately.</p>
                </body>
                </html>
            """,
            'text': """
                Account Security Alert
                
                Hello {{ username }},
                
                Your account has been temporarily locked due to multiple failed login attempts.
                
                You can try again after {{ lockout_minutes }} minutes or reset your password using the link below:
                
                {{ reset_url }}
                
                If you did not attempt to log in, please reset your password immediately.
            """
        },
        'welcome': {
            'subject': 'Welcome to Our Service',
            'html': """
                <html>
                <body>
                    <h1>Welcome!</h1>
                    <p>Hello {{ username }},</p>
                    <p>Thank you for verifying your email and joining our service.</p>
                    <p>You can now log in and start using all features.</p>
                    <p>If you have any questions, please contact our support team.</p>
                </body>
                </html>
            """,
            'text': """
                Welcome!
                
                Hello {{ username }},
                
                Thank you for verifying your email and joining our service.
                
                You can now log in and start using all features.
                
                If you have any questions, please contact our support team.
            """
        }
    }
    
    @classmethod
    def _render_template(cls, template_key: str, template_type: str, context: Dict) -> str:
        """
        Render an email template with the given context.
        
        Args:
            template_key (str): The key of the template to render
            template_type (str): The type of template ('html' or 'text')
            context (Dict): The context variables for the template
            
        Returns:
            str: The rendered template
        """
        template = cls._TEMPLATES.get(template_key, {}).get(template_type, '')
        return render_template_string(template, **context)
    
    @staticmethod
    def _get_smtp_connection():
        """
        Get an SMTP connection based on the application configuration.
        
        Returns:
            smtplib.SMTP: An SMTP connection
        """
        server = current_app.config.get('MAIL_SERVER', 'smtp.sendgrid.net')
        port = current_app.config.get('MAIL_PORT', 587)
        use_tls = current_app.config.get('MAIL_USE_TLS', True)
        username = current_app.config.get('MAIL_USERNAME', '')
        password = current_app.config.get('MAIL_PASSWORD', '')
        
        smtp = smtplib.SMTP(server, port)
        
        if use_tls:
            smtp.starttls()
            
        if username and password:
            smtp.login(username, password)
            
        return smtp
    
    # PUBLIC_INTERFACE
    @classmethod
    def send_email(
        cls,
        to_email: Union[str, List[str]],
        subject: str,
        html_content: str,
        text_content: str,
        from_email: Optional[str] = None,
        reply_to: Optional[str] = None
    ) -> bool:
        """
        Send an email using the configured email provider.
        
        Args:
            to_email (Union[str, List[str]]): Recipient email address(es)
            subject (str): Email subject
            html_content (str): HTML content of the email
            text_content (str): Plain text content of the email
            from_email (Optional[str], optional): Sender email address.
                Defaults to the configured default sender.
            reply_to (Optional[str], optional): Reply-to email address.
                Defaults to None.
                
        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        if isinstance(to_email, str):
            recipients = [to_email]
        else:
            recipients = to_email
            
        from_email = from_email or current_app.config.get('MAIL_DEFAULT_SENDER')
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = from_email
        msg['To'] = ', '.join(recipients)
        
        if reply_to:
            msg['Reply-To'] = reply_to
            
        # Attach parts
        part1 = MIMEText(text_content, 'plain')
        part2 = MIMEText(html_content, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
        try:
            with cls._get_smtp_connection() as smtp:
                smtp.sendmail(from_email, recipients, msg.as_string())
            logger.info(f"Email sent successfully to {recipients}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")
            return False
    
    # PUBLIC_INTERFACE
    @classmethod
    def send_verification_email(cls, email: str, username: str, verification_url: str) -> bool:
        """
        Send an email verification email.
        
        Args:
            email (str): The recipient's email address
            username (str): The recipient's username
            verification_url (str): The URL for email verification
            
        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        context = {
            'username': username,
            'verification_url': verification_url,
            'expiration_hours': 24  # Default expiration time
        }
        
        subject = cls._TEMPLATES['verification']['subject']
        html_content = cls._render_template('verification', 'html', context)
        text_content = cls._render_template('verification', 'text', context)
        
        return cls.send_email(email, subject, html_content, text_content)
    
    # PUBLIC_INTERFACE
    @classmethod
    def send_password_reset_email(cls, email: str, username: str, reset_url: str) -> bool:
        """
        Send a password reset email.
        
        Args:
            email (str): The recipient's email address
            username (str): The recipient's username
            reset_url (str): The URL for password reset
            
        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        context = {
            'username': username,
            'reset_url': reset_url,
            'expiration_hours': 1  # Default expiration time
        }
        
        subject = cls._TEMPLATES['password_reset']['subject']
        html_content = cls._render_template('password_reset', 'html', context)
        text_content = cls._render_template('password_reset', 'text', context)
        
        return cls.send_email(email, subject, html_content, text_content)
    
    # PUBLIC_INTERFACE
    @classmethod
    def send_account_locked_email(cls, email: str, username: str, reset_url: str, lockout_minutes: int = 15) -> bool:
        """
        Send an account locked notification email.
        
        Args:
            email (str): The recipient's email address
            username (str): The recipient's username
            reset_url (str): The URL for password reset
            lockout_minutes (int, optional): The lockout duration in minutes. Defaults to 15.
            
        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        context = {
            'username': username,
            'reset_url': reset_url,
            'lockout_minutes': lockout_minutes
        }
        
        subject = cls._TEMPLATES['account_locked']['subject']
        html_content = cls._render_template('account_locked', 'html', context)
        text_content = cls._render_template('account_locked', 'text', context)
        
        return cls.send_email(email, subject, html_content, text_content)
    
    # PUBLIC_INTERFACE
    @classmethod
    def send_welcome_email(cls, email: str, username: str) -> bool:
        """
        Send a welcome email after successful verification.
        
        Args:
            email (str): The recipient's email address
            username (str): The recipient's username
            
        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        context = {
            'username': username
        }
        
        subject = cls._TEMPLATES['welcome']['subject']
        html_content = cls._render_template('welcome', 'html', context)
        text_content = cls._render_template('welcome', 'text', context)
        
        return cls.send_email(email, subject, html_content, text_content)