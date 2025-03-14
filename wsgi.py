"""
Authentication Management Component - WSGI Entry Point

This module serves as the entry point for WSGI servers like Gunicorn.
It creates a Flask application instance using the application factory pattern.
"""
import os
from app import create_app

# Create a Flask application instance with the appropriate configuration
# The configuration is determined by the FLASK_ENV environment variable
app = create_app(os.getenv('FLASK_ENV', 'production'))

if __name__ == '__main__':
    # This block is executed when the script is run directly
    # It's useful for development, but in production, use Gunicorn
    app.run(
        host=os.getenv('FLASK_HOST', '0.0.0.0'),
        port=int(os.getenv('FLASK_PORT', 5000)),
        debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    )