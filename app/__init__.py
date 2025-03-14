"""
Authentication Management Component - Flask Application Factory
"""
import os
from flask import Flask, jsonify

from app.config import get_config
from app.extensions import db, migrate, jwt, bcrypt, cors, limiter
from app.logging_config import setup_logging


def create_app(config_name=None):
    """
    Flask application factory function that creates and configures
    the Flask application instance.
    
    Args:
        config_name (str, optional): The name of the configuration to use.
            Defaults to the value of FLASK_ENV environment variable.
            
    Returns:
        Flask: The configured Flask application instance.
    """
    app = Flask(__name__)
    
    # Load configuration
    config_name = config_name or os.getenv('FLASK_ENV', 'development')
    app.config.from_object(get_config(config_name))
    
    # Initialize extensions
    register_extensions(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register shell context
    register_shell_context(app)
    
    return app


def register_extensions(app):
    """
    Initialize and register Flask extensions with the application.
    
    Args:
        app (Flask): The Flask application instance.
    """
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    bcrypt.init_app(app)
    cors.init_app(app)
    limiter.init_app(app)
    
    # Set up logging
    setup_logging(app)
    
    # Set up Prometheus metrics if available
    try:
        from prometheus_client import Counter, Histogram, Info
        from flask import request, g
        import time
        
        # Create metrics
        request_counter = Counter(
            'flask_http_request_total',
            'Total number of HTTP requests',
            ['method', 'endpoint', 'status']
        )
        
        request_duration = Histogram(
            'flask_http_request_duration_seconds',
            'HTTP request duration in seconds',
            ['method', 'endpoint']
        )
        
        active_users = Counter(
            'auth_service_active_users',
            'Number of active users'
        )
        
        login_counter = Counter(
            'auth_service_login_total',
            'Total number of login attempts',
            ['status']
        )
        
        login_failed_counter = Counter(
            'auth_service_login_failed_total',
            'Total number of failed login attempts',
            ['reason']
        )
        
        registration_counter = Counter(
            'auth_service_registration_total',
            'Total number of user registrations',
            ['status']
        )
        
        # Add version info
        info = Info('auth_service_info', 'Authentication service information')
        info.info({
            'version': os.getenv('APP_VERSION', '0.1.0'),
            'environment': os.getenv('FLASK_ENV', 'development')
        })
        
        # Register metrics middleware
        @app.before_request
        def before_request_metrics():
            g.start_time = time.time()
        
        @app.after_request
        def after_request_metrics(response):
            if hasattr(g, 'start_time'):
                request_duration.labels(
                    method=request.method,
                    endpoint=request.endpoint or 'unknown'
                ).observe(time.time() - g.start_time)
                
            request_counter.labels(
                method=request.method,
                endpoint=request.endpoint or 'unknown',
                status=response.status_code
            ).inc()
            
            return response
            
        # Set up logging metrics
        from app.logging_config import setup_logging_metrics
        setup_logging_metrics({
            'counter': Counter,
            'histogram': Histogram,
            'info': Info
        })
        
        # Add metrics endpoint
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        
        @app.route('/metrics')
        def metrics():
            return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}
            
    except ImportError:
        app.logger.warning("Prometheus client not installed. Metrics will not be available.")
    
    return None


def register_blueprints(app):
    """
    Register Flask blueprints with the application.
    
    Args:
        app (Flask): The Flask application instance.
    """
    # Import blueprints here to avoid circular imports
    from app.api import auth_bp, users_bp
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    
    @app.route('/health')
    def health_check():
        """Health check endpoint for monitoring."""
        return jsonify({"status": "healthy"}), 200
    
    return None


def register_error_handlers(app):
    """
    Register error handlers with the application.
    
    Args:
        app (Flask): The Flask application instance.
    """
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"error": "Bad Request", "message": str(error)}), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({"error": "Unauthorized", "message": str(error)}), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({"error": "Forbidden", "message": str(error)}), 403
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Not Found", "message": str(error)}), 404
    
    @app.errorhandler(500)
    def internal_server_error(error):
        return jsonify({"error": "Internal Server Error", "message": str(error)}), 500
    
    return None


def register_shell_context(app):
    """
    Register shell context objects with the application.
    
    Args:
        app (Flask): The Flask application instance.
    """
    def shell_context():
        from app.models import User, Token
        return {
            'app': app,
            'db': db,
            'User': User,
            'Token': Token,
        }
    
    app.shell_context_processor(shell_context)
    
    return None
