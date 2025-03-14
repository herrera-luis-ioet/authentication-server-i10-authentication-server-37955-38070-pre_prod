"""
Authentication Management Component - Logging Configuration

This module provides configuration for structured logging with ELK Stack integration.
"""
import os
import json
import logging
import logging.config
from datetime import datetime
from flask import request, g, has_request_context
from pythonjsonlogger import jsonlogger


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """
    Custom JSON formatter for structured logging.
    
    Adds additional fields to the log record for better traceability and analysis.
    """
    
    def add_fields(self, log_record, record, message_dict):
        """
        Add custom fields to the log record.
        
        Args:
            log_record (dict): The log record to be modified.
            record (LogRecord): The original log record.
            message_dict (dict): The message dictionary.
        """
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        
        # Add timestamp in ISO format
        log_record['timestamp'] = datetime.utcnow().isoformat()
        log_record['level'] = record.levelname
        log_record['logger'] = record.name
        
        # Add request context information if available
        if has_request_context():
            log_record['request_id'] = getattr(g, 'request_id', 'unknown')
            log_record['remote_addr'] = request.remote_addr
            log_record['method'] = request.method
            log_record['path'] = request.path
            log_record['user_agent'] = request.user_agent.string
            
            # Add user information if available
            if hasattr(g, 'current_user') and g.current_user:
                log_record['user_id'] = g.current_user.id
                log_record['username'] = g.current_user.username
        
        # Add environment information
        log_record['environment'] = os.getenv('FLASK_ENV', 'development')
        log_record['service'] = 'auth-service'


class RequestIdFilter(logging.Filter):
    """
    Filter that adds request ID to log records.
    """
    
    def filter(self, record):
        """
        Add request ID to the log record if available.
        
        Args:
            record (LogRecord): The log record to be modified.
            
        Returns:
            bool: Always True to include the record in the log output.
        """
        if has_request_context():
            record.request_id = getattr(g, 'request_id', 'unknown')
        else:
            record.request_id = 'no-request-id'
        return True


def get_logging_config(log_level=None):
    """
    Get the logging configuration dictionary.
    
    Args:
        log_level (str, optional): The log level to use. Defaults to the value of LOG_LEVEL
            environment variable or 'INFO'.
            
    Returns:
        dict: The logging configuration dictionary.
    """
    log_level = log_level or os.getenv('LOG_LEVEL', 'INFO')
    
    # Ensure logs directory exists
    logs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    
    return {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'standard': {
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            },
            'json': {
                '()': CustomJsonFormatter,
                'format': '%(timestamp)s %(level)s %(name)s %(message)s'
            }
        },
        'filters': {
            'request_id': {
                '()': RequestIdFilter
            }
        },
        'handlers': {
            'console': {
                'level': log_level,
                'class': 'logging.StreamHandler',
                'formatter': 'json',
                'filters': ['request_id']
            },
            'file': {
                'level': log_level,
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': os.path.join(logs_dir, 'auth_service.log'),
                'maxBytes': 10485760,  # 10 MB
                'backupCount': 10,
                'formatter': 'json',
                'filters': ['request_id']
            },
            'error_file': {
                'level': 'ERROR',
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': os.path.join(logs_dir, 'error.log'),
                'maxBytes': 10485760,  # 10 MB
                'backupCount': 10,
                'formatter': 'json',
                'filters': ['request_id']
            },
            'logstash': {
                'level': log_level,
                'class': 'logstash_async.handler.AsynchronousLogstashHandler',
                'host': os.getenv('LOGSTASH_HOST', 'localhost'),
                'port': int(os.getenv('LOGSTASH_PORT', 5044)),
                'database_path': os.path.join(logs_dir, 'logstash_buffer.db'),
                'transport': 'logstash_async.transport.TcpTransport',
                'formatter': 'json',
                'filters': ['request_id']
            } if os.getenv('LOGSTASH_HOST') else {
                'level': log_level,
                'class': 'logging.NullHandler',
            }
        },
        'loggers': {
            '': {  # root logger
                'handlers': ['console', 'file', 'error_file', 'logstash'],
                'level': log_level,
                'propagate': True
            },
            'app': {
                'handlers': ['console', 'file', 'error_file', 'logstash'],
                'level': log_level,
                'propagate': False
            },
            'werkzeug': {
                'handlers': ['console', 'file'],
                'level': 'INFO',
                'propagate': False
            },
            'sqlalchemy.engine': {
                'handlers': ['console', 'file'],
                'level': 'WARNING',
                'propagate': False
            }
        }
    }


def setup_logging(app=None, log_level=None):
    """
    Set up logging for the application.
    
    Args:
        app (Flask, optional): The Flask application instance. Defaults to None.
        log_level (str, optional): The log level to use. Defaults to None.
    """
    config = get_logging_config(log_level)
    logging.config.dictConfig(config)
    
    if app:
        # Configure Flask app logger
        app.logger.handlers = []
        for handler in logging.getLogger('app').handlers:
            app.logger.addHandler(handler)
        app.logger.setLevel(logging.getLevelName(config['loggers']['app']['level']))
        
        # Add request ID to each request
        @app.before_request
        def before_request():
            """Generate a unique request ID for each request."""
            import uuid
            g.request_id = str(uuid.uuid4())
        
        # Log request and response information
        @app.after_request
        def after_request(response):
            """Log request and response information."""
            # Skip logging for health check endpoints to reduce noise
            if request.path == '/health':
                return response
                
            log_data = {
                'request': {
                    'method': request.method,
                    'path': request.path,
                    'remote_addr': request.remote_addr,
                    'user_agent': request.user_agent.string
                },
                'response': {
                    'status_code': response.status_code,
                    'content_length': response.content_length
                }
            }
            
            # Add user information if available
            if hasattr(g, 'current_user') and g.current_user:
                log_data['user'] = {
                    'id': g.current_user.id,
                    'username': g.current_user.username
                }
            
            # Log at appropriate level based on status code
            if 200 <= response.status_code < 400:
                app.logger.info(f"Request completed", extra=log_data)
            elif 400 <= response.status_code < 500:
                app.logger.warning(f"Client error", extra=log_data)
            else:
                app.logger.error(f"Server error", extra=log_data)
                
            return response
            
        # Log unhandled exceptions
        @app.errorhandler(Exception)
        def log_exception(error):
            """Log unhandled exceptions."""
            app.logger.exception("Unhandled exception", extra={
                'request_id': getattr(g, 'request_id', 'unknown'),
                'error': str(error)
            })
            raise error
    
    return logging.getLogger('app')


# Prometheus metrics for logging
def setup_logging_metrics(metrics):
    """
    Set up Prometheus metrics for logging.
    
    Args:
        metrics: The Prometheus metrics registry.
    """
    if not metrics:
        return
        
    # Create metrics for log levels
    log_counter = metrics.counter(
        'auth_service_log_total',
        'Total number of log entries by level',
        ['level']
    )
    
    # Create a custom handler that increments the counter
    class MetricsHandler(logging.Handler):
        def emit(self, record):
            log_counter.labels(level=record.levelname.lower()).inc()
    
    # Add the handler to the root logger
    logging.getLogger().addHandler(MetricsHandler())