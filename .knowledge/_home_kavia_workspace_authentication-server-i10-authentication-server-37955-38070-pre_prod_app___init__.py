{"is_source_file": true, "format": "Python", "description": "This file initializes a Flask application, registers extensions, error handlers, and shell context.", "external_files": ["app.config", "app.extensions"], "external_methods": ["get_config", "db.init_app", "migrate.init_app", "jwt.init_app", "bcrypt.init_app", "cors.init_app", "limiter.init_app"], "published": ["create_app", "register_extensions", "register_blueprints", "register_error_handlers", "register_shell_context"], "classes": [], "methods": [{"name": "create_app(config_name=None)", "description": "Creates and configures a Flask application instance.", "scope": "", "scopeKind": ""}, {"name": "register_extensions(app)", "description": "Initializes and registers Flask extensions with the application.", "scope": "", "scopeKind": ""}, {"name": "register_blueprints(app)", "description": "Registers Flask blueprints with the application.", "scope": "", "scopeKind": ""}, {"name": "register_error_handlers(app)", "description": "Registers error handlers with the application for different HTTP status codes.", "scope": "", "scopeKind": ""}, {"name": "register_shell_context(app)", "description": "Registers shell context objects to be available in the Flask shell.", "scope": "", "scopeKind": ""}, {"name": "bad_request(error)", "scope": "register_error_handlers", "scopeKind": "function", "description": "unavailable"}, {"name": "forbidden(error)", "scope": "register_error_handlers", "scopeKind": "function", "description": "unavailable"}, {"name": "health_check()", "scope": "register_blueprints", "scopeKind": "function", "description": "unavailable"}, {"name": "internal_server_error(error)", "scope": "register_error_handlers", "scopeKind": "function", "description": "unavailable"}, {"name": "not_found(error)", "scope": "register_error_handlers", "scopeKind": "function", "description": "unavailable"}, {"name": "shell_context()", "scope": "register_shell_context", "scopeKind": "function", "description": "unavailable"}, {"name": "unauthorized(error)", "scope": "register_error_handlers", "scopeKind": "function", "description": "unavailable"}], "calls": ["os.getenv", "app.config.from_object", "app.route", "app.errorhandler", "app.shell_context_processor"], "search-terms": ["Flask application factory", "authentication", "app initialization", "error handling"], "state": 2, "file_id": 4, "knowledge_revision": 9, "git_revision": "", "ctags": [{"_type": "tag", "name": "bad_request", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/__init__.py", "pattern": "/^    def bad_request(error):$/", "file": true, "language": "Python", "kind": "function", "signature": "(error)", "scope": "register_error_handlers", "scopeKind": "function"}, {"_type": "tag", "name": "create_app", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/__init__.py", "pattern": "/^def create_app(config_name=None):$/", "language": "Python", "kind": "function", "signature": "(config_name=None)"}, {"_type": "tag", "name": "forbidden", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/__init__.py", "pattern": "/^    def forbidden(error):$/", "file": true, "language": "Python", "kind": "function", "signature": "(error)", "scope": "register_error_handlers", "scopeKind": "function"}, {"_type": "tag", "name": "health_check", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/__init__.py", "pattern": "/^    def health_check():$/", "file": true, "language": "Python", "kind": "function", "signature": "()", "scope": "register_blueprints", "scopeKind": "function"}, {"_type": "tag", "name": "internal_server_error", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/__init__.py", "pattern": "/^    def internal_server_error(error):$/", "file": true, "language": "Python", "kind": "function", "signature": "(error)", "scope": "register_error_handlers", "scopeKind": "function"}, {"_type": "tag", "name": "not_found", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/__init__.py", "pattern": "/^    def not_found(error):$/", "file": true, "language": "Python", "kind": "function", "signature": "(error)", "scope": "register_error_handlers", "scopeKind": "function"}, {"_type": "tag", "name": "register_blueprints", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/__init__.py", "pattern": "/^def register_blueprints(app):$/", "language": "Python", "kind": "function", "signature": "(app)"}, {"_type": "tag", "name": "register_error_handlers", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/__init__.py", "pattern": "/^def register_error_handlers(app):$/", "language": "Python", "kind": "function", "signature": "(app)"}, {"_type": "tag", "name": "register_extensions", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/__init__.py", "pattern": "/^def register_extensions(app):$/", "language": "Python", "kind": "function", "signature": "(app)"}, {"_type": "tag", "name": "register_shell_context", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/__init__.py", "pattern": "/^def register_shell_context(app):$/", "language": "Python", "kind": "function", "signature": "(app)"}, {"_type": "tag", "name": "shell_context", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/__init__.py", "pattern": "/^    def shell_context():$/", "file": true, "language": "Python", "kind": "function", "signature": "()", "scope": "register_shell_context", "scopeKind": "function"}, {"_type": "tag", "name": "unauthorized", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/__init__.py", "pattern": "/^    def unauthorized(error):$/", "file": true, "language": "Python", "kind": "function", "signature": "(error)", "scope": "register_error_handlers", "scopeKind": "function"}], "filename": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/__init__.py", "hash": "e7e2c7cc47cf68a76fabab1eb1796acc", "format-version": 4, "code-base-name": "default", "revision_history": [{"9": ""}]}