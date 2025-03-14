{"is_source_file": true, "format": "Python", "description": "This file handles the authentication management for a Flask application, including JWT token management and defining different extensions.", "external_files": ["app/models/token", "app/models/user"], "external_methods": ["Token.find_by_token", "User.find_by_id"], "published": [], "classes": [], "methods": [{"name": "check_if_token_is_revoked(jwt_header, jwt_payload)", "description": "Callback function to check if a JWT token is revoked.", "scope": "", "scopeKind": ""}, {"name": "load_user_from_jwt(jwt_header, jwt_payload)", "description": "Callback function to load a user from a JWT token.", "scope": "", "scopeKind": ""}, {"name": "expired_token_callback(jwt_header, jwt_payload)", "description": "Callback function for expired JWT tokens.", "scope": "", "scopeKind": ""}, {"name": "invalid_token_callback(error)", "description": "Callback function for invalid JWT tokens.", "scope": "", "scopeKind": ""}, {"name": "missing_token_callback(error)", "description": "Callback function for missing JWT tokens.", "scope": "", "scopeKind": ""}, {"name": "token_not_fresh_callback(jwt_header, jwt_payload)", "description": "Callback function for non-fresh JWT tokens.", "scope": "", "scopeKind": ""}, {"name": "revoked_token_callback(jwt_header, jwt_payload)", "description": "Callback function for revoked JWT tokens.", "scope": "", "scopeKind": ""}], "calls": ["app.models.token.Token.find_by_token", "app.models.user.User.find_by_id"], "search-terms": ["JWT Management", "Flask Extensions", "Authentication Callbacks"], "state": 2, "file_id": 6, "knowledge_revision": 28, "git_revision": "96c5fa776ecac80fb543ea91a36c7ec330fa53ab", "revision_history": [{"13": ""}, {"28": "96c5fa776ecac80fb543ea91a36c7ec330fa53ab"}], "ctags": [{"_type": "tag", "name": "bcrypt", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/extensions.py", "pattern": "/^bcrypt = Bcrypt()$/", "language": "Python", "kind": "variable"}, {"_type": "tag", "name": "check_if_token_is_revoked", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/extensions.py", "pattern": "/^def check_if_token_is_revoked(jwt_header, jwt_payload):$/", "language": "Python", "kind": "function", "signature": "(jwt_header, jwt_payload)"}, {"_type": "tag", "name": "cors", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/extensions.py", "pattern": "/^cors = CORS()$/", "language": "Python", "kind": "variable"}, {"_type": "tag", "name": "db", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/extensions.py", "pattern": "/^db = SQLAlchemy()$/", "language": "Python", "kind": "variable"}, {"_type": "tag", "name": "expired_token_callback", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/extensions.py", "pattern": "/^def expired_token_callback(jwt_header, jwt_payload):$/", "language": "Python", "kind": "function", "signature": "(jwt_header, jwt_payload)"}, {"_type": "tag", "name": "invalid_token_callback", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/extensions.py", "pattern": "/^def invalid_token_callback(error):$/", "language": "Python", "kind": "function", "signature": "(error)"}, {"_type": "tag", "name": "jwt", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/extensions.py", "pattern": "/^jwt = JWTManager()$/", "language": "Python", "kind": "variable"}, {"_type": "tag", "name": "limiter", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/extensions.py", "pattern": "/^limiter = Limiter($/", "language": "Python", "kind": "variable"}, {"_type": "tag", "name": "load_user_from_jwt", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/extensions.py", "pattern": "/^def load_user_from_jwt(jwt_header, jwt_payload):$/", "language": "Python", "kind": "function", "signature": "(jwt_header, jwt_payload)"}, {"_type": "tag", "name": "migrate", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/extensions.py", "pattern": "/^migrate = Migrate()$/", "language": "Python", "kind": "variable"}, {"_type": "tag", "name": "missing_token_callback", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/extensions.py", "pattern": "/^def missing_token_callback(error):$/", "language": "Python", "kind": "function", "signature": "(error)"}, {"_type": "tag", "name": "revoked_token_callback", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/extensions.py", "pattern": "/^def revoked_token_callback(jwt_header, jwt_payload):$/", "language": "Python", "kind": "function", "signature": "(jwt_header, jwt_payload)"}, {"_type": "tag", "name": "token_not_fresh_callback", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/extensions.py", "pattern": "/^def token_not_fresh_callback(jwt_header, jwt_payload):$/", "language": "Python", "kind": "function", "signature": "(jwt_header, jwt_payload)"}], "filename": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/app/extensions.py", "hash": "8612ff96101676e983ca62cf24552ce6", "format-version": 4, "code-base-name": "default", "fields": [{"name": "bcrypt = Bcrypt()", "scope": "", "scopeKind": "", "description": "unavailable"}, {"name": "cors = CORS()", "scope": "", "scopeKind": "", "description": "unavailable"}, {"name": "db = SQLAlchemy()", "scope": "", "scopeKind": "", "description": "unavailable"}, {"name": "jwt = JWTManager()", "scope": "", "scopeKind": "", "description": "unavailable"}, {"name": "limiter = Limiter(", "scope": "", "scopeKind": "", "description": "unavailable"}, {"name": "migrate = Migrate()", "scope": "", "scopeKind": "", "description": "unavailable"}]}