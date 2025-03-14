{"is_source_file": true, "format": "Python", "description": "This file contains pytest fixtures for the Authentication Management Component, providing setup for testing various user authentication scenarios.", "external_files": ["app", "app.extensions", "app.models.user", "app.models.token", "app.utils.security"], "external_methods": ["app.create_app", "app.extensions.db.create_all", "app.extensions.db.remove", "app.extensions.db.drop_all", "app.extensions.db.engine.connect", "app.extensions.db.session.commit", "app.extensions.db.session.delete", "app.extensions.db.session.rollback", "app.utils.security.generate_jwt_token"], "published": ["app", "db", "session", "client", "test_user", "admin_user", "unverified_user", "locked_user", "refresh_token", "reset_token", "verification_token", "api_key", "auth_headers", "admin_auth_headers", "AuthActions"], "classes": [{"name": "AuthActions", "description": "Helper class for authentication actions in tests."}], "methods": [{"name": "app()", "description": "Create and configure a Flask app for testing.", "scope": "", "scopeKind": ""}, {"name": "db(app)", "description": "Database fixture for testing.", "scope": "", "scopeKind": ""}, {"name": "session(db)", "description": "Creates a new database session for each test.", "scope": "", "scopeKind": ""}, {"name": "client(app)", "description": "A test client for the app.", "scope": "", "scopeKind": ""}, {"name": "test_user(session)", "description": "Creates a test user.", "scope": "", "scopeKind": ""}, {"name": "admin_user(session)", "description": "Creates an admin user.", "scope": "", "scopeKind": ""}, {"name": "unverified_user(session)", "description": "Creates an unverified user.", "scope": "", "scopeKind": ""}, {"name": "locked_user(session)", "description": "Creates a locked user.", "scope": "", "scopeKind": ""}, {"name": "refresh_token(session, test_user)", "description": "Creates a refresh token for the test user.", "scope": "", "scopeKind": ""}, {"name": "reset_token(session, test_user)", "description": "Creates a password reset token for the test user.", "scope": "", "scopeKind": ""}, {"name": "verification_token(session, unverified_user)", "description": "Creates an email verification token for the unverified user.", "scope": "", "scopeKind": ""}, {"name": "api_key(session, test_user)", "description": "Creates an API key for the test user.", "scope": "", "scopeKind": ""}, {"name": "auth(client)", "description": "Authentication actions for tests.", "scope": "", "scopeKind": ""}, {"name": "__init__(self, client)", "scope": "AuthActions", "scopeKind": "class", "description": "unavailable"}, {"name": "admin_auth_headers(admin_user, app)", "scope": "", "scopeKind": "", "description": "unavailable"}, {"name": "auth_headers(test_user, app)", "scope": "", "scopeKind": "", "description": "unavailable"}, {"name": "login(self, username_or_email='testuser', password='Password123!')", "scope": "AuthActions", "scopeKind": "class", "description": "unavailable"}, {"name": "logout(self, access_token)", "scope": "AuthActions", "scopeKind": "class", "description": "unavailable"}, {"name": "register(self, username='newuser', email='new@example.com', password='Password123!', first_name='New', last_name='User')", "scope": "AuthActions", "scopeKind": "class", "description": "unavailable"}], "calls": ["app.app_context", "db.session", "client.post"], "search-terms": ["pytest fixtures", "Flask testing", "Authentication Management", "user roles", "Token types"], "state": 2, "file_id": 22, "knowledge_revision": 57, "git_revision": "", "revision_history": [{"50": ""}, {"57": ""}], "ctags": [{"_type": "tag", "name": "AuthActions", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^class AuthActions:$/", "language": "Python", "kind": "class"}, {"_type": "tag", "name": "__init__", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^    def __init__(self, client):$/", "language": "Python", "kind": "member", "signature": "(self, client)", "scope": "AuthActions", "scopeKind": "class"}, {"_type": "tag", "name": "_db", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^from app.extensions import db as _db$/", "language": "Python", "kind": "unknown", "nameref": "unknown:db"}, {"_type": "tag", "name": "admin_auth_headers", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^def admin_auth_headers(admin_user, app):$/", "language": "Python", "kind": "function", "signature": "(admin_user, app)"}, {"_type": "tag", "name": "admin_user", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^def admin_user(session):$/", "language": "Python", "kind": "function", "signature": "(session)"}, {"_type": "tag", "name": "api_key", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^def api_key(session, test_user):$/", "language": "Python", "kind": "function", "signature": "(session, test_user)"}, {"_type": "tag", "name": "app", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^def app():$/", "language": "Python", "kind": "function", "signature": "()"}, {"_type": "tag", "name": "auth", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^def auth(client):$/", "language": "Python", "kind": "function", "signature": "(client)"}, {"_type": "tag", "name": "auth_headers", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^def auth_headers(test_user, app):$/", "language": "Python", "kind": "function", "signature": "(test_user, app)"}, {"_type": "tag", "name": "client", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^def client(app):$/", "language": "Python", "kind": "function", "signature": "(app)"}, {"_type": "tag", "name": "db", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^def db(app):$/", "language": "Python", "kind": "function", "signature": "(app)"}, {"_type": "tag", "name": "locked_user", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^def locked_user(session):$/", "language": "Python", "kind": "function", "signature": "(session)"}, {"_type": "tag", "name": "login", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^    def login(self, username_or_email='testuser', password='Password123!'):$/", "language": "Python", "kind": "member", "signature": "(self, username_or_email='testuser', password='Password123!')", "scope": "AuthActions", "scopeKind": "class"}, {"_type": "tag", "name": "logout", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^    def logout(self, access_token):$/", "language": "Python", "kind": "member", "signature": "(self, access_token)", "scope": "AuthActions", "scopeKind": "class"}, {"_type": "tag", "name": "refresh_token", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^def refresh_token(session, test_user):$/", "language": "Python", "kind": "function", "signature": "(session, test_user)"}, {"_type": "tag", "name": "register", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^    def register(self, username='newuser', email='new@example.com', password='Password123!',$/", "language": "Python", "kind": "member", "signature": "(self, username='newuser', email='new@example.com', password='Password123!', first_name='New', last_name='User')", "scope": "AuthActions", "scopeKind": "class"}, {"_type": "tag", "name": "reset_token", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^def reset_token(session, test_user):$/", "language": "Python", "kind": "function", "signature": "(session, test_user)"}, {"_type": "tag", "name": "session", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^def session(db):$/", "language": "Python", "kind": "function", "signature": "(db)"}, {"_type": "tag", "name": "test_user", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^def test_user(session):$/", "language": "Python", "kind": "function", "signature": "(session)"}, {"_type": "tag", "name": "unverified_user", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^def unverified_user(session):$/", "language": "Python", "kind": "function", "signature": "(session)"}, {"_type": "tag", "name": "verification_token", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "pattern": "/^def verification_token(session, unverified_user):$/", "language": "Python", "kind": "function", "signature": "(session, unverified_user)"}], "filename": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/conftest.py", "hash": "a1c1f1681218344f042dcc4b3c675e7a", "format-version": 4, "code-base-name": "default"}