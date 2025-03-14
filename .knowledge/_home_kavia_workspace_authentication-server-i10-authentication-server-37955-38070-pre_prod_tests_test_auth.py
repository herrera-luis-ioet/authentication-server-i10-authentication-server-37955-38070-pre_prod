{"is_source_file": true, "format": "Python", "description": "This file contains unit tests for the authentication API endpoints, testing various scenarios like user registration, login, email verification, password reset, and token refresh.", "external_files": ["app.models.user.User", "app.models.user.UserStatus", "app.models.token.Token", "app.models.token.TokenType", "app.services.email_service.EmailService"], "external_methods": ["User.find_by_username", "User.find_by_id", "User.verify_password", "EmailService.send_password_reset_email"], "published": [], "classes": [], "methods": [{"name": "test_register_success(client, session)", "description": "Test successful user registration.", "scope": "", "scopeKind": ""}, {"name": "test_register_missing_fields(client)", "description": "Test registration with missing required fields.", "scope": "", "scopeKind": ""}, {"name": "test_register_weak_password(client)", "description": "Test registration with a weak password.", "scope": "", "scopeKind": ""}, {"name": "test_register_existing_username(client, test_user)", "description": "Test registration with an existing username.", "scope": "", "scopeKind": ""}, {"name": "test_register_existing_email(client, test_user)", "description": "Test registration with an existing email.", "scope": "", "scopeKind": ""}, {"name": "test_login_success(client, test_user)", "description": "Test successful login with username.", "scope": "", "scopeKind": ""}, {"name": "test_login_with_email(client, test_user)", "description": "Test successful login with email.", "scope": "", "scopeKind": ""}, {"name": "test_login_invalid_credentials(client, test_user)", "description": "Test login with invalid credentials.", "scope": "", "scopeKind": ""}, {"name": "test_login_nonexistent_user(client)", "description": "Test login with a nonexistent user.", "scope": "", "scopeKind": ""}, {"name": "test_login_locked_account(client, locked_user)", "description": "Test login with a locked account.", "scope": "", "scopeKind": ""}, {"name": "test_login_unverified_account(client, unverified_user)", "description": "Test login with an unverified account.", "scope": "", "scopeKind": ""}, {"name": "test_login_account_lockout(client, session)", "description": "Test account lockout after multiple failed login attempts.", "scope": "", "scopeKind": ""}, {"name": "test_logout_success(client, test_user, auth_headers)", "description": "Test successful logout.", "scope": "", "scopeKind": ""}, {"name": "test_logout_no_token(client)", "description": "Test logout without a token.", "scope": "", "scopeKind": ""}, {"name": "test_refresh_token_success(client, test_user, refresh_token)", "description": "Test successful token refresh.", "scope": "", "scopeKind": ""}, {"name": "test_refresh_token_invalid(client)", "description": "Test refresh with an invalid token.", "scope": "", "scopeKind": ""}, {"name": "test_refresh_token_missing(client)", "description": "Test refresh without a token.", "scope": "", "scopeKind": ""}, {"name": "test_verify_email_success(client, unverified_user, verification_token)", "description": "Test successful email verification.", "scope": "", "scopeKind": ""}, {"name": "test_verify_email_invalid_token(client)", "description": "Test email verification with an invalid token.", "scope": "", "scopeKind": ""}, {"name": "test_request_password_reset(client, test_user)", "description": "Test requesting a password reset.", "scope": "", "scopeKind": ""}, {"name": "test_request_password_reset_nonexistent_email(client)", "description": "Test requesting a password reset for a nonexistent email.", "scope": "", "scopeKind": ""}, {"name": "test_reset_password_success(client, test_user, reset_token)", "description": "Test successful password reset.", "scope": "", "scopeKind": ""}, {"name": "test_reset_password_invalid_token(client)", "description": "Test password reset with an invalid token.", "scope": "", "scopeKind": ""}, {"name": "test_reset_password_weak_password(client, reset_token)", "description": "Test password reset with a weak password.", "scope": "", "scopeKind": ""}, {"name": "test_reset_password_missing_fields(client)", "description": "Test password reset with missing fields.", "scope": "", "scopeKind": ""}], "calls": ["client.post", "json.loads"], "search-terms": ["authentication", "registration", "login", "logout", "password reset"], "state": 2, "file_id": 23, "knowledge_revision": 52, "git_revision": "", "ctags": [{"_type": "tag", "name": "test_login_account_lockout", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_login_account_lockout(client, session):$/", "language": "Python", "kind": "function", "signature": "(client, session)"}, {"_type": "tag", "name": "test_login_invalid_credentials", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_login_invalid_credentials(client, test_user):$/", "language": "Python", "kind": "function", "signature": "(client, test_user)"}, {"_type": "tag", "name": "test_login_locked_account", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_login_locked_account(client, locked_user):$/", "language": "Python", "kind": "function", "signature": "(client, locked_user)"}, {"_type": "tag", "name": "test_login_nonexistent_user", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_login_nonexistent_user(client):$/", "language": "Python", "kind": "function", "signature": "(client)"}, {"_type": "tag", "name": "test_login_success", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_login_success(client, test_user):$/", "language": "Python", "kind": "function", "signature": "(client, test_user)"}, {"_type": "tag", "name": "test_login_unverified_account", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_login_unverified_account(client, unverified_user):$/", "language": "Python", "kind": "function", "signature": "(client, unverified_user)"}, {"_type": "tag", "name": "test_login_with_email", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_login_with_email(client, test_user):$/", "language": "Python", "kind": "function", "signature": "(client, test_user)"}, {"_type": "tag", "name": "test_logout_no_token", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_logout_no_token(client):$/", "language": "Python", "kind": "function", "signature": "(client)"}, {"_type": "tag", "name": "test_logout_success", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_logout_success(client, test_user, auth_headers):$/", "language": "Python", "kind": "function", "signature": "(client, test_user, auth_headers)"}, {"_type": "tag", "name": "test_refresh_token_invalid", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_refresh_token_invalid(client):$/", "language": "Python", "kind": "function", "signature": "(client)"}, {"_type": "tag", "name": "test_refresh_token_missing", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_refresh_token_missing(client):$/", "language": "Python", "kind": "function", "signature": "(client)"}, {"_type": "tag", "name": "test_refresh_token_success", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_refresh_token_success(client, test_user, refresh_token):$/", "language": "Python", "kind": "function", "signature": "(client, test_user, refresh_token)"}, {"_type": "tag", "name": "test_register_existing_email", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_register_existing_email(client, test_user):$/", "language": "Python", "kind": "function", "signature": "(client, test_user)"}, {"_type": "tag", "name": "test_register_existing_username", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_register_existing_username(client, test_user):$/", "language": "Python", "kind": "function", "signature": "(client, test_user)"}, {"_type": "tag", "name": "test_register_missing_fields", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_register_missing_fields(client):$/", "language": "Python", "kind": "function", "signature": "(client)"}, {"_type": "tag", "name": "test_register_success", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_register_success(client, session):$/", "language": "Python", "kind": "function", "signature": "(client, session)"}, {"_type": "tag", "name": "test_register_weak_password", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_register_weak_password(client):$/", "language": "Python", "kind": "function", "signature": "(client)"}, {"_type": "tag", "name": "test_request_password_reset", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_request_password_reset(client, test_user):$/", "language": "Python", "kind": "function", "signature": "(client, test_user)"}, {"_type": "tag", "name": "test_request_password_reset_nonexistent_email", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_request_password_reset_nonexistent_email(client):$/", "language": "Python", "kind": "function", "signature": "(client)"}, {"_type": "tag", "name": "test_reset_password_invalid_token", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_reset_password_invalid_token(client):$/", "language": "Python", "kind": "function", "signature": "(client)"}, {"_type": "tag", "name": "test_reset_password_missing_fields", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_reset_password_missing_fields(client):$/", "language": "Python", "kind": "function", "signature": "(client)"}, {"_type": "tag", "name": "test_reset_password_success", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_reset_password_success(client, test_user, reset_token):$/", "language": "Python", "kind": "function", "signature": "(client, test_user, reset_token)"}, {"_type": "tag", "name": "test_reset_password_weak_password", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_reset_password_weak_password(client, reset_token):$/", "language": "Python", "kind": "function", "signature": "(client, reset_token)"}, {"_type": "tag", "name": "test_verify_email_invalid_token", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_verify_email_invalid_token(client):$/", "language": "Python", "kind": "function", "signature": "(client)"}, {"_type": "tag", "name": "test_verify_email_success", "path": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "pattern": "/^def test_verify_email_success(client, unverified_user, verification_token):$/", "language": "Python", "kind": "function", "signature": "(client, unverified_user, verification_token)"}], "filename": "/home/kavia/workspace/authentication-server-i10-authentication-server-37955-38070-pre_prod/tests/test_auth.py", "hash": "60f7831777132ee47483b915fe35bad9", "format-version": 4, "code-base-name": "default", "revision_history": [{"52": ""}]}