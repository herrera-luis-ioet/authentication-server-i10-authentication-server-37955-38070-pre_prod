# Authentication Management Component

A comprehensive authentication service built with Flask that provides secure user authentication, registration, and account management capabilities.

## Features

- **User Registration and Management**
  - Email and username-based registration
  - Email verification
  - Profile management
  
- **Secure Authentication**
  - JWT-based authentication
  - Token refresh and revocation
  - Password hashing with bcrypt
  
- **Advanced Security Features**
  - Multi-factor authentication
  - Rate limiting for login attempts
  - Account lockout mechanisms
  - Password complexity enforcement
  
- **Password Management**
  - Secure password reset workflow
  - Password history tracking
  - Password complexity validation
  
- **Comprehensive Logging and Monitoring**
  - Authentication event logging
  - Security audit trails
  - Prometheus metrics integration

## Technology Stack

- **Backend**: Python 3.9+, Flask
- **Database**: PostgreSQL, SQLAlchemy ORM
- **Authentication**: JWT (JSON Web Tokens)
- **Security**: bcrypt for password hashing
- **Email Service**: SMTP/SendGrid integration
- **Containerization**: Docker
- **Monitoring**: Prometheus, Grafana
- **Logging**: ELK Stack (Elasticsearch, Logstash, Kibana)

## Project Structure

```
authentication-management-component/
├── auth_service/                  # Main application package
│   ├── __init__.py                # Package initialization
│   ├── app.py                     # Application factory
│   ├── config.py                  # Configuration settings
│   ├── extensions.py              # Flask extensions
│   ├── api/                       # API endpoints
│   │   ├── __init__.py
│   │   ├── auth.py                # Authentication routes
│   │   ├── users.py               # User management routes
│   │   └── ...
│   ├── models/                    # Database models
│   │   ├── __init__.py
│   │   ├── user.py                # User model
│   │   └── ...
│   ├── services/                  # Business logic
│   │   ├── __init__.py
│   │   ├── auth_service.py        # Authentication service
│   │   ├── email_service.py       # Email service
│   │   └── ...
│   ├── schemas/                   # Data validation schemas
│   │   ├── __init__.py
│   │   ├── auth.py                # Auth-related schemas
│   │   └── ...
│   └── utils/                     # Utility functions
│       ├── __init__.py
│       ├── security.py            # Security utilities
│       └── ...
├── tests/                         # Test suite
│   ├── __init__.py
│   ├── conftest.py                # Test configuration
│   ├── unit/                      # Unit tests
│   └── integration/               # Integration tests
├── migrations/                    # Database migrations
├── docker/                        # Docker configuration
│   ├── Dockerfile
│   └── docker-compose.yml
├── scripts/                       # Utility scripts
├── docs/                          # Documentation
├── .env.example                   # Environment variables example
├── .gitignore                     # Git ignore file
├── pyproject.toml                 # Poetry configuration
└── README.md                      # Project documentation
```

## Installation

### Prerequisites

- Python 3.9 or higher
- PostgreSQL
- Docker (optional)

### Local Development Setup

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd authentication-management-component
   ```

2. Set up a virtual environment and install dependencies using Poetry:
   ```bash
   # Install Poetry if not already installed
   pip install poetry
   
   # Install dependencies
   poetry install
   
   # Activate the virtual environment
   poetry shell
   ```

3. Create a `.env` file from the example:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. Set up the database:
   ```bash
   # Create the database
   createdb auth_service
   
   # Run migrations
   flask db upgrade
   ```

5. Run the development server:
   ```bash
   flask run
   ```

### Docker Setup

1. Build and run using Docker Compose:
   ```bash
   docker-compose up -d
   ```

## Configuration

All configuration is done through environment variables. See `.env.example` for available options.

Key configuration parameters:

- `FLASK_APP`: Entry point to the Flask application
- `FLASK_ENV`: Environment (development, production)
- `DATABASE_URL`: Database connection string
- `JWT_SECRET_KEY`: Secret key for JWT token generation
- `MAIL_*`: Email server configuration

## API Documentation

### Authentication Endpoints

- `POST /api/auth/register`: Register a new user
- `POST /api/auth/login`: Authenticate and get tokens
- `POST /api/auth/refresh`: Refresh access token
- `POST /api/auth/logout`: Revoke tokens
- `POST /api/auth/verify-email`: Verify email address
- `POST /api/auth/forgot-password`: Initiate password reset
- `POST /api/auth/reset-password`: Complete password reset

### User Management Endpoints

- `GET /api/users/me`: Get current user profile
- `PUT /api/users/me`: Update user profile
- `PUT /api/users/me/password`: Change password
- `POST /api/users/me/mfa`: Enable/disable MFA

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=auth_service
```

### Code Quality

```bash
# Format code
black auth_service tests

# Sort imports
isort auth_service tests

# Lint code
flake8 auth_service tests

# Type checking
mypy auth_service
```

### Database Migrations

```bash
# Create a new migration
flask db migrate -m "Description of changes"

# Apply migrations
flask db upgrade

# Revert migrations
flask db downgrade
```

## Monitoring and Logging

- Prometheus metrics available at `/metrics`
- Logs are written to `logs/auth_service.log` and stdout
- ELK Stack integration for centralized logging

## Security Considerations

- All passwords are hashed using bcrypt
- JWT tokens have configurable expiration
- Rate limiting is applied to sensitive endpoints
- HTTPS should be used in production

## License

[MIT License](LICENSE)

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -am 'Add feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request