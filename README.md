# Authentication Management Component

Authentication Management Component for secure user authentication and management.

## Features

- User registration and authentication
- JWT-based authentication
- Email verification
- Password reset
- Account lockout protection
- Role-based access control
- API key management
- Multi-factor authentication

## Technologies

- Python 3.9+
- Flask
- SQLAlchemy
- PostgreSQL
- JWT
- Docker
- Kubernetes

## CI/CD

This project uses GitHub Actions for continuous integration and deployment. The workflow is defined in `.github/workflows/ci.yml` and includes the following jobs:

- **Lint**: Runs code quality checks using Black, Flake8, isort, and mypy
- **Test**: Runs tests using pytest with coverage reporting
- **Build**: Builds a Docker image and pushes it to a Docker registry
- **Deploy**: Deploys the application to development or production environments based on the branch

### GitHub Secrets

The following secrets need to be set in the GitHub repository:

- `DOCKER_USERNAME`: Docker Hub username
- `DOCKER_PASSWORD`: Docker Hub password
- `DOCKER_REPO`: Docker Hub repository name
- `KUBE_CONFIG`: Base64-encoded Kubernetes configuration file

## Monitoring

### Prometheus

Prometheus is used for metrics collection. The configuration is defined in `monitoring/prometheus.yml` and includes the following scrape configurations:

- Authentication service
- PostgreSQL database
- Node exporter
- cAdvisor
- Kubernetes service discovery

To run Prometheus:

```bash
docker run -d -p 9090:9090 -v $(pwd)/monitoring/prometheus.yml:/etc/prometheus/prometheus.yml prom/prometheus
```

### Grafana

Grafana is used for metrics visualization. The dashboard is defined in `monitoring/grafana-dashboard.json` and includes the following panels:

- Request rate by endpoint
- Request duration by endpoint
- Active users
- Login rate
- Failed login rate
- Registration rate
- CPU usage
- Memory usage
- Error rates
- Database connections

To run Grafana:

```bash
docker run -d -p 3000:3000 -v $(pwd)/monitoring/grafana-dashboard.json:/var/lib/grafana/dashboards/auth-service.json grafana/grafana
```

### Logging

The application uses structured logging with ELK Stack integration. The logging configuration is defined in `app/logging_config.py` and includes:

- JSON formatting
- Request ID tracking
- Log level configuration
- Logstash integration
- Prometheus metrics for logging

## Development

### Prerequisites

- Python 3.9+
- Poetry
- Docker
- PostgreSQL

### Installation

1. Clone the repository
2. Install dependencies: `poetry install`
3. Set up environment variables (see `.env.example`)
4. Run database migrations: `poetry run flask db upgrade`
5. Run the application: `poetry run flask run`

### Testing

Run tests with pytest:

```bash
poetry run pytest
```

Run tests with coverage:

```bash
poetry run pytest --cov=app --cov-report=term-missing
```

### Docker

Build the Docker image:

```bash
docker build -t auth-service .
```

Run the Docker container:

```bash
docker run -p 5000:5000 auth-service
```

### Kubernetes

Deploy to Kubernetes:

```bash
kubectl apply -f kubernetes/
```