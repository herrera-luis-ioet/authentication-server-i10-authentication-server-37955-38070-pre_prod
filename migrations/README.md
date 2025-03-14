# Database Migrations

This directory contains database migration scripts for the Authentication Management Component. The migrations are managed using Alembic through Flask-Migrate.

## Migration Commands

### Initialize Migrations (First Time Only)
```bash
flask db init
```

### Create a New Migration
```bash
flask db migrate -m "Description of changes"
```

### Apply Migrations
```bash
flask db upgrade
```

### Rollback Migrations
```bash
flask db downgrade
```

### View Migration History
```bash
flask db history
```

### View Current Migration
```bash
flask db current
```

## Migration Best Practices

1. **Always review generated migrations**: Alembic auto-generates migrations based on model changes, but these should be reviewed before applying.

2. **Test migrations**: Always test migrations in a development environment before applying to production.

3. **Backup database**: Always backup your database before applying migrations in production.

4. **Version control**: Keep migrations in version control along with your application code.

5. **Meaningful messages**: Use descriptive commit messages when creating migrations.

## Directory Structure

- `versions/`: Contains individual migration scripts
- `env.py`: Alembic environment configuration
- `script.py.mako`: Template for new migration scripts
- `alembic.ini`: Alembic configuration file (created by Flask-Migrate)

## Common Issues

### Migration Not Detecting Changes
If Alembic isn't detecting changes to your models, try:
```bash
flask db stamp head  # Mark the current database as up-to-date
flask db migrate -m "Description of changes"  # Create a new migration
```

### Conflicts in Migration Scripts
If you encounter conflicts in migration scripts, it's often best to:
1. Rollback to a known good state
2. Create a new migration that combines the changes

### Data Migrations
For complex data migrations, you may need to write custom Python code in the migration script. See the Alembic documentation for details.