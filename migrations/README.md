# CayVPN schema migrations

The application uses SQLAlchemy models and Alembic for additive schema
migrations. `Database.initialize_defaults()` also performs a small compatibility
check so a node can recover if an upgrade is interrupted before Alembic starts.

Production upgrades run `alembic upgrade head` from the versioned release before
the web and worker services are restarted.
