"""Hardcoded secrets - intentionally insecure, for scanner demos only."""

SECRET_KEY = "super-secret-flask-key-12345"
ADMIN_PASSWORD = "admin123"

# Fake AWS-style credentials (not real) to trigger secret detectors.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

DATABASE_URL = "postgresql://admin:P@ssw0rd!@db.internal:5432/prod"
