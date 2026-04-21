"""
Django settings.py (dummy secrets for scanner benchmarking)
DO NOT USE IN PRODUCTION
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# -------------------------------------------------------
# Core Django secrets
# -------------------------------------------------------

SECRET_KEY = "django-insecure-5z8x7c6v5b4n3m2a1s0d9f8g7h6j5k4l3p2o1i9u8y7t6r"

DEBUG = False

ALLOWED_HOSTS = ["example.com", "api.example.com"]

# -------------------------------------------------------
# Database configuration
# -------------------------------------------------------

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "production_db",
        "USER": "prod_admin",
        "PASSWORD": "Pr0dDBP@ssw0rd!A9f3KlmPq8Xz2Tn4Yw6Rb0Cj",
        "HOST": "prod-db.internal.example.com",
        "PORT": "5432",
    }
}

# -------------------------------------------------------
# AWS configuration
# -------------------------------------------------------

AWS_ACCESS_KEY_ID = "AKIA7EXAMPLEQWERTYUI"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYdummyExampleKey123"
AWS_STORAGE_BUCKET_NAME = "production-bucket"
AWS_S3_REGION_NAME = "us-east-1"

# -------------------------------------------------------
# OpenAI configuration
# -------------------------------------------------------

OPENAI_API_KEY = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdef"

# -------------------------------------------------------
# Cloudflare configuration
# -------------------------------------------------------

CLOUDFLARE_API_TOKEN = "CFAT-abcdefghijklmnopqrstuvwxyz1234567890"
CLOUDFLARE_ZONE_ID = "1a2b3c4d5e6f7890abcdef1234567890"

# -------------------------------------------------------
# SonarQube configuration
# -------------------------------------------------------

SONAR_HOST_URL = "https://sonar.internal.example.com"
SONAR_TOKEN = "squ_abcdef1234567890abcdef1234567890abcdef12"

# -------------------------------------------------------
# Stripe configuration
# -------------------------------------------------------

STRIPE_SECRET_KEY = "sk_live_abcdefghijklmnopqrstuvwxyz123456"
STRIPE_PUBLIC_KEY = "pk_live_abcdefghijklmnopqrstuvwxyz123456"

# -------------------------------------------------------
# GitHub integration
# -------------------------------------------------------

GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"

# -------------------------------------------------------
# Email configuration
# -------------------------------------------------------

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.mailgun.org"
EMAIL_PORT = 587
EMAIL_HOST_USER = "postmaster@example.com"
EMAIL_HOST_PASSWORD = "MailgunP@ssw0rdExample0987654321"
EMAIL_USE_TLS = True

# -------------------------------------------------------
# Redis / cache
# -------------------------------------------------------

REDIS_HOST = "redis.internal.example.com"
REDIS_PORT = 6379
REDIS_PASSWORD = "redis-secret-9sd8f7s9df87s9df87s9df87s9df87s9df"

# -------------------------------------------------------
# JWT configuration
# -------------------------------------------------------

JWT_SECRET_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummyPayloadSignatureABCDEFGHIJKLMNOPQRSTUVWXYZ123456"

# -------------------------------------------------------
# Third-party API keys
# -------------------------------------------------------

SLACK_BOT_TOKEN = "xoxb-123456789012-abcdefghijklmnopqrstuvwxyz1234"
TWILIO_ACCOUNT_SID = "ACabcdef1234567890abcdef1234567890"
TWILIO_AUTH_TOKEN = "abcdef1234567890abcdef1234567890"

# -------------------------------------------------------
# Internal service secrets
# -------------------------------------------------------

INTERNAL_API_KEY = "internal-api-key-abcdefghijklmnopqrstuvwxyz123456"
SIGNING_KEY = "MIICXAIBAAKBgQCdummySigningKeyExample0987654321abcdefghijklmnop"