# Deployment Environment Variables Checklist

This document provides a comprehensive checklist of environment variables that need to be configured in your Render deployment environment to ensure proper functionality of the authentication system, database connections, and email services.

## Database Configuration

| Variable | Description | Example |
|----------|-------------|---------|
| `DB_HOST` | MySQL database host URL | `mysql-host.example.com` |
| `DB_USER` | MySQL database username | `db_user` |
| `DB_PASSWORD` | MySQL database password | `your_password` |
| `DB_NAME` | MySQL database name | `fooddb` |
| `DB_PORT` | MySQL database port | `3306` |
| `DB_SSL` | Enable SSL for database connection | `true` |
| `DB_SSL_REJECT_UNAUTHORIZED` | Whether to reject unauthorized SSL | `true` |

## Authentication Configuration

| Variable | Description | Example |
|----------|-------------|---------|
| `JWT_SECRET` | Secret key for JWT token signing | `your_secure_jwt_secret_key` |
| `JWT_EXPIRES` | JWT token expiration time | `24h` |
| `COOKIE_SECRET` | Secret for cookie signing | `your_secure_cookie_secret` |
| `COOKIE_DOMAIN` | Cookie domain (for cross-domain) | `.yourdomain.com` |
| `COOKIE_SECURE` | Whether cookies require HTTPS | `true` in production |
| `COOKIE_SAMESITE` | Cookie SameSite policy | `none` for cross-origin |
| `RESET_TOKEN_EXPIRY` | Password reset token expiry in minutes | `15` |

## Email Service Configuration (Resend)

| Variable | Description | Example |
|----------|-------------|---------|
| `RESEND_API_KEY` | Resend API key for email sending | `re_123456789` |
| `FROM_EMAIL` | From email address for sent emails | `noreply@yourdomain.com` |
| `SITE_NAME` | Site name used in email templates | `Fresh Eats Market` |

## Frontend Configuration

| Variable | Description | Example |
|----------|-------------|---------|
| `FRONTEND_URL` | URL of the frontend application | `https://yourdomain.com` |
| `CORS_ORIGIN` | Allowed origins for CORS | `https://yourdomain.com` |
| `API_PATH` | API path prefix | `/api` |

## Server Configuration

| Variable | Description | Example |
|----------|-------------|---------|
| `PORT` | Port for the server to listen on | `10000` |
| `NODE_ENV` | Node environment | `production` |

## Pre-Deployment Checklist

Before deploying to Render:

1. ☐ Generate a new Resend API key to replace any previously shared keys
2. ☐ Ensure your sending domain in Resend is verified (for production usage)
3. ☐ Verify database SSL settings are correctly configured
4. ☐ Use environment-specific secrets (different values for development and production)
5. ☐ Test all authentication flows locally before deploying
6. ☐ Ensure CORS settings match your actual frontend domain
7. ☐ Set cookie domain to match your application domain configuration

## Post-Deployment Testing

After deploying:

1. ☐ Test user registration flow
2. ☐ Test user login flow
3. ☐ Test password reset flow by requesting a reset email
4. ☐ Verify that cross-domain cookies are working correctly
5. ☐ Check server logs for any authentication or email sending errors
6. ☐ Verify database connection is secure (SSL enabled)

## Common Issues and Solutions

- **500 Errors on Authentication**: Check database connection settings and SSL configuration
- **Email Sending Failures**: Verify Resend API key and sender domain verification
- **Cross-Domain Cookie Issues**: Check CORS settings and cookie configuration (secure, samesite)
- **JWT Token Issues**: Verify JWT_SECRET is properly set and consistent

