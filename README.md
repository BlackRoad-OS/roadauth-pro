# RoadAuth Pro

Enterprise-grade authentication service for the BlackRoad ecosystem.

## Features

- **OAuth2 / OpenID Connect** - Standard authentication flows
- **JWT Tokens** - Secure, stateless authentication
- **Multi-Factor Authentication** - TOTP-based 2FA
- **Session Management** - Token refresh and revocation
- **Role-Based Access Control** - Fine-grained permissions
- **SSO Integrations** - Google, GitHub, Microsoft, Okta

## Quick Start

```bash
# Install
pip install -e .

# Run
roadauth

# Or with uvicorn
uvicorn roadauth.main:app --reload
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/register` | POST | Register new user |
| `/auth/token` | POST | Login (OAuth2 password flow) |
| `/auth/refresh` | POST | Refresh access token |
| `/auth/me` | GET | Get current user |
| `/auth/mfa/setup` | POST | Set up MFA |
| `/auth/mfa/verify` | POST | Verify MFA code |
| `/auth/logout` | POST | Logout |

## Environment Variables

```bash
ROADAUTH_JWT_SECRET_KEY=your-secret-key
ROADAUTH_DATABASE_URL=postgresql+asyncpg://localhost/roadauth
ROADAUTH_REDIS_URL=redis://localhost:6379
ROADAUTH_ACCESS_TOKEN_EXPIRE_MINUTES=30
```

## License

Proprietary - BlackRoad OS, Inc.
