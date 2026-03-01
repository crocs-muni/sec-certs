# User Accounts System

User authentication and management system for sec-certs.

## Features

- **Registration**: Email/username/password with email confirmation
- **Login**: Username/password, magic links, or GitHub OAuth
- **Password Reset**: Email-based recovery
- **Profile Management**: View/edit user information  
- **Account Deletion**: User-initiated removal
- **Subscriptions**: Manage notifications without email confirmation

## Architecture

- **`/user` blueprint**: All user functionality including authentication
- **`/admin` blueprint**: Administrative functionality only
- **Unified Login**: Single authentication system for all user types

## Database Schema
See [database.md](database.md) for details on the user-related collections and fields.

## Routes

### User Blueprint (`/user`)
- `GET|POST /login` - User login
- `GET /logout` - User logout  
- `GET|POST /register` - Account registration
- `GET /confirm/<token>` - Email confirmation
- `GET|POST /forgot-password` - Password reset request
- `GET|POST /reset-password/<token>` - Password reset
- `GET|POST /magic-link` - Magic link request
- `GET /magic-login/<token>` - Magic link login
- `GET /profile` - User profile
- `POST /delete-account` - Account deletion
- `GET|POST /subscriptions` - Subscription management

### GitHub OAuth (`/auth`)
- `GET /github` - Initiate GitHub OAuth
- `GET /github/authorized` - OAuth callback

## Configuration

See `docs/OAUTH_SETUP.md` for GitHub OAuth setup details.

GitHub OAuth is controlled by the `GITHUB_OAUTH_ENABLED` configuration option.
