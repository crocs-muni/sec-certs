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

### Users Collection
```javascript
{
  username: String,          // Unique identifier
  email: String,             // User email
  pwhash: String,           // Password hash (empty for OAuth users)
  roles: Array,             // ["admin"] for administrators, [] for regular users
  email_confirmed: Boolean, // Email confirmation status
  created_at: Date,         // Account creation timestamp
  github_id: String         // GitHub user ID (optional)
}
```

### Email Tokens Collection
```javascript
{
  token: String,            // URL-safe token
  user_id: String,          // Username
  type: String,             // "email_confirmation", "password_reset", "magic_link"
  expires_at: Date,         // Expiration time
  created_at: Date          // Creation time
}
```

**Token Expiry:**
- Email confirmation: 24 hours
- Password reset: 1 hour  
- Magic link: 15 minutes

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
