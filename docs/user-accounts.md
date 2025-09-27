# User Accounts Documentation

This document describes the comprehensive user account system implemented for the sec-certs web application.

## Overview

The user account system provides modern authentication and user management features while maintaining compatibility with the existing admin system.

## Features

### Account Creation
- **Email/Username/Password Registration**: Traditional account creation with email confirmation
- **GitHub OAuth Registration**: Quick registration using GitHub account
- **Email Confirmation**: Required for email/password accounts, automatic for OAuth users

### Authentication Methods

#### Password-Based Login
- Traditional username/password authentication
- "Remember me" functionality for persistent sessions
- Unified system serves both admin and regular users

#### Magic Link Login
- Passwordless authentication via email
- Secure 15-minute token expiry
- One-time use tokens with automatic cleanup

#### GitHub OAuth 2.0
- Login/signup with GitHub account
- Automatic account linking for existing email addresses
- Auto-confirmed email addresses for OAuth users
- Graceful fallback when not configured

### Password Management
- **Password Reset**: Secure email-based reset system with 1-hour token expiry
- **Password Security**: PBKDF2 hashing
- **OAuth Users**: Empty passwords (no random password generation)

### Account Management
- **User Profiles**: View and manage account information
- **Account Deletion**: User-initiated with confirmation dialog
- **GitHub Linking**: Connect/disconnect GitHub accounts

### Subscription Management
- **Auto-confirmed Subscriptions**: No email confirmation needed for logged-in users
- **Quick Subscribe/Unsubscribe**: Streamlined management interface
- **Integration**: Seamless integration with existing notification system

## Architecture

### Blueprint Structure
- **`/user` Blueprint**: All user functionality (registration, login, profiles, subscriptions)
- **`/admin` Blueprint**: Administrative functionality only (dashboard, tasks, config)
- **Unified Authentication**: Single login system for all user types

### Database Schema
The system extends the existing `users` collection with additional fields:

```javascript
{
  _id: ObjectId,
  username: String,
  email: String,
  pwhash: String,  // Empty string for OAuth users
  role: String,    // "admin" for administrators
  
  // New user account fields
  email_confirmed: Boolean,
  email_confirmed_at: Date,
  confirmation_token: String,
  confirmation_expires: Date,
  
  reset_token: String,
  reset_expires: Date,
  
  magic_token: String,
  magic_expires: Date,
  
  github_id: String,
  github_username: String,
  
  created_at: Date,
  last_login: Date
}
```

### Security Features
- **Token Security**: URL-safe tokens with appropriate expiry times
- **CSRF Protection**: All forms protected against CSRF attacks
- **Session Management**: Proper Flask-Login integration
- **OAuth Security**: Secure GitHub integration with proper scope

## Configuration

### GitHub OAuth Setup
See `docs/OAUTH_SETUP.md` for detailed GitHub OAuth configuration.

### Required Settings
```python
# GitHub OAuth (optional)
GITHUB_OAUTH_ENABLED = True  # Enable/disable GitHub authentication
GITHUB_OAUTH_CLIENT_ID = "your_client_id"
GITHUB_OAUTH_CLIENT_SECRET = "your_client_secret"

# Email settings (required for password reset, magic links, confirmations)
MAIL_SERVER = "your_smtp_server"
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = "your_email"
MAIL_PASSWORD = "your_password"
```

## API Endpoints

### User Blueprint Routes (`/user`)
- `GET|POST /login` - User login (all users)
- `GET|POST /logout` - User logout
- `GET|POST /register` - Account registration
- `GET /confirm/<token>` - Email confirmation
- `GET|POST /forgot-password` - Password reset request
- `GET|POST /reset-password/<token>` - Password reset form
- `GET|POST /magic-link` - Magic link request
- `GET /magic-login/<token>` - Magic link login
- `GET /profile` - User profile page
- `POST /delete-account` - Account deletion
- `GET|POST /subscriptions` - Subscription management

### GitHub OAuth Routes (`/auth`)
- `GET /github` - Initiate GitHub OAuth
- `GET /github/authorized` - OAuth callback

## User Experience Flow

### New User Registration
1. User visits `/user/register`
2. Chooses email/password or GitHub OAuth
3. For email/password: receives confirmation email
4. For GitHub: automatically confirmed
5. Redirected to main site or admin dashboard (based on role)

### Existing User Login
1. User visits `/user/login`
2. Multiple options: password, magic link, GitHub OAuth
3. Role-based redirection after successful authentication
4. Admin users → admin dashboard
5. Regular users → main site

### Password Recovery
1. User visits `/user/forgot-password`
2. Enters email address
3. Receives secure reset link (1-hour expiry)
4. Sets new password via `/user/reset-password/<token>`

### Magic Link Authentication
1. User visits `/user/magic-link`
2. Enters email address
3. Receives secure login link (15-minute expiry)
4. Automatic login via `/user/magic-login/<token>`

## Integration with Existing Systems

### Admin System
- Existing admin users work seamlessly
- Same login system for admin and regular users
- Role-based access control preserved
- Admin functionality unchanged

### Notification System
- Logged-in users can manage subscriptions without email confirmation
- Integration with existing subscription management
- Maintains compatibility with existing notification workflows

### Database
- Uses existing MongoDB infrastructure
- Backward-compatible schema extensions
- Existing user records preserved

## Security Considerations

### Token Management
- **Email Confirmation**: 24-hour expiry
- **Password Reset**: 1-hour expiry
- **Magic Links**: 15-minute expiry
- **One-time Use**: All tokens invalidated after use

### OAuth Security
- **Scope Limitation**: Only requests `user:email` scope
- **Account Linking**: Secure email-based account association
- **Session Storage**: Uses Flask-Dance default session storage

### Data Protection
- **Password Hashing**: PBKDF2 with salt
- **OAuth Users**: No password storage (empty string)
- **Email Validation**: Proper email format validation
- **CSRF Protection**: All state-changing operations protected

## Troubleshooting

### Common Issues
1. **GitHub OAuth not appearing**: Check `GITHUB_OAUTH_ENABLED` config and credentials
2. **Email confirmations not sent**: Verify SMTP configuration
3. **Magic links not working**: Check token expiry and one-time use validation
4. **Admin access issues**: Ensure user has `role: "admin"` in database

### Debug Settings
```python
# Enable debug logging for user account operations
LOGGING = {
    'loggers': {
        'sec_certs_page.user': {
            'level': 'DEBUG'
        }
    }
}
```